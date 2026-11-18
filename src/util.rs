//! Small helpers shared by several operations.

use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read},
    path::Path,
};

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hexadecimal text of `bytes`, two characters per byte.
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX_DIGITS[(byte >> 4) as usize] as char);
        out.push(HEX_DIGITS[(byte & 15) as usize] as char);
    }
    out
}

/// SHA-256 of `bytes` as 64 lowercase hexadecimal characters.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// Reads `reader` to the end and returns the number of bytes read and their SHA-256 as
/// lowercase hexadecimal text.
pub fn sha256_reader(mut reader: impl Read) -> io::Result<(u64, String)> {
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        digest.update(&buffer[..read]);
        total += read as u64;
    }
    Ok((total, hex(&digest.finalize())))
}

/// The 62-character alphabet of generated secrets.
const ALNUM: &[u8; 62] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// `len` alphanumeric characters from the kernel's random source (`/dev/urandom`).
pub fn random_alnum(len: usize) -> io::Result<String> {
    random_alnum_from(len, std::fs::File::open("/dev/urandom")?)
}

/// [`random_alnum`] over any byte source. Bytes are read a buffer at a time; a
/// byte of 248 or more is dropped (248 = 62 * 4) so every character is equally
/// likely, and more bytes are read until `len` characters are collected. A
/// short or failed read is an error.
pub fn random_alnum_from(len: usize, mut source: impl Read) -> io::Result<String> {
    let mut out = String::with_capacity(len);
    let mut buffer = vec![0u8; len];
    while out.len() < len {
        let need = len - out.len();
        source.read_exact(&mut buffer[..need])?;
        for &byte in &buffer[..need] {
            if byte < 248 {
                out.push(ALNUM[usize::from(byte) % ALNUM.len()] as char);
            }
        }
    }
    Ok(out)
}

/// `value` as a PHP single-quoted string literal: backslash and single quote are escaped,
/// everything else (including `$`, double quotes and non-ASCII text) is literal in PHP.
///
/// Not an SQL or shell escaper: SQL literals and POSIX shell words follow different rules.
pub fn php_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}

/// The first `max` bytes of `text`, shortened to the previous character boundary when the
/// limit falls inside a multi-byte character. Text of at most `max` bytes is returned whole.
pub fn truncate_utf8_head(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// The last `max` bytes of `text`, shortened to the next character boundary when the cut
/// falls inside a multi-byte character. Text of at most `max` bytes is returned whole.
pub fn truncate_utf8_tail(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut start = text.len() - max;
    while !text.is_char_boundary(start) {
        start += 1;
    }
    &text[start..]
}

/// Reads at most `max` bytes from `reader`. Returns `None` when the reader holds more than
/// `max` bytes (one extra byte is read to tell, never more), so a caller can refuse an
/// oversized input without buffering it.
pub fn read_bounded(reader: impl Read, max: u64) -> io::Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    reader.take(max.saturating_add(1)).read_to_end(&mut bytes)?;
    Ok((bytes.len() as u64 <= max).then_some(bytes))
}

/// Whether `value` is non-empty, at most `max` bytes long, starts with a byte
/// accepted by `first` and continues with bytes accepted by `rest`. Any
/// non-ASCII character fails unless a predicate accepts its bytes, which the
/// ASCII predicates in use never do.
pub fn charset_ok(
    value: &str,
    max: usize,
    first: impl Fn(u8) -> bool,
    rest: impl Fn(u8) -> bool,
) -> bool {
    let mut bytes = value.bytes();
    value.len() <= max && bytes.next().is_some_and(first) && bytes.all(rest)
}

/// Sets `KEY=value` lines in a Compose `.env` file and replaces it atomically
/// (a private temporary file next to it, `fsync`, original permissions, rename).
///
/// A line is replaced when it starts with `KEY=` (the first such line only);
/// otherwise the line is appended. Nothing else is parsed: quotes, comments,
/// `export` prefixes and other lines stay byte for byte, except that line
/// endings are normalised to `\n` and the file ends with one. A value holding
/// CR, LF or NUL is refused before anything is written. The path must be a
/// regular file, not a symlink. `temp_extension` names the temporary file
/// (`path.with_extension(..)`).
pub fn update_env_atomic(
    path: &Path,
    updates: &[(&str, &str)],
    temp_extension: &str,
) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::other("compose env is not a regular file"));
    }
    let original = fs::read_to_string(path)?;
    let mut lines = original.lines().map(str::to_owned).collect::<Vec<_>>();
    for (key, value) in updates {
        if value.contains(['\r', '\n', '\0']) {
            return Err(io::Error::other("invalid env pointer"));
        }
        let prefix = format!("{key}=");
        if let Some(line) = lines.iter_mut().find(|line| line.starts_with(&prefix)) {
            *line = format!("{key}={value}");
        } else {
            lines.push(format!("{key}={value}"));
        }
    }
    let content = format!("{}\n", lines.join("\n"));
    let temporary = path.with_extension(temp_extension);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    {
        use std::io::Write;
        let mut file = options.open(&temporary)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
    }
    fs::set_permissions(&temporary, metadata.permissions())?;
    fs::rename(temporary, path)
}

#[cfg(test)]
pub mod testing {
    /// Pins the accept/reject behaviour of a name validator: `first` are the
    /// characters allowed at position 0, `rest` those allowed after it, `max`
    /// the longest accepted length in bytes; the empty string is rejected.
    /// Every ASCII character (control characters, NUL, newline, quotes, `/`,
    /// space included) is probed alone, first, in the middle and last, and a
    /// set of non-ASCII strings is probed in each position.
    pub fn pin_charset(
        name: &str,
        accepts: impl Fn(&str) -> bool,
        max: usize,
        first: &str,
        rest: &str,
    ) {
        let fill_first = first.chars().next().unwrap();
        let fill_rest = rest.chars().next().unwrap();
        let check = |input: &str, expected: bool| {
            assert_eq!(
                accepts(input),
                expected,
                "{name}({input:?}) should be {}",
                if expected { "accepted" } else { "rejected" }
            );
        };
        check("", false);
        let longest = format!("{fill_first}{}", fill_rest.to_string().repeat(max - 1));
        check(&longest, true);
        check(&format!("{longest}{fill_rest}"), false);
        check(&fill_first.to_string().repeat(max + 1), false);
        for c in (0u8..=127).map(char::from) {
            let in_first = first.contains(c);
            let in_rest = rest.contains(c);
            check(&c.to_string(), in_first);
            check(&format!("{c}{fill_rest}"), in_first);
            check(&format!("{fill_first}{c}{fill_rest}"), in_rest);
            check(&format!("{fill_first}{c}"), in_rest);
        }
        for odd in [
            "\u{e9}",
            "\u{ff21}",
            "\u{65e5}\u{672c}",
            "\u{202e}",
            "\u{1f600}",
            "\u{a0}",
            "\u{2028}",
            "\u{0}\u{e9}",
        ] {
            check(odd, false);
            check(&format!("{odd}{fill_rest}"), false);
            check(&format!("{fill_first}{odd}{fill_rest}"), false);
            check(&format!("{fill_first}{odd}"), false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn charset_ok_checks_length_first_byte_and_the_rest() {
        let digit = |b: u8| b.is_ascii_digit();
        let alpha = |b: u8| b.is_ascii_alphabetic();
        assert!(!charset_ok("", 4, digit, alpha));
        assert!(charset_ok("1abc", 4, digit, alpha));
        assert!(!charset_ok("1abcd", 4, digit, alpha));
        assert!(!charset_ok("a1bc", 4, digit, alpha));
        assert!(!charset_ok("1ab1", 4, digit, alpha));
        assert!(charset_ok("1", 4, digit, alpha));
        assert!(!charset_ok("1\u{e9}", 4, digit, alpha));
    }

    #[test]
    fn hex_is_lowercase_two_digits_per_byte() {
        assert_eq!(hex(&[]), "");
        assert_eq!(hex(&[0x00]), "00");
        assert_eq!(hex(&[0xff]), "ff");
        assert_eq!(hex(&[0x01, 0xab, 0x7f, 0x80]), "01ab7f80");
    }

    #[test]
    fn sha256_hex_matches_known_digests() {
        assert_eq!(sha256_hex(b""), EMPTY);
        assert_eq!(sha256_hex(b"abc"), ABC);
    }

    #[test]
    fn sha256_reader_counts_and_hashes() {
        assert_eq!(sha256_reader(io::empty()).unwrap(), (0, EMPTY.to_owned()));
        assert_eq!(sha256_reader(&b"abc"[..]).unwrap(), (3, ABC.to_owned()));
        let big = vec![7u8; 300_000];
        assert_eq!(
            sha256_reader(&big[..]).unwrap(),
            (300_000, sha256_hex(&big))
        );
    }

    #[test]
    fn sha256_reader_reports_read_errors() {
        struct Failing;
        impl Read for Failing {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("boom"))
            }
        }
        assert!(sha256_reader(Failing).is_err());
    }

    #[test]
    fn random_alnum_maps_bytes_to_the_alphabet_and_drops_248_and_up() {
        let bytes = [0u8, 25, 26, 51, 52, 61, 62, 247, 248, 255, 124, 186];
        // 248 and 255 are dropped; 62 wraps to 'a', 247 % 62 = 61 -> '9'.
        assert_eq!(random_alnum_from(10, &bytes[..]).unwrap(), "azAZ09a9aa");
    }

    #[test]
    fn random_alnum_reads_more_when_bytes_are_rejected() {
        let mut bytes = vec![255u8; 5];
        bytes.extend([1, 2, 3]);
        assert_eq!(random_alnum_from(3, &bytes[..]).unwrap(), "bcd");
    }

    #[test]
    fn random_alnum_fails_on_a_short_source() {
        let error = random_alnum_from(4, &[1u8, 2][..]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        // Everything rejected, then the source runs dry.
        assert!(random_alnum_from(4, &[255u8; 4][..]).is_err());
    }

    #[test]
    fn random_alnum_of_zero_reads_nothing() {
        assert_eq!(random_alnum_from(0, io::empty()).unwrap(), "");
    }

    #[test]
    fn random_alnum_has_the_requested_length_alphabet_and_is_not_repeated() {
        for len in [1, 32, 64, 300] {
            let a = random_alnum(len).unwrap();
            let b = random_alnum(len).unwrap();
            assert_eq!(a.len(), len);
            assert!(a.bytes().all(|c| c.is_ascii_alphanumeric()));
            if len >= 32 {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn php_single_quote_escapes_only_backslash_and_quote() {
        assert_eq!(php_single_quote(""), "''");
        assert_eq!(php_single_quote("plain"), "'plain'");
        assert_eq!(php_single_quote("it's"), r"'it\'s'");
        assert_eq!(php_single_quote(r"a\b"), r"'a\\b'");
        assert_eq!(php_single_quote(r"\'"), r"'\\\''");
        assert_eq!(php_single_quote("'"), r"'\''");
        assert_eq!(php_single_quote("$x \"q\" %s"), "'$x \"q\" %s'");
        assert_eq!(
            php_single_quote("pä\u{20ac}\u{1f600}'"),
            "'pä\u{20ac}\u{1f600}\\''"
        );
    }

    #[test]
    fn truncate_head_never_splits_a_character() {
        assert_eq!(truncate_utf8_head("", 0), "");
        assert_eq!(truncate_utf8_head("", 4), "");
        assert_eq!(truncate_utf8_head("abc", 3), "abc");
        assert_eq!(truncate_utf8_head("abcd", 3), "abc");
        assert_eq!(truncate_utf8_head("abc", 0), "");
        assert_eq!(truncate_utf8_head("abc", 100), "abc");
        // 2-byte (\u{439}), 3-byte (\u{20ac}) and 4-byte (\u{1f600}) characters.
        assert_eq!(truncate_utf8_head("a\u{439}b", 2), "a");
        assert_eq!(truncate_utf8_head("a\u{439}b", 3), "a\u{439}");
        assert_eq!(truncate_utf8_head("\u{20ac}\u{20ac}", 5), "\u{20ac}");
        for max in 0..4 {
            assert_eq!(truncate_utf8_head("\u{1f600}x", max), "");
        }
        assert_eq!(truncate_utf8_head("\u{1f600}x", 4), "\u{1f600}");
        assert_eq!(truncate_utf8_head("\u{1f600}x", 5), "\u{1f600}x");
    }

    #[test]
    fn truncate_tail_never_splits_a_character() {
        assert_eq!(truncate_utf8_tail("", 0), "");
        assert_eq!(truncate_utf8_tail("", 4), "");
        assert_eq!(truncate_utf8_tail("abc", 3), "abc");
        assert_eq!(truncate_utf8_tail("abcd", 3), "bcd");
        assert_eq!(truncate_utf8_tail("abc", 0), "");
        assert_eq!(truncate_utf8_tail("abc", 100), "abc");
        assert_eq!(truncate_utf8_tail("a\u{439}b", 2), "b");
        assert_eq!(truncate_utf8_tail("a\u{439}b", 3), "\u{439}b");
        assert_eq!(truncate_utf8_tail("\u{20ac}\u{20ac}", 5), "\u{20ac}");
        for max in 0..4 {
            let text = "x\u{1f600}";
            let tail = truncate_utf8_tail(text, max);
            assert!(tail.len() <= max);
            assert!(text.ends_with(tail));
        }
        assert_eq!(truncate_utf8_tail("x\u{1f600}", 4), "\u{1f600}");
    }

    #[test]
    fn read_bounded_accepts_up_to_the_limit_only() {
        assert_eq!(read_bounded(io::empty(), 0).unwrap(), Some(Vec::new()));
        assert_eq!(read_bounded(&b"a"[..], 0).unwrap(), None);
        assert_eq!(read_bounded(&b"abc"[..], 3).unwrap(), Some(b"abc".to_vec()));
        assert_eq!(read_bounded(&b"abcd"[..], 3).unwrap(), None);
        assert_eq!(read_bounded(&b"ab"[..], 3).unwrap(), Some(b"ab".to_vec()));
        assert_eq!(
            read_bounded(&b"ab"[..], u64::MAX).unwrap().unwrap().len(),
            2
        );
    }

    #[test]
    fn read_bounded_reads_one_byte_past_the_limit_at_most() {
        let mut source = io::Cursor::new(vec![0u8; 1000]);
        assert_eq!(read_bounded(&mut source, 10).unwrap(), None);
        assert_eq!(source.position(), 11);
    }

    #[test]
    fn read_bounded_reports_read_errors() {
        struct Failing;
        impl Read for Failing {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("boom"))
            }
        }
        assert!(read_bounded(Failing, 8).is_err());
    }

    fn env_fixture(content: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        fs::write(&path, content).unwrap();
        (dir, path)
    }

    fn env_update(content: &str, updates: &[(&str, &str)]) -> String {
        let (_dir, path) = env_fixture(content);
        update_env_atomic(&path, updates, "env.test.tmp").unwrap();
        fs::read_to_string(&path).unwrap()
    }

    #[test]
    fn env_update_replaces_only_the_first_matching_line() {
        assert_eq!(
            env_update("A=1\nB=2\nA=3\n", &[("A", "9")]),
            "A=9\nB=2\nA=3\n"
        );
    }

    #[test]
    fn env_update_appends_missing_keys_and_adds_a_final_newline() {
        assert_eq!(env_update("A=1", &[("B", "2")]), "A=1\nB=2\n");
        assert_eq!(env_update("", &[("B", "2")]), "B=2\n");
        assert_eq!(
            env_update("A=1\n", &[("B", "2"), ("C", "3")]),
            "A=1\nB=2\nC=3\n"
        );
    }

    #[test]
    fn env_update_matches_the_key_prefix_exactly() {
        assert_eq!(
            env_update("AB=1\n A=2\nexport A=3\n#A=4\nA_=5\n", &[("A", "9")]),
            "AB=1\n A=2\nexport A=3\n#A=4\nA_=5\nA=9\n"
        );
    }

    #[test]
    fn env_update_leaves_quotes_comments_and_other_values_verbatim() {
        let original = "# header\nP='a=b'\nQ=\"x y\"\nEMPTY=\n\nK=old\n";
        assert_eq!(
            env_update(original, &[("K", "new=1 # not a comment")]),
            "# header\nP='a=b'\nQ=\"x y\"\nEMPTY=\n\nK=new=1 # not a comment\n"
        );
        assert_eq!(env_update(original, &[("EMPTY", "")]), original);
    }

    #[test]
    fn env_update_writes_the_value_without_quoting_it() {
        assert_eq!(env_update("K=1\n", &[("K", "'q'")]), "K='q'\n");
    }

    #[test]
    fn env_update_normalises_crlf_line_endings() {
        assert_eq!(env_update("A=1\r\nB=2\r\n", &[("B", "3")]), "A=1\nB=3\n");
    }

    #[test]
    fn env_update_refuses_values_with_cr_lf_or_nul_and_writes_nothing() {
        for bad in ["a\rb", "a\nb", "a\0b"] {
            let (dir, path) = env_fixture("A=1\n");
            let error =
                update_env_atomic(&path, &[("B", "ok"), ("A", bad)], "env.test.tmp").unwrap_err();
            assert_eq!(error.to_string(), "invalid env pointer");
            assert_eq!(fs::read_to_string(&path).unwrap(), "A=1\n");
            assert!(!dir.path().join(".env.env.test.tmp").exists());
        }
    }

    #[test]
    fn env_update_duplicate_updates_apply_in_order() {
        assert_eq!(env_update("A=1\n", &[("A", "2"), ("A", "3")]), "A=3\n");
        assert_eq!(env_update("", &[("A", "2"), ("A", "3")]), "A=3\n");
    }

    #[cfg(unix)]
    #[test]
    fn env_update_keeps_the_mode_and_leaves_no_temporary_file() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, path) = env_fixture("A=1\n");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        update_env_atomic(&path, &[("A", "2")], "env.test.tmp").unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn env_update_refuses_symlinks_and_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        fs::write(&target, "A=1\n").unwrap();
        let link = dir.path().join(".env");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let error = update_env_atomic(&link, &[("A", "2")], "env.test.tmp").unwrap_err();
        assert_eq!(error.to_string(), "compose env is not a regular file");
        assert_eq!(fs::read_to_string(&target).unwrap(), "A=1\n");
        assert!(update_env_atomic(&dir.path().join("none"), &[], "env.test.tmp").is_err());
    }

    #[test]
    fn env_update_refuses_an_existing_temporary_file() {
        let (dir, path) = env_fixture("A=1\n");
        fs::write(dir.path().join(".env.env.test.tmp"), "stale").unwrap();
        assert!(update_env_atomic(&path, &[("A", "2")], "env.test.tmp").is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "A=1\n");
    }
}
