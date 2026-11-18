//! Small helpers shared by several operations.

use sha2::{Digest, Sha256};
use std::io::{self, Read};

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
}
