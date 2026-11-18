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

#[cfg(test)]
mod tests {
    use super::*;

    const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

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
}
