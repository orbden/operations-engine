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
}
