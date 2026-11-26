//! Downloads a third-party archive whose SHA-256 the caller pinned (an
//! application release from the project's own site) into a private file and
//! hands it back only when it hashes to the pin. Nothing in the response is
//! trusted: no redirect is followed, the body is capped at a byte limit and
//! the whole transfer at a time limit (`engine::fetch`), the file is created
//! mode 0600 beneath a root-only directory, and on any failure, a digest
//! mismatch included, the partial file is removed.
//!
//! Which URLs are acceptable is the caller's rule (an official host and file
//! name per application); this module checks the digest's form only.

use std::{
    fs::File,
    io::{self, Read, Write},
    time::Duration,
};

use sha2::{Digest, Sha256};

use crate::{engine::fetch, filesystem::ManagedRoot, site::SiteRelativePath, util::hex};

/// Opens a stream of the URL's body, capped at the byte and time limits.
/// Production passes `engine::fetch::fetch_reader_bounded`; tests a fake.
pub type Fetch<'a> = &'a dyn Fn(&str, u64, Duration) -> Result<Box<dyn Read>, fetch::Error>;

#[derive(Debug)]
pub enum Error {
    Fetch(fetch::Error),
    /// The body was cut off, too large or could not be written.
    Io(io::Error),
    DigestMismatch,
}

/// Whether `value` is a SHA-256 in the form pins are written: 64 lowercase
/// hexadecimal characters.
pub fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Streams `url` into the new file `name` of `dir` while hashing it and
/// returns it opened for reading when its SHA-256 is `sha256`. `name` must not
/// exist. On any error the file is gone.
pub fn download(
    fetch: Fetch<'_>,
    url: &str,
    sha256: &str,
    max_bytes: u64,
    timeout: Duration,
    dir: &ManagedRoot,
    name: &SiteRelativePath,
) -> Result<File, Error> {
    if !is_sha256_hex(sha256) {
        return Err(Error::DigestMismatch);
    }
    let mut file = dir
        .create_new_file_with_mode(name, 0o600)
        .map_err(Error::Io)?;
    let result = fetch(url, max_bytes, timeout)
        .map_err(Error::Fetch)
        .and_then(|mut body| copy_hashing(&mut body, &mut file).map_err(Error::Io))
        .and_then(|actual| {
            if actual == sha256 {
                Ok(())
            } else {
                Err(Error::DigestMismatch)
            }
        })
        // The write handle is closed before the file is opened for reading.
        .and_then(|()| {
            drop(file);
            dir.open_regular_read(name).map_err(Error::Io)
        });
    if result.is_err() {
        let _ = dir.remove_file(name);
    }
    result
}

fn copy_hashing(body: &mut dyn Read, file: &mut File) -> io::Result<String> {
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 256 * 1024];
    loop {
        let read = match body.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        digest.update(&buffer[..read]);
        file.write_all(&buffer[..read])?;
    }
    file.sync_all()?;
    Ok(hex(&digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::site::TrustedRoot;
    use std::{
        io::{BufRead, BufReader},
        net::TcpListener,
        os::unix::fs::PermissionsExt,
    };

    const BODY: &[u8] = b"archive bytes";

    fn digest(bytes: &[u8]) -> String {
        crate::util::sha256_hex(bytes)
    }

    fn dir() -> (tempfile::TempDir, ManagedRoot) {
        let temp = tempfile::tempdir().unwrap();
        let root = ManagedRoot::open(&TrustedRoot::parse(temp.path()).unwrap()).unwrap();
        (temp, root)
    }

    fn name() -> SiteRelativePath {
        SiteRelativePath::parse("archive.part").unwrap()
    }

    fn serving(
        body: &'static [u8],
    ) -> impl Fn(&str, u64, Duration) -> Result<Box<dyn Read>, fetch::Error> {
        move |_, max, _| Ok(Box::new(io::Read::take(body, max)) as Box<dyn Read>)
    }

    #[test]
    fn digest_form_table() {
        let good = digest(BODY);
        assert!(is_sha256_hex(&good));
        for bad in [
            "",
            &good[..63],
            &format!("{good}0"),
            &good.to_ascii_uppercase(),
            &format!("{}g", &good[..63]),
            &format!(" {}", &good[..63]),
        ] {
            assert!(!is_sha256_hex(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_matching_download_is_returned_private_and_readable() {
        let (temp, root) = dir();
        let fetch = serving(BODY);
        let mut file = download(
            &fetch,
            "https://example.org/a",
            &digest(BODY),
            1024,
            Duration::from_secs(5),
            &root,
            &name(),
        )
        .unwrap();
        let mut read = Vec::new();
        file.read_to_end(&mut read).unwrap();
        assert_eq!(read, BODY);
        let mode = std::fs::metadata(temp.path().join("archive.part"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn a_mismatch_a_bad_pin_or_a_failed_fetch_leaves_no_file() {
        let (temp, root) = dir();
        let fetch = serving(BODY);
        let failing = |_: &str, _: u64, _: Duration| -> Result<Box<dyn Read>, fetch::Error> {
            Err(fetch::Error::Status(404))
        };
        let other = digest(b"something else");
        for (fetch, pin) in [
            (&fetch as Fetch<'_>, other.as_str()),
            (&fetch, "not-a-digest"),
            (&failing, digest(BODY).as_str()),
        ] {
            assert!(
                download(
                    fetch,
                    "https://example.org/a",
                    pin,
                    1024,
                    Duration::from_secs(5),
                    &root,
                    &name()
                )
                .is_err()
            );
            assert!(!temp.path().join("archive.part").exists(), "{pin}");
        }
        // A body cut at the limit hashes differently: refused.
        assert!(matches!(
            download(
                &fetch,
                "https://example.org/a",
                &digest(BODY),
                4,
                Duration::from_secs(5),
                &root,
                &name()
            ),
            Err(Error::DigestMismatch)
        ));
        assert!(!temp.path().join("archive.part").exists());
    }

    #[test]
    fn an_existing_file_is_never_replaced() {
        let (temp, root) = dir();
        std::fs::write(temp.path().join("archive.part"), "mine").unwrap();
        let fetch = serving(BODY);
        assert!(matches!(
            download(
                &fetch,
                "https://example.org/a",
                &digest(BODY),
                1024,
                Duration::from_secs(5),
                &root,
                &name()
            ),
            Err(Error::Io(_))
        ));
        assert_eq!(
            std::fs::read(temp.path().join("archive.part")).unwrap(),
            b"mine"
        );
    }

    /// One plain-HTTP response on a loopback port (the only plain-HTTP
    /// destination `engine::fetch` allows).
    fn serve_once(response: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap() > 2 {
                line.clear();
            }
            stream.write_all(response.as_bytes()).unwrap();
        });
        format!("http://127.0.0.1:{port}/archive")
    }

    #[test]
    fn the_real_fetch_follows_no_redirect_and_honours_the_size_limit() {
        let (temp, root) = dir();
        let fetch =
            |url: &str, max: u64, timeout: Duration| fetch::fetch_reader_bounded(url, max, timeout);
        let ok = serve_once(
            "HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\narchive bytes",
        );
        assert!(
            download(
                &fetch,
                &ok,
                &digest(BODY),
                1024,
                Duration::from_secs(10),
                &root,
                &name()
            )
            .is_ok()
        );
        std::fs::remove_file(temp.path().join("archive.part")).unwrap();

        let redirect = serve_once(
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        assert!(matches!(
            download(
                &fetch,
                &redirect,
                &digest(BODY),
                1024,
                Duration::from_secs(10),
                &root,
                &name()
            ),
            Err(Error::Fetch(fetch::Error::Status(302)))
        ));
        let large = serve_once(
            "HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\narchive bytes",
        );
        assert!(matches!(
            download(
                &fetch,
                &large,
                &digest(BODY),
                5,
                Duration::from_secs(10),
                &root,
                &name()
            ),
            Err(Error::Io(_))
        ));
        assert!(!temp.path().join("archive.part").exists());
    }
}
