//! Helpers shared by unit tests only.

use std::path::Path;

/// `path` as one POSIX shell word in single quotes, for fake-program scripts written by
/// tests. An embedded single quote is closed, escaped and reopened (`'\''`).
pub(crate) fn shell_quote(path: &Path) -> String {
    let text = path.to_str().expect("test paths are UTF-8");
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// A ustar archive's modification time in tests' archives.
pub(crate) const TAR_MTIME: u64 = 1_700_000_000;

/// One ustar header block, checksum included.
pub(crate) fn tar_header(name: &str, typeflag: u8, size: u64, mode: u32, link: &str) -> [u8; 512] {
    let mut block = [0u8; 512];
    block[..name.len()].copy_from_slice(name.as_bytes());
    block[100..107].copy_from_slice(format!("{mode:07o}").as_bytes());
    block[124..135].copy_from_slice(format!("{size:011o}").as_bytes());
    block[136..147].copy_from_slice(format!("{TAR_MTIME:011o}").as_bytes());
    block[156] = typeflag;
    block[157..157 + link.len()].copy_from_slice(link.as_bytes());
    block[257..263].copy_from_slice(b"ustar\0");
    block[263..265].copy_from_slice(b"00");
    block[148..156].copy_from_slice(b"        ");
    let sum: u32 = block.iter().map(|&b| u32::from(b)).sum();
    block[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
    block
}

pub(crate) struct TarArchive(pub(crate) Vec<u8>);

impl TarArchive {
    pub(crate) fn new() -> Self {
        Self(Vec::new())
    }
    pub(crate) fn entry(
        mut self,
        name: &str,
        typeflag: u8,
        data: &[u8],
        mode: u32,
        link: &str,
    ) -> Self {
        self.0
            .extend_from_slice(&tar_header(name, typeflag, data.len() as u64, mode, link));
        self.0.extend_from_slice(data);
        let pad = (512 - data.len() % 512) % 512;
        self.0.extend(std::iter::repeat_n(0, pad));
        self
    }
    pub(crate) fn file(self, name: &str, data: &[u8]) -> Self {
        self.entry(name, b'0', data, 0o644, "")
    }
    pub(crate) fn end(mut self) -> Vec<u8> {
        self.0.extend_from_slice(&[0u8; 512 * 2]);
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn quotes_plain_paths_in_single_quotes() {
        assert_eq!(shell_quote(Path::new("/tmp/a b/c")), "'/tmp/a b/c'");
        assert_eq!(shell_quote(Path::new("")), "''");
        assert_eq!(
            shell_quote(Path::new("/tmp/\u{439}$x`y`")),
            "'/tmp/\u{439}$x`y`'"
        );
    }

    #[test]
    fn a_single_quote_in_the_path_survives_the_shell() {
        let path = Path::new("/tmp/it's here");
        assert_eq!(shell_quote(path), "'/tmp/it'\\''s here'");
        let out = Command::new("sh")
            .arg("-c")
            .arg(format!("printf %s {}", shell_quote(path)))
            .output()
            .unwrap();
        assert_eq!(String::from_utf8(out.stdout).unwrap(), "/tmp/it's here");
    }
}
