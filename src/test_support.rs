//! Helpers shared by unit tests only.

use std::path::Path;

/// `path` as one POSIX shell word in single quotes, for fake-program scripts written by
/// tests. An embedded single quote is closed, escaped and reopened (`'\''`).
pub(crate) fn shell_quote(path: &Path) -> String {
    let text = path.to_str().expect("test paths are UTF-8");
    format!("'{}'", text.replace('\'', "'\\''"))
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
