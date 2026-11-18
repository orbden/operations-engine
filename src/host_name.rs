//! Shared host-name grammar for values that name a network peer.

use std::net::Ipv4Addr;

/// Longest textual DNS name, without a trailing dot.
const MAX_NAME_LEN: usize = 253;
/// Longest single DNS label.
const MAX_LABEL_LEN: usize = 63;

/// A DNS host name or dotted-quad IPv4 text: 1..=253 bytes in non-empty
/// labels of at most 63 ASCII letters, digits and `-`, no label starting or
/// ending with `-`. No trailing dot, no port, no IPv6. A name whose last
/// label is all digits and that has more than one label must be a valid IPv4
/// address (`999.1.1.1` is neither a name nor an address).
pub(crate) fn is_dns_name_or_ipv4(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_NAME_LEN {
        return false;
    }
    let labels_ok = value.split('.').all(|label| {
        let bytes = label.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= MAX_LABEL_LEN
            && bytes[0] != b'-'
            && bytes[bytes.len() - 1] != b'-'
            && bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
    });
    if !labels_ok {
        return false;
    }
    match value.rsplit_once('.') {
        Some((_, last)) if last.bytes().all(|b| b.is_ascii_digit()) => {
            value.parse::<Ipv4Addr>().is_ok()
        }
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_name_or_ipv4_table() {
        let long_label = "a".repeat(63);
        let name_253 = format!("{0}.{0}.{0}.{1}", long_label, "a".repeat(61));
        assert_eq!(name_253.len(), 253);
        assert!(is_dns_name_or_ipv4(&name_253));
        assert!(!is_dns_name_or_ipv4(&format!("{name_253}a")));
        assert!(!is_dns_name_or_ipv4(&"a".repeat(64)));
        assert!(is_dns_name_or_ipv4(&"a".repeat(63)));
        for ok in [
            "a",
            "9",
            "localhost",
            "example.com",
            "a-b.c",
            "UPPER.example",
            "1.2.3.4",
        ] {
            assert!(is_dns_name_or_ipv4(ok), "{ok:?}");
        }
        for bad in [
            "",
            ".",
            "-",
            "a..b",
            ".a",
            "a.",
            "-a",
            "a-",
            "a.-b",
            "a-.b",
            "a.-.b",
            "a b",
            " a",
            "a\n",
            "a\0b",
            ":::",
            "]]",
            "[",
            "a:",
            "a:587",
            "[::1]",
            "a/b",
            "a_b",
            "\u{e9}.com",
            "999.1.1.1",
            "1.2.3",
            "01.2.3.4",
            "1.2.3.4.5",
        ] {
            assert!(!is_dns_name_or_ipv4(bad), "{bad:?}");
        }
    }
}
