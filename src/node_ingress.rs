//! Caddy route and resource names of a hosted Node application.
//!
//! The route is rendered from the domain alone, so the engine can tell a route
//! it manages from any other one by comparing text. Only this application's
//! container is an upstream, reached by its fixed name on a network the
//! ingress container joins; nothing in a request can name another upstream.
//!
//! Security headers are set on this route only (not on the shared ingress):
//! HSTS, `nosniff`, a referrer policy, a permissions policy and a
//! `Content-Security-Policy` limited to the directives that never break an
//! application (`frame-ancestors`, `base-uri`, `form-action`, `object-src`);
//! a script/style policy belongs to the application, which knows its own
//! inline code. Responses are compressed, versioned `/_astro/*` assets are
//! cached as immutable and every other response keeps the application's own
//! cache headers. Caddy keeps its upstream connections alive by default.

use crate::{site::Domain, util::sha256_hex};

/// The private port the application listens on inside its container.
pub const APP_PORT: u16 = 4321;

fn short(domain: &Domain) -> String {
    sha256_hex(domain.as_str().as_bytes())[..12].to_owned()
}

/// Container name; also the upstream host name on the application's network.
pub fn container_name(domain: &Domain) -> String {
    format!("wcp-node-{}", short(domain))
}

/// The user-defined network that joins the application and the ingress only.
pub fn network_name(domain: &Domain) -> String {
    format!("wcp-node-net-{}", short(domain))
}

/// Where the ingress container sees the host's `/var/lib/wcp-static`.
pub const STATIC_MOUNT: &str = "/srv/wcp-static";

/// The directory (under the static root) that holds one application's
/// published client files: `<domain>-assets/` with the build's
/// `dist/client` tree, hashed files under `_astro/`.
pub fn assets_dir_name(domain: &Domain) -> String {
    format!("{domain}-assets")
}

/// How much of the application's client files the route serves itself.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Form {
    /// Everything goes to the application (the first releases).
    Proxy,
    /// Only the hashed `/_astro/*` files, from the published copy.
    HashedOnly,
    /// Any published client file (`favicon`, `robots.txt`, images, the hashed
    /// files); the unhashed ones get a short cache lifetime.
    Published,
}

/// The route this engine writes today: a file the build published to the
/// ingress's static directory is served by the ingress, and every other
/// request, and any file not published, goes to the application.
pub fn render(domain: &Domain) -> String {
    render_with(domain, Form::Published)
}

/// Routes written by earlier releases of this engine. A host still on one is
/// the engine's own route: the next deploy replaces it.
fn earlier_forms(domain: &Domain) -> [String; 2] {
    [
        render_with(domain, Form::Proxy),
        render_with(domain, Form::HashedOnly),
    ]
}

/// `text` is a route this engine wrote for `domain`, in any form.
pub fn is_managed(domain: &Domain, text: &str) -> bool {
    text == render(domain) || earlier_forms(domain).iter().any(|form| form == text)
}

/// The first form, for tests that adopt it.
#[cfg(test)]
pub fn render_legacy(domain: &Domain) -> String {
    render_with(domain, Form::Proxy)
}

fn render_with(domain: &Domain, form: Form) -> String {
    let upstream = container_name(domain);
    let root = format!("{STATIC_MOUNT}/{}", assets_dir_name(domain));
    // One line per entry (a Rust `\` continuation would drop the indentation).
    let mut lines = vec![
        format!("{domain} {{"),
        "    import /etc/wcp/ingress.d/bans/*.caddy".to_owned(),
        "    encode zstd gzip".to_owned(),
        "    header {".to_owned(),
        "        Strict-Transport-Security \"max-age=31536000\"".to_owned(),
        "        X-Content-Type-Options \"nosniff\"".to_owned(),
        "        Referrer-Policy \"strict-origin-when-cross-origin\"".to_owned(),
        "        Permissions-Policy \"camera=(), microphone=(), geolocation=()\"".to_owned(),
        "        Content-Security-Policy \"frame-ancestors 'self'; base-uri 'self'; form-action 'self'; object-src 'none'\"".to_owned(),
        "        -Server".to_owned(),
        "        -X-Powered-By".to_owned(),
        "    }".to_owned(),
        "    @versioned path /_astro/*".to_owned(),
        "    header @versioned Cache-Control \"public, max-age=31536000, immutable\"".to_owned(),
    ];
    let proxied = form != Form::Proxy;
    if proxied {
        lines.push("    @published {".to_owned());
        if form == Form::HashedOnly {
            lines.push("        path /_astro/*".to_owned());
        }
        lines.extend([
            "        file {".to_owned(),
            format!("            root {root}"),
            "            try_files {path}".to_owned(),
            "        }".to_owned(),
            "    }".to_owned(),
            "    handle @published {".to_owned(),
            format!("        root * {root}"),
        ]);
        if form == Form::Published {
            lines.extend([
                "        @unhashed not path /_astro/*".to_owned(),
                "        header @unhashed Cache-Control \"public, max-age=3600\"".to_owned(),
            ]);
        }
        lines.extend([
            "        file_server".to_owned(),
            "    }".to_owned(),
            "    handle {".to_owned(),
        ]);
    }
    let pad = if proxied { "    " } else { "" };
    lines.extend([
        format!("{pad}    reverse_proxy {upstream}:{APP_PORT} {{"),
        format!("{pad}        header_up X-Request-ID {{http.request.uuid}}"),
        format!("{pad}        header_down X-Request-ID {{http.request.uuid}}"),
        format!("{pad}    }}"),
    ]);
    if proxied {
        lines.push("    }".to_owned());
    }
    lines.extend([
        "    log_append request_id {http.request.uuid}".to_owned(),
        format!("    log_append domain {domain}"),
        "}".to_owned(),
    ]);
    lines.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(value: &str) -> Domain {
        Domain::parse(value).unwrap()
    }

    #[test]
    fn names_are_stable_short_and_distinct_per_domain() {
        let a = domain("a.example.test");
        let b = domain("b.example.test");
        assert_eq!(container_name(&a), container_name(&a));
        assert_ne!(container_name(&a), container_name(&b));
        assert_ne!(network_name(&a), network_name(&b));
        assert!(container_name(&a).len() <= 63 && network_name(&a).len() <= 63);
        assert!(container_name(&a).starts_with("wcp-node-"));
    }

    #[test]
    fn the_route_proxies_one_private_upstream_with_edge_hardening() {
        let d = domain("app.example.test");
        let route = render(&d);
        assert!(route.starts_with("app.example.test {\n    import "));
        assert!(
            route
                .lines()
                .skip(1)
                .all(|line| line.is_empty() || line.starts_with("    ") || line == "}")
        );
        assert!(route.contains(&format!("reverse_proxy {}:4321 {{", container_name(&d))));
        assert_eq!(route.matches("reverse_proxy").count(), 1);
        assert_eq!(render_legacy(&d).matches("reverse_proxy").count(), 1);
        for wanted in [
            "import /etc/wcp/ingress.d/bans/*.caddy",
            "encode zstd gzip",
            "Strict-Transport-Security",
            "X-Content-Type-Options \"nosniff\"",
            "frame-ancestors 'self'",
            "-Server",
            "@versioned path /_astro/*",
            "immutable",
            "log_append request_id",
        ] {
            assert!(route.contains(wanted), "{wanted}\n{route}");
        }
        // No other upstream, PHP handler or host path; the only file server
        // is the published copy of the hashed assets, and the legacy form has
        // none.
        for forbidden in ["php_fastcgi", "/var/www"] {
            assert!(!route.contains(forbidden), "{forbidden}");
        }
        assert_eq!(route.matches("file_server").count(), 1);
        assert_eq!(route.matches("root * ").count(), 1);
        assert!(route.contains("root * /srv/wcp-static/app.example.test-assets\n"));
        for forbidden in ["file_server", "root *", "handle"] {
            assert!(!render_legacy(&d).contains(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn the_new_route_proxies_everything_that_is_not_a_published_asset() {
        let route = render(&domain("app.example.test"));
        let published = route.find("handle @published {").unwrap();
        let proxied = route.find("    handle {").unwrap();
        let proxy = route.find("reverse_proxy").unwrap();
        assert!(published < proxied && proxied < proxy);
        // Any published file, but only when the file exists there.
        assert!(route.contains("@published {\n        file {"));
        assert!(route.contains("try_files {path}"));
        // Unhashed files get a short lifetime; the hashed ones stay immutable.
        assert!(route.contains("@unhashed not path /_astro/*"));
        assert!(route.contains("header @unhashed Cache-Control \"public, max-age=3600\""));
        // Braces balance, so Caddy accepts the text.
        assert_eq!(route.matches('{').count(), route.matches('}').count());
    }

    #[test]
    fn every_earlier_form_is_still_the_engines_own_route() {
        let d = domain("app.example.test");
        let upstream = container_name(&d);
        // The form that served only `/_astro/*` from the published copy,
        // written out as it was released.
        let hashed_only = format!(
            "app.example.test {{\n    import /etc/wcp/ingress.d/bans/*.caddy\n    encode zstd gzip\n    header {{\n        Strict-Transport-Security \"max-age=31536000\"\n        X-Content-Type-Options \"nosniff\"\n        Referrer-Policy \"strict-origin-when-cross-origin\"\n        Permissions-Policy \"camera=(), microphone=(), geolocation=()\"\n        Content-Security-Policy \"frame-ancestors 'self'; base-uri 'self'; form-action 'self'; object-src 'none'\"\n        -Server\n        -X-Powered-By\n    }}\n    @versioned path /_astro/*\n    header @versioned Cache-Control \"public, max-age=31536000, immutable\"\n    @published {{\n        path /_astro/*\n        file {{\n            root /srv/wcp-static/app.example.test-assets\n            try_files {{path}}\n        }}\n    }}\n    handle @published {{\n        root * /srv/wcp-static/app.example.test-assets\n        file_server\n    }}\n    handle {{\n        reverse_proxy {upstream}:4321 {{\n            header_up X-Request-ID {{http.request.uuid}}\n            header_down X-Request-ID {{http.request.uuid}}\n        }}\n    }}\n    log_append request_id {{http.request.uuid}}\n    log_append domain app.example.test\n}}\n"
        );
        assert!(is_managed(&d, &hashed_only));
        assert_ne!(hashed_only, render(&d));
    }

    #[test]
    fn both_forms_are_managed_and_nothing_else_is() {
        let d = domain("app.example.test");
        assert!(is_managed(&d, &render(&d)));
        assert!(is_managed(&d, &render_legacy(&d)));
        assert!(!is_managed(&d, "app.example.test {\n    respond 200\n}\n"));
        assert!(!is_managed(&d, &render(&domain("other.example.test"))));
        assert_eq!(assets_dir_name(&d), "app.example.test-assets");
    }

    #[test]
    fn the_route_depends_on_the_domain_only() {
        let d = domain("app.example.test");
        assert_eq!(render(&d), render(&domain("app.example.test")));
        assert_ne!(render(&d), render(&domain("other.example.test")));
    }
}
