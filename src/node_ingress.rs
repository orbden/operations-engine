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

pub fn render(domain: &Domain) -> String {
    let upstream = container_name(domain);
    format!(
        "{domain} {{\n\
    import /etc/wcp/ingress.d/bans/*.caddy\n\
    encode zstd gzip\n\
    header {{\n\
        Strict-Transport-Security \"max-age=31536000\"\n\
        X-Content-Type-Options \"nosniff\"\n\
        Referrer-Policy \"strict-origin-when-cross-origin\"\n\
        Permissions-Policy \"camera=(), microphone=(), geolocation=()\"\n\
        Content-Security-Policy \"frame-ancestors 'self'; base-uri 'self'; form-action 'self'; object-src 'none'\"\n\
        -Server\n\
        -X-Powered-By\n\
    }}\n\
    @versioned path /_astro/*\n\
    header @versioned Cache-Control \"public, max-age=31536000, immutable\"\n\
    reverse_proxy {upstream}:{APP_PORT} {{\n\
        header_up X-Request-ID {{http.request.uuid}}\n\
        header_down X-Request-ID {{http.request.uuid}}\n\
    }}\n\
    log_append request_id {{http.request.uuid}}\n\
    log_append domain {domain}\n\
}}\n"
    )
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
        assert!(route.starts_with("app.example.test {\n"));
        assert!(route.contains(&format!("reverse_proxy {}:4321 {{", container_name(&d))));
        assert_eq!(route.matches("reverse_proxy").count(), 1);
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
        // No other upstream, file server, PHP handler or host path.
        for forbidden in ["file_server", "php_fastcgi", "/var/www", "root *"] {
            assert!(!route.contains(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn the_route_depends_on_the_domain_only() {
        let d = domain("app.example.test");
        assert_eq!(render(&d), render(&domain("app.example.test")));
        assert_ne!(render(&d), render(&domain("other.example.test")));
    }
}
