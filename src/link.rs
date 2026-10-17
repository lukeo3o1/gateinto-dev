use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use crate::config::PortalUrl;
use crate::http::{self, Authority, Host};

pub const DEFAULT_PORT: u16 = 443;

fn strict_host(text: &str) -> Option<Host> {
    if let Some(ip) = text.strip_prefix('[') {
        return ip.strip_suffix(']')?.parse().ok().map(Host::Ipv6);
    }
    match http::parse_host(text)? {
        Host::Name(name) => name
            .rsplit('.')
            .next()
            .filter(|last| last.starts_with(|c: char| c.is_ascii_alphabetic()))
            .map(|_| Host::Name(name.to_ascii_lowercase())),
        host => Some(host),
    }
}

fn host_and_port(authority: &str, empty_port: bool) -> Option<(Host, u16)> {
    let (host, port) = match authority.rfind(':') {
        Some(colon) if !authority[colon..].contains(']') => {
            (&authority[..colon], Some(&authority[colon + 1..]))
        }
        _ => (authority, None),
    };
    let port = match port {
        None => DEFAULT_PORT,
        Some("") if empty_port => DEFAULT_PORT,
        Some(port) if (1..=5).contains(&port.len()) && port.bytes().all(|b| b.is_ascii_digit()) => {
            port.parse().ok().filter(|&port| port != 0)?
        }
        Some(_) => return None,
    };
    Some((strict_host(host)?, port))
}

fn host_text(host: &Host) -> String {
    match host {
        Host::Name(name) => name.clone(),
        Host::Ipv4(ip) => ip.to_string(),
        Host::Ipv6(ip) => ip.to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayAddress(Authority);

impl GatewayAddress {
    pub fn host(&self) -> String {
        host_text(&self.0.host)
    }

    pub fn port(&self) -> u16 {
        self.0.port
    }

    pub fn matches(&self, host: &str, port: u16) -> bool {
        let same_host = match (&self.0.host, host.parse::<IpAddr>()) {
            (Host::Name(name), Err(_)) => name.eq_ignore_ascii_case(host),
            (Host::Ipv4(ip), Ok(other)) => IpAddr::from(*ip) == other,
            (Host::Ipv6(ip), Ok(other)) => IpAddr::from(*ip) == other,
            _ => false,
        };
        same_host && self.0.port == port
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidGatewayAddress;

impl fmt::Display for InvalidGatewayAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "gateway must be host[:port]: a DNS name, an IPv4 address or a bracketed IPv6 \
             address, and a port from 1 to 65535",
        )
    }
}

impl std::error::Error for InvalidGatewayAddress {}

impl FromStr for GatewayAddress {
    type Err = InvalidGatewayAddress;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        host_and_port(text, false)
            .map(|(host, port)| Self(Authority { host, port }))
            .ok_or(InvalidGatewayAddress)
    }
}

impl fmt::Display for GatewayAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    host: Host,
    port: u16,
}

impl Origin {
    pub fn of(url: &PortalUrl) -> Option<Self> {
        let rest = url.as_str().get("https://".len()..)?;
        let authority = rest.split(['/', '?', '#']).next()?;
        let (host, port) = host_and_port(authority, true)?;
        Some(Self { host, port })
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Host::Ipv6(ip) => write!(f, "https://[{ip}]")?,
            host => write!(f, "https://{}", host_text(host))?,
        }
        if self.port != DEFAULT_PORT {
            write!(f, ":{}", self.port)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(text: &str) -> Option<String> {
        text.parse::<GatewayAddress>().ok().map(|a| a.to_string())
    }

    #[test]
    fn gateway_addresses_default_to_port_443_and_lowercase_names() {
        for (text, expected) in [
            ("proxy.corp.example", "proxy.corp.example:443"),
            ("Proxy.Corp.Example:8443", "proxy.corp.example:8443"),
            ("localhost:1", "localhost:1"),
            ("xn--bcher-kva.example:65535", "xn--bcher-kva.example:65535"),
            ("10.0.0.1", "10.0.0.1:443"),
            ("127.0.0.1:3128", "127.0.0.1:3128"),
            ("[::1]", "[::1]:443"),
            ("[2001:DB8::1]:444", "[2001:db8::1]:444"),
        ] {
            assert_eq!(address(text).as_deref(), Some(expected), "{text}");
        }
    }

    #[test]
    fn gateway_addresses_are_validated_strictly() {
        let long_label = format!("{}.example", "a".repeat(64));
        let long_name = format!("{}example", "a.".repeat(127));
        for text in [
            "",
            ":443",
            "proxy.example:",
            "proxy.example:0",
            "proxy.example:65536",
            "proxy.example:+443",
            "proxy.example:0443x",
            "proxy.example:443:443",
            "user@proxy.example",
            "proxy.example/path",
            "proxy.example\\path",
            "proxy.example?q",
            "proxy.example#f",
            "*.example",
            "proxy .example",
            " proxy.example",
            "proxy.example\t",
            "proxy_1.example",
            "-proxy.example",
            "proxy-.example",
            "proxy..example",
            ".example",
            "proxy.example.",
            "127.1",
            "0x7f000001",
            "1.2.3.4.5",
            "01.2.3.4",
            "256.0.0.1",
            "::1",
            "[::1",
            "[::1]x",
            "[::1]:",
            "[fe80::1%eth0]",
            "[1.2.3.4]",
            "caf\u{e9}.example",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            assert_eq!(address(text), None, "{text:?}");
        }
    }

    #[test]
    fn gateway_hosts_never_contain_delimiters_or_whitespace() {
        let address: GatewayAddress = "[::1]:8443".parse().unwrap();
        assert_eq!(address.host(), "::1");
        assert_eq!(address.port(), 8443);
        let address: GatewayAddress = "Proxy.Example".parse().unwrap();
        assert_eq!(address.host(), "proxy.example");
    }

    #[test]
    fn gateway_addresses_match_configured_hosts_by_value() {
        let address: GatewayAddress = "proxy.example:443".parse().unwrap();
        assert!(address.matches("proxy.example", 443));
        assert!(address.matches("PROXY.example", 443));
        assert!(!address.matches("proxy.example", 444));
        assert!(!address.matches("other.example", 443));
        let address: GatewayAddress = "[::1]:443".parse().unwrap();
        assert!(address.matches("::1", 443));
        assert!(address.matches("0:0:0:0:0:0:0:1", 443));
        assert!(!address.matches("127.0.0.1", 443));
    }

    fn origin(url: &str) -> Option<String> {
        Origin::of(&url.parse().unwrap()).map(|o| o.to_string())
    }

    #[test]
    fn origins_omit_the_default_port_and_lowercase_the_host() {
        for (url, expected) in [
            ("https://portal.example", "https://portal.example"),
            ("HTTPS://Portal.Example/", "https://portal.example"),
            ("https://portal.example:443/a?b#c", "https://portal.example"),
            ("https://portal.example:/a", "https://portal.example"),
            (
                "https://portal.example:8443?x",
                "https://portal.example:8443",
            ),
            ("https://10.0.0.1#x", "https://10.0.0.1"),
            ("https://[::1]:444/", "https://[::1]:444"),
        ] {
            assert_eq!(origin(url).as_deref(), Some(expected), "{url}");
        }
    }

    #[test]
    fn portal_urls_without_a_strict_host_have_no_origin() {
        for url in [
            "https://portal_1.example/",
            "https://portal.example:0/",
            "https://portal.example:99999/",
            "https://%70ortal.example/",
            "https://portal.example./",
            "https://127.1/",
            "https://[::1/",
        ] {
            assert_eq!(origin(url), None, "{url}");
        }
    }

    #[test]
    fn same_origin_compares_scheme_host_and_port() {
        let same =
            |a: &str, b: &str| Origin::of(&a.parse().unwrap()) == Origin::of(&b.parse().unwrap());
        assert!(same("https://p.example/", "https://P.EXAMPLE:443/other?x"));
        assert!(!same("https://p.example/", "https://p.example:8443/"));
        assert!(!same("https://p.example/", "https://q.p.example/"));
        assert!(!same("https://p.example/", "https://p.example.evil/"));
    }
}
