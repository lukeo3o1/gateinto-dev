use std::fmt;
use std::str::FromStr;

use crate::config::{GatewayName, PortalUrl};
use crate::link::{GatewayAddress, Origin};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchRequest {
    pub profile: GatewayName,
    pub auth: LaunchAuth,
    pub url: Option<PortalUrl>,
    pub gateway: Option<GatewayAddress>,
    pub portal: Option<PortalUrl>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchAuth {
    BasicTofu,
}

impl LaunchAuth {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BasicTofu => "basic_tofu",
        }
    }
}

impl fmt::Display for LaunchAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for LaunchAuth {
    type Err = UriError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "basic_tofu" => Ok(Self::BasicTofu),
            _ => Err(UriError::InvalidValue("auth")),
        }
    }
}

pub const MAX_LEN: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UriError {
    TooLong,
    Form,
    Character,
    UnknownField,
    DuplicateField(&'static str),
    InvalidValue(&'static str),
    MissingProfile,
    GatewayWithoutPortal,
    PortalWithoutGateway,
    UrlOutsidePortal,
}

impl fmt::Display for UriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid launch URI: ")?;
        match self {
            Self::TooLong => write!(f, "longer than {MAX_LEN} bytes"),
            Self::Form => f.write_str("expected gateinto://connect?profile=<gateway>"),
            Self::Character => f.write_str(
                "field names and values may contain only A-Z, a-z, 0-9, -, ., _, ~ and \
                 %-escapes, joined by = and &; field names and the profile, auth and v values \
                 may decode only to A-Z, a-z, 0-9, _ and -",
            ),
            Self::UnknownField => {
                f.write_str("only the fields profile, auth, v, url, gateway and portal are allowed")
            }
            Self::DuplicateField(name) => write!(f, "the field {name} appears more than once"),
            Self::InvalidValue("profile") => write!(
                f,
                "profile must be a gateway name of 1 to {} characters that does not start with -",
                GatewayName::MAX_LEN
            ),
            Self::InvalidValue("auth") => f.write_str("auth must be basic_tofu"),
            Self::InvalidValue("v") => f.write_str("v must be 1"),
            Self::InvalidValue(name @ ("url" | "portal")) => write!(
                f,
                "{name} must be a percent-encoded https:// URL of at most {} characters whose \
                 host is a DNS name or an IP address, without user information, spaces, quotes \
                 or backslashes",
                PortalUrl::MAX_LEN
            ),
            Self::InvalidValue("gateway") => f.write_str(
                "gateway must be a percent-encoded host[:port]: a DNS name, an IPv4 address or \
                 a bracketed IPv6 address, and a port from 1 to 65535 (default 443)",
            ),
            Self::InvalidValue(name) => write!(f, "unsupported {name}"),
            Self::MissingProfile => f.write_str("the profile field is required"),
            Self::GatewayWithoutPortal => {
                f.write_str("a link that names a gateway must also name its portal")
            }
            Self::PortalWithoutGateway => {
                f.write_str("portal is allowed only together with gateway")
            }
            Self::UrlOutsidePortal => {
                f.write_str("url must have the same origin (https, host and port) as the portal")
            }
        }
    }
}

impl std::error::Error for UriError {}

const SCHEME: &str = "gateinto:";
const VERSION: &str = "1";

#[derive(Default)]
struct Fields {
    profile: Option<String>,
    auth: Option<String>,
    version: Option<String>,
    url: Option<String>,
    gateway: Option<String>,
    portal: Option<String>,
}

impl FromStr for LaunchRequest {
    type Err = UriError;

    fn from_str(uri: &str) -> Result<Self, Self::Err> {
        if uri.len() > MAX_LEN {
            return Err(UriError::TooLong);
        }
        let query = uri
            .get(..SCHEME.len())
            .filter(|scheme| scheme.eq_ignore_ascii_case(SCHEME))
            .and_then(|_| uri[SCHEME.len()..].strip_prefix("//connect"))
            .map(|rest| rest.strip_prefix('/').unwrap_or(rest))
            .and_then(|rest| rest.strip_prefix('?'))
            .filter(|query| !query.is_empty())
            .ok_or(UriError::Form)?;
        let mut fields = Fields::default();
        for field in query.split('&') {
            let (name, value) = field.split_once('=').ok_or(UriError::Character)?;
            let name = decode(name)?;
            let (name, slot, restricted) = match plain(&name)? {
                "profile" => ("profile", &mut fields.profile, true),
                "auth" => ("auth", &mut fields.auth, true),
                "v" => ("v", &mut fields.version, true),
                "url" => ("url", &mut fields.url, false),
                "gateway" => ("gateway", &mut fields.gateway, false),
                "portal" => ("portal", &mut fields.portal, false),
                _ => return Err(UriError::UnknownField),
            };
            let value = decode(value)?;
            let value = if restricted {
                plain(&value)?.to_owned()
            } else {
                printable(value).ok_or(UriError::InvalidValue(name))?
            };
            if slot.replace(value).is_some() {
                return Err(UriError::DuplicateField(name));
            }
        }
        if fields.version.is_some_and(|version| version != VERSION) {
            return Err(UriError::InvalidValue("v"));
        }
        Self::new(
            &fields.profile.ok_or(UriError::MissingProfile)?,
            fields
                .auth
                .as_deref()
                .unwrap_or(LaunchAuth::BasicTofu.as_str()),
        )?
        .with_link(
            fields.url.as_deref(),
            fields.gateway.as_deref(),
            fields.portal.as_deref(),
        )
    }
}

impl LaunchRequest {
    pub fn new(profile: &str, auth: &str) -> Result<Self, UriError> {
        if profile.starts_with('-') {
            return Err(UriError::InvalidValue("profile"));
        }
        Ok(Self {
            profile: profile
                .parse()
                .map_err(|_| UriError::InvalidValue("profile"))?,
            auth: auth.parse()?,
            url: None,
            gateway: None,
            portal: None,
        })
    }

    pub fn with_link(
        self,
        url: Option<&str>,
        gateway: Option<&str>,
        portal: Option<&str>,
    ) -> Result<Self, UriError> {
        let https = |value: &str, name| {
            value
                .parse::<PortalUrl>()
                .ok()
                .and_then(|url| Some((Origin::of(&url)?, url)))
                .ok_or(UriError::InvalidValue(name))
        };
        let url = url.map(|url| https(url, "url")).transpose()?;
        let gateway = gateway
            .map(|gateway| {
                gateway
                    .parse()
                    .map_err(|_| UriError::InvalidValue("gateway"))
            })
            .transpose()?;
        let portal = portal.map(|portal| https(portal, "portal")).transpose()?;
        match (&gateway, &portal) {
            (Some(_), None) => return Err(UriError::GatewayWithoutPortal),
            (None, Some(_)) => return Err(UriError::PortalWithoutGateway),
            _ => {}
        }
        if let (Some((url, _)), Some((portal, _))) = (&url, &portal)
            && url != portal
        {
            return Err(UriError::UrlOutsidePortal);
        }
        Ok(Self {
            url: url.map(|(_, url)| url),
            gateway,
            portal: portal.map(|(_, portal)| portal),
            ..self
        })
    }
}

impl fmt::Display for LaunchRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "gateinto://connect?profile={}&auth={}&v={VERSION}",
            self.profile, self.auth
        )?;
        if let Some(url) = &self.url {
            write!(f, "&url={}", Encoded(url.as_str()))?;
        }
        if let Some(gateway) = &self.gateway {
            write!(f, "&gateway={}", Encoded(&gateway.to_string()))?;
        }
        if let Some(portal) = &self.portal {
            write!(f, "&portal={}", Encoded(portal.as_str()))?;
        }
        Ok(())
    }
}

struct Encoded<'a>(&'a str);

impl fmt::Display for Encoded<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0.bytes() {
            if unreserved(byte) {
                write!(f, "{}", char::from(byte))?;
            } else {
                write!(f, "%{byte:02X}")?;
            }
        }
        Ok(())
    }
}

fn unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn allowed(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

fn plain(text: &[u8]) -> Result<&str, UriError> {
    if text.iter().all(|&byte| allowed(byte)) {
        Ok(std::str::from_utf8(text).expect("ASCII"))
    } else {
        Err(UriError::Character)
    }
}

fn printable(bytes: Vec<u8>) -> Option<String> {
    if bytes.iter().all(u8::is_ascii_graphic) {
        String::from_utf8(bytes).ok()
    } else {
        None
    }
}

fn decode(text: &str) -> Result<Vec<u8>, UriError> {
    let mut decoded = Vec::with_capacity(text.len());
    let mut bytes = text.bytes();
    while let Some(byte) = bytes.next() {
        let byte = match byte {
            b'%' => {
                let mut hex = || {
                    bytes
                        .next()
                        .and_then(|digit| char::from(digit).to_digit(16))
                        .ok_or(UriError::Character)
                };
                let high = hex()?;
                let low = hex()?;
                (high * 16 + low) as u8
            }
            byte if unreserved(byte) => byte,
            _ => return Err(UriError::Character),
        };
        decoded.push(byte);
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(uri: &str) -> Result<LaunchRequest, UriError> {
        uri.parse()
    }

    fn request(profile: &str) -> LaunchRequest {
        LaunchRequest::new(profile, "basic_tofu").unwrap()
    }

    const PORTAL: &str = "https%3A%2F%2Fportal.corp.example%2F";
    const START: &str = "https%3A%2F%2Fportal.corp.example%2Fapp%3Fx%3D1%26y%3D2";

    fn linked(url: Option<&str>, gateway: Option<&str>, portal: Option<&str>) -> LaunchRequest {
        request("corp").with_link(url, gateway, portal).unwrap()
    }

    #[test]
    fn a_profile_and_basic_tofu_are_accepted() {
        assert_eq!(
            parse("gateinto://connect?profile=my-gateway&auth=basic_tofu"),
            Ok(request("my-gateway"))
        );
    }

    #[test]
    fn auth_defaults_to_basic_tofu_and_keys_may_come_in_any_order() {
        for uri in [
            "gateinto://connect?profile=office_1",
            "gateinto://connect?auth=basic_tofu&profile=office_1",
            "gateinto://connect?v=1&profile=office_1",
            "gateinto://connect?profile=office_1&v=1&auth=basic_tofu",
        ] {
            assert_eq!(parse(uri), Ok(request("office_1")), "{uri}");
        }
    }

    #[test]
    fn the_scheme_is_case_insensitive_and_a_slash_may_end_the_authority() {
        for uri in [
            "GATEINTO://connect?profile=a",
            "GateInto://connect?profile=a",
            "gateinto://connect/?profile=a",
        ] {
            assert_eq!(parse(uri), Ok(request("a")), "{uri}");
        }
    }

    #[test]
    fn percent_encoded_characters_of_the_allowed_set_are_decoded() {
        assert_eq!(
            parse("gateinto://connect?profile=my%2Dgateway&auth=basic%5ftofu"),
            Ok(request("my-gateway"))
        );
        assert_eq!(parse("gateinto://connect?pro%66ile=a"), Ok(request("a")));
    }

    #[test]
    fn other_schemes_hosts_and_forms_are_rejected() {
        for uri in [
            "",
            "gateinto:",
            "gateinto://",
            "gateinto:connect?profile=a",
            "gateinto:/connect?profile=a",
            "gateinto:///connect?profile=a",
            "gateintox://connect?profile=a",
            "https://connect?profile=a",
            "gateinto://Connect?profile=a",
            "gateinto://launch?profile=a",
            "gateinto://connect.example?profile=a",
            "gateinto://user@connect?profile=a",
            "gateinto://user:pass@connect?profile=a",
            "gateinto://connect:443?profile=a",
            "gateinto://connect/path?profile=a",
            "gateinto://connect//?profile=a",
            "gateinto://connect",
            "gateinto://connect/",
            "gateinto://connect?",
            "gateinto://connect?profile=a#fragment",
            "gateinto://connect#?profile=a",
            "gateinto://connect?profile=a#",
            "gateinto://connect%3Fprofile=a",
        ] {
            assert!(parse(uri).is_err(), "{uri:?}");
        }
    }

    #[test]
    fn unknown_duplicate_empty_and_malformed_fields_are_rejected() {
        for query in [
            "auth=basic_tofu",
            "v=1",
            "profile=",
            "profile",
            "=a",
            "profile=a&",
            "&profile=a",
            "profile=a&&auth=basic_tofu",
            "profile=a&profile=a",
            "profile=a&profile=b",
            "profile=a&auth=basic_tofu&auth=basic_tofu",
            "profile=a&v=1&v=1",
            "profile=a&Profile=b",
            "PROFILE=a",
            "profile=a&auth=none",
            "profile=a&auth=Basic_Tofu",
            "profile=a&auth=",
            "profile=a&v=2",
            "profile=a&v=01",
            "profile=a&v=",
            "profile=a&url=https://evil.example",
            "profile=a&portal_url=https%3A%2F%2Fevil.example",
            "profile=a&host=evil.example",
            "profile=a&ca_file=evil.pem",
            "profile=a&password=secret",
            "profile=a=b",
            "profile==a",
            "profile=a;auth=basic_tofu",
        ] {
            let uri = format!("gateinto://connect?{query}");
            assert!(parse(&uri).is_err(), "{uri:?}");
        }
    }

    #[test]
    fn injection_attempts_are_rejected() {
        let long = "a".repeat(65);
        for profile in [
            "a b",
            "a+b",
            "a%20b",
            "a\"",
            "a%22",
            "a'",
            "a%27",
            "a\"%20--config%20evil",
            "--config",
            "-a",
            "a&",
            "a%26auth=basic_tofu",
            "a%00",
            "a%0a",
            "a%0D%0A",
            "%",
            "a%2",
            "a%zz",
            "a%%41",
            "%2541",
            "..",
            "%2E%2E",
            "..%2F..%2Fetc",
            "a/b",
            "a%2Fb",
            "a%5Cb",
            "a\\b",
            "C:",
            "a.b",
            "a$(calc)",
            "a`calc`",
            "a|calc",
            "a;calc",
            "a^b",
            "%61%62%63%E2%80%8B",
            "caf\u{e9}",
            "caf%C3%A9",
            "\u{202e}a",
            "a\u{0}",
            "a\t",
            &long,
        ] {
            let uri = format!("gateinto://connect?profile={profile}");
            assert!(parse(&uri).is_err(), "{uri:?}");
        }
    }

    #[test]
    fn leading_or_trailing_whitespace_and_quotes_are_rejected() {
        for uri in [
            " gateinto://connect?profile=a",
            "gateinto://connect?profile=a ",
            "\"gateinto://connect?profile=a\"",
            "gateinto://connect?profile=a\n",
            "gateinto://connect?profile=a\r\n",
        ] {
            assert!(parse(uri).is_err(), "{uri:?}");
        }
    }

    #[test]
    fn the_longest_profile_name_is_accepted() {
        let name = "a".repeat(GatewayName::MAX_LEN);
        let uri = format!("gateinto://connect?profile={name}&auth=basic_tofu&v=1");
        assert_eq!(parse(&uri), Ok(request(&name)));
    }

    #[test]
    fn uris_longer_than_the_limit_are_rejected_before_parsing() {
        let encoded = "%61".repeat(GatewayName::MAX_LEN);
        let fits = format!("gateinto://connect?profile={encoded}");
        assert!(fits.len() <= MAX_LEN);
        assert_eq!(parse(&fits), Ok(request(&"a".repeat(GatewayName::MAX_LEN))));
        let padded = format!("{fits}&auth=basic_tofu&v=1{}", "&".repeat(MAX_LEN));
        assert!(parse(&padded).is_err());
        let long = format!("gateinto://connect?profile=a{}", "a".repeat(MAX_LEN));
        assert_eq!(parse(&long).unwrap_err(), UriError::TooLong);
    }

    #[test]
    fn errors_name_the_rule_that_was_broken() {
        for (query, expected) in [
            ("profile=a&profile=a", UriError::DuplicateField("profile")),
            (
                "profile=a&auth=basic_tofu&auth=basic_tofu",
                UriError::DuplicateField("auth"),
            ),
            ("profile=a&host=x", UriError::UnknownField),
            ("profile=a&url=x", UriError::InvalidValue("url")),
            (
                "profile=a&gateway=x%40y&portal=x",
                UriError::InvalidValue("gateway"),
            ),
            (
                "profile=a&gateway=x&portal=http%3A%2F%2Fx",
                UriError::InvalidValue("portal"),
            ),
            ("profile=a&gateway=x", UriError::GatewayWithoutPortal),
            (
                "profile=a&portal=https%3A%2F%2Fx",
                UriError::PortalWithoutGateway,
            ),
            (
                "profile=a&gateway=x&portal=https%3A%2F%2Fx&url=https%3A%2F%2Fy",
                UriError::UrlOutsidePortal,
            ),
            (
                "profile=a&url=https%3A%2F%2Fx&url=https%3A%2F%2Fx",
                UriError::DuplicateField("url"),
            ),
            ("auth=basic_tofu", UriError::MissingProfile),
            ("profile=a&auth=none", UriError::InvalidValue("auth")),
            ("profile=a&v=2", UriError::InvalidValue("v")),
            ("profile=--a", UriError::InvalidValue("profile")),
            ("profile=a%20b", UriError::Character),
        ] {
            let uri = format!("gateinto://connect?{query}");
            assert_eq!(parse(&uri), Err(expected), "{uri}");
        }
        assert_eq!(parse("gateinto://connect/x?profile=a"), Err(UriError::Form));
    }

    #[test]
    fn a_start_page_and_a_gateway_with_its_portal_are_parsed() {
        assert_eq!(
            parse(&format!("gateinto://connect?profile=corp&url={START}")),
            Ok(linked(
                Some("https://portal.corp.example/app?x=1&y=2"),
                None,
                None
            ))
        );
        let uri = format!(
            "gateinto://connect?profile=corp&gateway=proxy.corp.example%3A443&portal={PORTAL}&url={START}"
        );
        let parsed = parse(&uri).unwrap();
        assert_eq!(
            parsed,
            linked(
                Some("https://portal.corp.example/app?x=1&y=2"),
                Some("proxy.corp.example:443"),
                Some("https://portal.corp.example/"),
            )
        );
        assert_eq!(
            parsed.gateway.unwrap().to_string(),
            "proxy.corp.example:443"
        );
        let parsed = parse("gateinto://connect?profile=corp&gateway=Proxy.Corp.Example&portal=https%3a%2f%2fp.example").unwrap();
        assert_eq!(
            parsed.gateway.unwrap().to_string(),
            "proxy.corp.example:443"
        );
        assert_eq!(parsed.portal.unwrap().as_str(), "https://p.example");
    }

    #[test]
    fn link_values_must_be_percent_encoded_and_valid() {
        for query in [
            "profile=a&url=https://portal.example/",
            "profile=a&url=https%3A//portal.example/",
            "profile=a&url=https%3A%2F%2Fportal.example%2Fa b",
            "profile=a&url=https%3A%2F%2Fportal.example%2Fa+b",
            "profile=a&url=https%3A%2F%2Fportal.example%2F%20",
            "profile=a&url=https%3A%2F%2Fportal.example%2F%0A",
            "profile=a&url=https%3A%2F%2Fportal.example%2F%C3%A9",
            "profile=a&url=https%3A%2F%2Fportal.example%2F%22",
            "profile=a&url=https%3A%2F%2Fportal.example%2F%5C",
            "profile=a&url=http%3A%2F%2Fportal.example%2F",
            "profile=a&url=javascript%3Aalert(1)",
            "profile=a&url=https%3A%2F%2Fuser%40portal.example%2F",
            "profile=a&url=https%3A%2F%2Fportal_1.example%2F",
            "profile=a&url=",
            "profile=a&gateway=&portal=https%3A%2F%2Fp.example",
            "profile=a&gateway=p.example&portal=",
            "profile=a&gateway=p.example:443&portal=https%3A%2F%2Fp.example",
            "profile=a&gateway=p.example%3A0&portal=https%3A%2F%2Fp.example",
            "profile=a&gateway=p.example%2Fx&portal=https%3A%2F%2Fp.example",
            "profile=a&gateway=%2A.example&portal=https%3A%2F%2Fp.example",
            "profile=a&gateway=p.example%20&portal=https%3A%2F%2Fp.example",
            "profile=a&gateway=p.example%5C&portal=https%3A%2F%2Fp.example",
            "profile=a&gateway=p.example%3F&portal=https%3A%2F%2Fp.example",
            "profile=a&gateway=p.example%23&portal=https%3A%2F%2Fp.example",
            "profile=a&gateway=p.example&portal=https%3A%2F%2Fp_1.example",
            "profile=a&gateway=p.example&portal=https%3A%2F%2Fp.example&url=https%3A%2F%2Fp.example%3A8443%2F",
            "profile=a&gateway=p.example&portal=https%3A%2F%2Fp.example&url=https%3A%2F%2Fevil.example%2F",
            "profile=a&gateway=p.example&portal=https%3A%2F%2Fp.example&url=https%3A%2F%2Fp.example.evil%2F",
            "profile=a&ca_file=x&gateway=p.example&portal=https%3A%2F%2Fp.example",
            "profile=a&tls_mode=x&gateway=p.example&portal=https%3A%2F%2Fp.example",
            "profile=a&listen=x&gateway=p.example&portal=https%3A%2F%2Fp.example",
            "profile=a&client_cert_file=x&gateway=p.example&portal=https%3A%2F%2Fp.example",
            "profile=a&gateway=p.example&gateway=q.example&portal=https%3A%2F%2Fp.example",
            "profile=a&gateway=p.example&portal=https%3A%2F%2Fp.example&portal=https%3A%2F%2Fp.example",
        ] {
            let uri = format!("gateinto://connect?{query}");
            assert!(parse(&uri).is_err(), "{uri:?}");
        }
    }

    #[test]
    fn a_start_page_on_the_portal_origin_is_accepted_with_the_default_port_spelled_out() {
        let uri = "gateinto://connect?profile=a&gateway=p.example&portal=https%3A%2F%2FP.example%2Fx&url=https%3A%2F%2Fp.example%3A443%2Fy";
        let parsed = parse(uri).unwrap();
        assert_eq!(parsed.url.unwrap().as_str(), "https://p.example:443/y");
    }

    #[test]
    fn requests_print_as_canonical_uris_that_parse_back() {
        for request in [
            request("office_1"),
            linked(
                Some("https://portal.corp.example/a?b=c&d=%20#e~f"),
                None,
                None,
            ),
            linked(
                Some("https://portal.corp.example/app"),
                Some("[2001:db8::1]:8443"),
                Some("https://portal.corp.example/"),
            ),
        ] {
            let uri = request.to_string();
            assert!(uri.starts_with("gateinto://connect?profile="), "{uri}");
            assert_eq!(parse(&uri), Ok(request), "{uri}");
        }
        assert_eq!(
            linked(Some("https://p.example/a~b?c=%20"), None, None).to_string(),
            "gateinto://connect?profile=corp&auth=basic_tofu&v=1&url=https%3A%2F%2Fp.example%2Fa~b%3Fc%3D%2520"
        );
    }

    #[test]
    fn the_longest_portal_and_start_page_fit_in_a_link() {
        let path = |len: usize| "a".repeat(len - "https://portal.corp.example/".len());
        let portal = format!("https%3A%2F%2Fportal.corp.example%2F{}", path(2048));
        let url = format!("https%3A%2F%2Fportal.corp.example%2F{}", path(2048));
        let name = "a".repeat(GatewayName::MAX_LEN);
        let host = format!("{}example", format!("{}.", "a".repeat(63)).repeat(3));
        let uri = format!(
            "gateinto://connect?profile={name}&auth=basic_tofu&v=1&gateway={host}%3A65535&portal={portal}&url={url}"
        );
        assert!(uri.len() <= MAX_LEN, "{}", uri.len());
        let parsed = parse(&uri).unwrap();
        assert_eq!(parsed.portal.unwrap().as_str().len(), 2048);
        assert_eq!(parsed.url.unwrap().as_str().len(), 2048);
    }

    #[test]
    fn the_longest_link_fits_the_windows_command_line() {
        const WINDOWS_COMMAND_LINE_MAX: usize = 32767;
        let long = format!("C:\\{}\\gateinto.exe", "a".repeat(1024));
        let command = crate::registration::handler_command(
            std::path::Path::new(&long),
            Some(std::path::Path::new(&format!(
                "C:\\{}.toml",
                "c".repeat(1024)
            ))),
        );
        let command = match command {
            Ok(command) => command,
            Err(_) => format!("\"{long}\" open --config \"{long}\" -- \"%1\""),
        };
        assert!(command.len() - "%1".len() + MAX_LEN < WINDOWS_COMMAND_LINE_MAX);
    }

    #[test]
    fn errors_do_not_echo_the_uri() {
        let error = parse("gateinto://connect?profile=secret%22value").unwrap_err();
        assert!(!error.to_string().contains("secret"), "{error}");
    }
}
