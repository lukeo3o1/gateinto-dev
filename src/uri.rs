use std::fmt;
use std::str::FromStr;

use crate::config::GatewayName;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchRequest {
    pub profile: GatewayName,
    pub auth: LaunchAuth,
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

pub const MAX_LEN: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UriError {
    TooLong,
    Form,
    Character,
    UnknownField,
    DuplicateField(&'static str),
    InvalidValue(&'static str),
    MissingProfile,
}

impl fmt::Display for UriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid launch URI: ")?;
        match self {
            Self::TooLong => write!(f, "longer than {MAX_LEN} bytes"),
            Self::Form => f.write_str("expected gateinto://connect?profile=<gateway>"),
            Self::Character => f.write_str(
                "only A-Z, a-z, 0-9, _ and - are allowed in field names and values, \
                 joined by = and &",
            ),
            Self::UnknownField => f.write_str("only the fields profile, auth and v are allowed"),
            Self::DuplicateField(name) => write!(f, "the field {name} appears more than once"),
            Self::InvalidValue("profile") => write!(
                f,
                "profile must be a gateway name of 1 to {} characters that does not start with -",
                GatewayName::MAX_LEN
            ),
            Self::InvalidValue("auth") => f.write_str("auth must be basic_tofu"),
            Self::InvalidValue(name) => write!(f, "unsupported {name}"),
            Self::MissingProfile => f.write_str("the profile field is required"),
        }
    }
}

impl std::error::Error for UriError {}

const SCHEME: &str = "gateinto:";
const VERSION: &str = "1";

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
        let (mut profile, mut auth, mut version) = (None, None, None);
        for field in query.split('&') {
            let (name, value) = field.split_once('=').ok_or(UriError::Character)?;
            let value = decode(value)?;
            let (name, slot) = match decode(name)?.as_str() {
                "profile" => ("profile", &mut profile),
                "auth" => ("auth", &mut auth),
                "v" => ("v", &mut version),
                _ => return Err(UriError::UnknownField),
            };
            if slot.replace(value).is_some() {
                return Err(UriError::DuplicateField(name));
            }
        }
        if version.is_some_and(|version| version != VERSION) {
            return Err(UriError::InvalidValue("v"));
        }
        let profile = profile.ok_or(UriError::MissingProfile)?;
        if profile.starts_with('-') {
            return Err(UriError::InvalidValue("profile"));
        }
        Ok(Self {
            profile: profile
                .parse()
                .map_err(|_| UriError::InvalidValue("profile"))?,
            auth: auth.map_or(Ok(LaunchAuth::BasicTofu), |auth| auth.parse())?,
        })
    }
}

fn allowed(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

fn decode(text: &str) -> Result<String, UriError> {
    let mut decoded = String::with_capacity(text.len());
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
            byte => byte,
        };
        if !allowed(byte) {
            return Err(UriError::Character);
        }
        decoded.push(char::from(byte));
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
        LaunchRequest {
            profile: profile.parse().unwrap(),
            auth: LaunchAuth::BasicTofu,
        }
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
            ("profile=a&url=x", UriError::UnknownField),
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
    fn errors_do_not_echo_the_uri() {
        let error = parse("gateinto://connect?profile=secret%22value").unwrap_err();
        assert!(!error.to_string().contains("secret"), "{error}");
    }
}
