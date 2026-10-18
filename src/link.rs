use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;
use std::str::FromStr;

use crate::config::{ConfigFile, GatewayName, PortalUrl};
use crate::http::{self, Authority, Host};
use crate::uri::LaunchRequest;

pub mod store;

pub const DEFAULT_PORT: u16 = 443;

fn local_ipv4(ip: Ipv4Addr) -> bool {
    let [first, second, ..] = ip.octets();
    let shared = first == 100 && second & 0xc0 == 64;
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || first == 0
        || shared
}

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

    fn ip(&self) -> Option<IpAddr> {
        match self.0.host {
            Host::Name(_) => None,
            Host::Ipv4(ip) => Some(IpAddr::V4(ip)),
            Host::Ipv6(ip) => Some(IpAddr::V6(ip).to_canonical()),
        }
    }

    pub fn matches(&self, host: &str, port: u16) -> bool {
        let same_host = match (&self.0.host, host.parse::<IpAddr>()) {
            (Host::Name(name), Err(_)) => name.eq_ignore_ascii_case(host),
            (Host::Name(_), Ok(_)) => false,
            (_, Ok(other)) => self.ip() == Some(other.to_canonical()),
            (_, Err(_)) => false,
        };
        same_host && self.0.port == port
    }

    pub fn is_local(&self) -> bool {
        match (&self.0.host, self.ip()) {
            (Host::Name(name), _) => name == "localhost" || name.ends_with(".localhost"),
            (_, Some(IpAddr::V4(ip))) => local_ipv4(ip),
            (_, Some(IpAddr::V6(ip))) => {
                let [a, b, c, d, e, f, ..] = ip.segments();
                let nat64 = [a, b, c, d, e, f] == [0x64, 0xff9b, 0, 0, 0, 0];
                ip.is_loopback()
                    || ip.is_unspecified()
                    || ip.is_unique_local()
                    || ip.is_unicast_link_local()
                    || nat64 && local_ipv4(Ipv4Addr::from_bits(ip.to_bits() as u32))
            }
            (_, None) => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidGatewayAddress {
    Syntax,
    Reserved,
}

impl fmt::Display for InvalidGatewayAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Syntax => {
                "gateway must be host[:port]: a DNS name, an IPv4 address or a bracketed IPv6 \
                 address, and a port from 1 to 65535"
            }
            Self::Reserved => {
                "the gateway host must not start with a Windows device name (CON, PRN, AUX, \
                 NUL, COM0 to COM9, LPT0 to LPT9)"
            }
        })
    }
}

impl std::error::Error for InvalidGatewayAddress {}

fn reserved_device_name(name: &str) -> bool {
    let first = name.split('.').next().unwrap_or_default();
    match first.len() {
        3 => ["con", "prn", "aux", "nul"].contains(&first),
        4 => {
            (first.starts_with("com") || first.starts_with("lpt"))
                && first.as_bytes()[3].is_ascii_digit()
        }
        _ => false,
    }
}

impl FromStr for GatewayAddress {
    type Err = InvalidGatewayAddress;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (host, port) = host_and_port(text, false).ok_or(InvalidGatewayAddress::Syntax)?;
        let host = match host {
            Host::Ipv6(ip) => match IpAddr::V6(ip).to_canonical() {
                IpAddr::V4(ip) => Host::Ipv4(ip),
                IpAddr::V6(ip) => Host::Ipv6(ip),
            },
            // Its file name, with '-' for ':', would be the same as an IPv6 address's.
            Host::Name(name) if name.replace('-', ":").parse::<Ipv6Addr>().is_ok() => {
                return Err(InvalidGatewayAddress::Syntax);
            }
            Host::Name(name) if reserved_device_name(&name) => {
                return Err(InvalidGatewayAddress::Reserved);
            }
            host => host,
        };
        Ok(Self(Authority { host, port }))
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Config,
    Linked,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Config => "config",
            Self::Linked => "linked",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownGateway {
    pub name: GatewayName,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub portal_url: Option<PortalUrl>,
    pub source: Source,
}

impl KnownGateway {
    fn is_at(&self, address: &GatewayAddress) -> bool {
        match (&self.host, self.port) {
            (Some(host), Some(port)) => address.matches(host, port),
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedGateway {
    pub name: GatewayName,
    pub address: GatewayAddress,
    pub portal_url: PortalUrl,
    pub approved_at: Option<u64>,
}

pub fn known_gateways(config: &ConfigFile, linked: &[LinkedGateway]) -> Vec<KnownGateway> {
    let mut known: Vec<KnownGateway> = config
        .gateways
        .iter()
        .map(|(name, section)| KnownGateway {
            name: name.clone(),
            host: section.host.clone(),
            port: section.port.map(NonZeroU16::get),
            portal_url: section.portal_url.clone(),
            source: Source::Config,
        })
        .collect();
    for gateway in linked {
        if !known.iter().any(|known| known.name == gateway.name) {
            known.push(KnownGateway {
                name: gateway.name.clone(),
                host: Some(gateway.address.host()),
                port: Some(gateway.address.port()),
                portal_url: Some(gateway.portal_url.clone()),
                source: Source::Linked,
            });
        }
    }
    known
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Known {
    pub gateways: Vec<KnownGateway>,
    pub invalid: Vec<store::InvalidEntry>,
    pub unavailable: Option<String>,
}

impl Known {
    pub fn new(config: &ConfigFile, loaded: Result<store::Loaded, store::StoreError>) -> Self {
        match loaded {
            Ok(loaded) => Self {
                gateways: known_gateways(config, &loaded.gateways),
                invalid: loaded.invalid,
                unavailable: None,
            },
            Err(error) => Self {
                gateways: known_gateways(config, &[]),
                invalid: Vec::new(),
                unavailable: Some(error.to_string()),
            },
        }
    }

    pub fn error_lines(&self) -> Vec<String> {
        let mut lines: Vec<String> = self
            .unavailable
            .iter()
            .map(|error| format!("linked-gateways: error: {error}"))
            .collect();
        lines.extend(
            self.invalid
                .iter()
                .map(|entry| format!("linked-gateway: error: {entry}")),
        );
        lines
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirmation {
    pub profile: GatewayName,
    pub gateway: GatewayAddress,
    pub portal: PortalUrl,
}

impl Confirmation {
    pub fn portal_origin(&self) -> String {
        Origin::of(&self.portal).map_or_else(String::new, |origin| origin.to_string())
    }

    pub fn echo(&self) -> Vec<String> {
        vec![
            format!("gateway: {}", self.profile),
            format!("address: {}", self.gateway),
            format!("portal: {}", self.portal_origin()),
        ]
    }

    pub fn echoed_by(&self, lines: &[String]) -> bool {
        let echoed: Vec<&String> = lines
            .iter()
            .filter(|line| {
                !line.starts_with(crate::ipc::CONFIRM)
                    && !line.starts_with("linked-gateway: error: ")
                    && !line.starts_with("linked-gateways: error: ")
            })
            .collect();
        echoed.into_iter().eq(self.echo().iter())
    }

    pub fn message(&self) -> String {
        let local = if self.gateway.is_local() {
            "\nThis address is on your computer or local network."
        } else {
            ""
        };
        format!(
            "A website asks to add the gateway \"{}\" to Gateinto and to open a browser \
             session through it.\n\n\
             Gateway: {}{local}\n\
             Portal: {}\n\n\
             The gateway will see this device's identity (its client certificate, if one is \
             installed) and all traffic of the isolated browser. Allow it only if you trust \
             the organisation that runs this gateway.",
            self.profile,
            self.gateway,
            self.portal_origin()
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Approve,
    Deny,
    Defer,
}

pub trait Confirm {
    fn decide(&mut self, confirmation: &Confirmation) -> Decision;
}

impl Confirm for Decision {
    fn decide(&mut self, _: &Confirmation) -> Decision {
        *self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    pub profile: GatewayName,
    pub start_page: Option<PortalUrl>,
    pub add: Option<LinkedGateway>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    Launch(Launch),
    Confirm(Confirmation),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    UnknownProfile(GatewayName),
    GatewayMismatch(GatewayName),
    UrlWithoutPortal(GatewayName),
    UrlOutsidePortal(GatewayName),
    KnownGateway {
        profile: GatewayName,
        existing: GatewayName,
    },
    Denied(GatewayName),
    LookAlikeProfile {
        profile: GatewayName,
        existing: GatewayName,
    },
    Damaged {
        profile: GatewayName,
        file: String,
    },
    StoreUnavailable(String),
    Unstorable {
        profile: GatewayName,
        reason: String,
    },
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownProfile(name) => write!(
                f,
                "unknown gateway \"{name}\": it is not set up on this device and the link does \
                 not bring one; the portal must provide the gateway and its portal in the link, \
                 or an administrator must add [gateways.{name}] to the config file"
            ),
            Self::GatewayMismatch(name) => write!(
                f,
                "the link's gateway or portal differs from the gateway \"{name}\" set up on this \
                 device; the link was refused and \"{name}\" was not changed"
            ),
            Self::UrlWithoutPortal(name) => write!(
                f,
                "the link asks for a start page, but the gateway \"{name}\" has no portal_url; \
                 a start page is accepted only on the origin of the gateway's portal"
            ),
            Self::UrlOutsidePortal(name) => write!(
                f,
                "the link's start page is not on the origin (https, host and port) of the \
                 portal of the gateway \"{name}\""
            ),
            Self::KnownGateway { profile, existing } => write!(
                f,
                "the link names the gateway \"{profile}\", but its address is already set up as \
                 \"{existing}\"; use profile={existing} in the link"
            ),
            Self::LookAlikeProfile { profile, existing } => write!(
                f,
                "the link names the gateway \"{profile}\", which differs only in letter case \
                 from the gateway \"{existing}\" set up on this device; use \
                 profile={existing} in the link"
            ),
            Self::Damaged { profile, file } => write!(
                f,
                "the gateway \"{profile}\" is held by the damaged file {file}; fix or delete \
                 it (`gateinto gateway list` shows why); nothing was changed"
            ),
            Self::StoreUnavailable(error) => write!(
                f,
                "the gateways added from links cannot be read: {error}; only gateways of the \
                 config file can be used until this is fixed"
            ),
            Self::Unstorable { profile, reason } => {
                write!(f, "the gateway \"{profile}\" cannot be added: {reason}")
            }
            Self::Denied(name) => write!(
                f,
                "adding the gateway \"{name}\" was not allowed; nothing was stored"
            ),
        }
    }
}

impl std::error::Error for LinkError {}

fn same_origin(url: &PortalUrl, portal: &PortalUrl) -> bool {
    Origin::of(url).is_some_and(|origin| Some(origin) == Origin::of(portal))
}

pub fn resolve(
    link: &LaunchRequest,
    all: &Known,
    confirm: &mut dyn Confirm,
    now: u64,
) -> Result<Resolution, LinkError> {
    let profile = &link.profile;
    let known = all.gateways.as_slice();
    let damaged = |entry: &store::InvalidEntry| LinkError::Damaged {
        profile: profile.clone(),
        file: entry.file.display().to_string(),
    };
    if let Some(local) = known.iter().find(|known| &known.name == profile) {
        if let Some(gateway) = &link.gateway {
            let matches = local.is_at(gateway) && link.portal == local.portal_url;
            if !matches {
                return Err(LinkError::GatewayMismatch(profile.clone()));
            }
        }
        let start_page = match (&link.url, &local.portal_url) {
            (None, portal) => portal.clone(),
            (Some(_), None) => return Err(LinkError::UrlWithoutPortal(profile.clone())),
            (Some(url), Some(portal)) if same_origin(url, portal) => Some(url.clone()),
            (Some(_), Some(_)) => return Err(LinkError::UrlOutsidePortal(profile.clone())),
        };
        return Ok(Resolution::Launch(Launch {
            profile: profile.clone(),
            start_page,
            add: None,
        }));
    }
    if let Some(entry) = all
        .invalid
        .iter()
        .find(|entry| entry.name.as_ref() == Some(profile))
    {
        return Err(damaged(entry));
    }
    if let Some(similar) = known
        .iter()
        .find(|known| known.name.as_str().eq_ignore_ascii_case(profile.as_str()))
    {
        return Err(LinkError::LookAlikeProfile {
            profile: profile.clone(),
            existing: similar.name.clone(),
        });
    }
    if let Some(error) = &all.unavailable {
        return Err(LinkError::StoreUnavailable(error.clone()));
    }
    let (Some(gateway), Some(portal)) = (&link.gateway, &link.portal) else {
        return Err(LinkError::UnknownProfile(profile.clone()));
    };
    if let Some(entry) = all.invalid.iter().find(|entry| {
        entry
            .addresses
            .iter()
            .any(|address| address.matches(&gateway.host(), gateway.port()))
    }) {
        return Err(damaged(entry));
    }
    if let Some(existing) = known.iter().find(|known| known.is_at(gateway)) {
        return Err(LinkError::KnownGateway {
            profile: profile.clone(),
            existing: existing.name.clone(),
        });
    }
    if link
        .url
        .as_ref()
        .is_some_and(|url| !same_origin(url, portal))
    {
        return Err(LinkError::UrlOutsidePortal(profile.clone()));
    }
    if let Err(error) = store::file_name(gateway) {
        return Err(LinkError::Unstorable {
            profile: profile.clone(),
            reason: error.to_string(),
        });
    }
    let confirmation = Confirmation {
        profile: profile.clone(),
        gateway: gateway.clone(),
        portal: portal.clone(),
    };
    match confirm.decide(&confirmation) {
        Decision::Defer => Ok(Resolution::Confirm(confirmation)),
        Decision::Deny => Err(LinkError::Denied(profile.clone())),
        Decision::Approve => Ok(Resolution::Launch(Launch {
            profile: profile.clone(),
            start_page: Some(link.url.clone().unwrap_or_else(|| portal.clone())),
            add: Some(LinkedGateway {
                name: profile.clone(),
                address: gateway.clone(),
                portal_url: portal.clone(),
                approved_at: Some(now),
            }),
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PORTAL: &str = "https://portal.corp.example/";
    const NOW: u64 = 1_760_000_000;

    fn name(text: &str) -> GatewayName {
        text.parse().unwrap()
    }

    fn known(
        text: &str,
        host: &str,
        port: u16,
        portal: Option<&str>,
        source: Source,
    ) -> KnownGateway {
        KnownGateway {
            name: name(text),
            host: Some(host.to_owned()),
            port: Some(port),
            portal_url: portal.map(|portal| portal.parse().unwrap()),
            source,
        }
    }

    fn profiles() -> Vec<KnownGateway> {
        vec![
            known(
                "corp",
                "proxy.corp.example",
                443,
                Some(PORTAL),
                Source::Config,
            ),
            known("bare", "bare.example", 8443, None, Source::Config),
            known(
                "partner",
                "10.0.0.1",
                3128,
                Some("https://partner.example:8443/x"),
                Source::Linked,
            ),
            KnownGateway {
                name: name("incomplete"),
                host: None,
                port: None,
                portal_url: None,
                source: Source::Config,
            },
        ]
    }

    fn link(
        profile: &str,
        url: Option<&str>,
        gateway: Option<&str>,
        portal: Option<&str>,
    ) -> LaunchRequest {
        LaunchRequest::new(profile, "basic_tofu")
            .unwrap()
            .with_link(url, gateway, portal)
            .unwrap()
    }

    #[derive(Default)]
    struct Recorder {
        decision: Option<Decision>,
        asked: Vec<Confirmation>,
    }

    impl Confirm for Recorder {
        fn decide(&mut self, confirmation: &Confirmation) -> Decision {
            self.asked.push(confirmation.clone());
            self.decision.expect("no confirmation was expected")
        }
    }

    fn resolve_with(
        link: &LaunchRequest,
        decision: Option<Decision>,
    ) -> (Result<Resolution, LinkError>, Vec<Confirmation>) {
        let mut confirm = Recorder {
            decision,
            asked: Vec::new(),
        };
        let known = Known {
            gateways: profiles(),
            ..Known::default()
        };
        let resolution = resolve(link, &known, &mut confirm, NOW);
        (resolution, confirm.asked)
    }

    fn damaged() -> Known {
        Known {
            gateways: profiles(),
            invalid: vec![store::InvalidEntry {
                file: std::path::PathBuf::from("/c/gateways/held.example.toml"),
                name: Some(name("held")),
                addresses: vec!["held.example".parse().unwrap()],
                reason: "broken".to_owned(),
            }],
            unavailable: None,
        }
    }

    fn resolve_in(known: &Known, link: &LaunchRequest) -> (Result<Resolution, LinkError>, usize) {
        let mut confirm = Recorder {
            decision: Some(Decision::Approve),
            asked: Vec::new(),
        };
        let resolution = resolve(link, known, &mut confirm, NOW);
        (resolution, confirm.asked.len())
    }

    #[test]
    fn a_link_to_a_gateway_held_by_an_invalid_file_fails_closed() {
        let held = || LinkError::Damaged {
            profile: name("held"),
            file: "/c/gateways/held.example.toml".to_owned(),
        };
        for (request, expected) in [
            (link("held", None, None, None), held()),
            (
                link(
                    "held",
                    None,
                    Some("new.example"),
                    Some("https://new.example/"),
                ),
                held(),
            ),
            (
                link(
                    "newco",
                    None,
                    Some("Held.Example:443"),
                    Some("https://new.example/"),
                ),
                LinkError::Damaged {
                    profile: name("newco"),
                    file: "/c/gateways/held.example.toml".to_owned(),
                },
            ),
        ] {
            let (resolution, asked) = resolve_in(&damaged(), &request);
            assert_eq!(resolution, Err(expected), "{request}");
            assert_eq!(asked, 0);
        }
        let error = resolve_in(&damaged(), &link("held", None, None, None))
            .0
            .unwrap_err();
        assert!(error.to_string().contains("held.example.toml"), "{error}");
        let (resolution, _) = resolve_in(&damaged(), &link("corp", None, None, None));
        assert_eq!(resolution, Ok(launch("corp", Some(PORTAL))));
        let (resolution, asked) = resolve_in(
            &damaged(),
            &link(
                "newco",
                None,
                Some("other.example"),
                Some("https://new.example/"),
            ),
        );
        assert!(
            matches!(resolution, Ok(Resolution::Launch(_))),
            "{resolution:?}"
        );
        assert_eq!(asked, 1);
    }

    #[test]
    fn without_a_usable_store_only_known_gateways_launch() {
        let known = Known {
            gateways: profiles(),
            invalid: Vec::new(),
            unavailable: Some("not a directory".to_owned()),
        };
        let (resolution, _) = resolve_in(&known, &link("corp", None, None, None));
        assert_eq!(resolution, Ok(launch("corp", Some(PORTAL))));
        for request in [
            link("nope", None, None, None),
            link(
                "newco",
                None,
                Some("new.example"),
                Some("https://new.example/"),
            ),
        ] {
            let (resolution, asked) = resolve_in(&known, &request);
            let error = resolution.unwrap_err();
            assert!(matches!(error, LinkError::StoreUnavailable(_)), "{error}");
            assert!(error.to_string().contains("not a directory"), "{error}");
            assert_eq!(asked, 0);
        }
    }

    #[test]
    fn a_gateway_whose_file_name_would_be_too_long_is_refused_before_asking() {
        let host = format!("{}example", "a.".repeat(123));
        let (resolution, asked) = resolve_with(
            &link("newco", None, Some(&host), Some("https://new.example/")),
            Some(Decision::Approve),
        );
        let error = resolution.unwrap_err();
        assert!(matches!(error, LinkError::Unstorable { .. }), "{error}");
        assert!(error.to_string().contains("too long"), "{error}");
        assert!(asked.is_empty());
    }

    #[test]
    fn known_gateways_carry_the_invalid_files_and_store_errors() {
        let config = config_file("[gateways.corp]\nhost = \"proxy.corp.example\"\nport = 443\n");
        let invalid = damaged().invalid;
        let loaded = store::Loaded {
            gateways: vec![linked("newco", "new.example")],
            invalid: invalid.clone(),
        };
        let known = Known::new(&config, Ok(loaded));
        assert_eq!(known.gateways.len(), 2);
        assert_eq!(known.invalid, invalid);
        assert_eq!(known.unavailable, None);
        let known = Known::new(
            &config,
            Err(store::StoreError::NotADirectory("/c/gateways".into())),
        );
        assert_eq!(known.gateways.len(), 1);
        assert!(known.unavailable.unwrap().contains("not a directory"));
    }

    fn launch(profile: &str, start: Option<&str>) -> Resolution {
        Resolution::Launch(Launch {
            profile: name(profile),
            start_page: start.map(|url| url.parse().unwrap()),
            add: None,
        })
    }

    #[test]
    fn a_known_profile_opens_its_portal_or_a_blank_page_without_asking() {
        for (profile, start) in [
            ("corp", Some(PORTAL)),
            ("bare", None),
            ("partner", Some("https://partner.example:8443/x")),
        ] {
            let (resolution, asked) = resolve_with(&link(profile, None, None, None), None);
            assert_eq!(resolution, Ok(launch(profile, start)), "{profile}");
            assert!(asked.is_empty());
        }
    }

    #[test]
    fn a_start_page_on_the_portal_origin_replaces_the_portal_for_this_launch() {
        for (profile, url) in [
            ("corp", "https://portal.corp.example/app?x=1"),
            ("corp", "https://PORTAL.corp.example:443/"),
            ("partner", "https://partner.example:8443/other"),
        ] {
            let (resolution, _) = resolve_with(&link(profile, Some(url), None, None), None);
            assert_eq!(resolution, Ok(launch(profile, Some(url))), "{url}");
        }
    }

    #[test]
    fn a_start_page_off_the_portal_origin_or_without_a_portal_is_refused() {
        for (profile, url, expected) in [
            (
                "corp",
                "https://evil.example/",
                LinkError::UrlOutsidePortal(name("corp")),
            ),
            (
                "corp",
                "https://portal.corp.example:8443/",
                LinkError::UrlOutsidePortal(name("corp")),
            ),
            (
                "corp",
                "https://sub.portal.corp.example/",
                LinkError::UrlOutsidePortal(name("corp")),
            ),
            (
                "partner",
                "https://partner.example/x",
                LinkError::UrlOutsidePortal(name("partner")),
            ),
            (
                "bare",
                "https://bare.example/",
                LinkError::UrlWithoutPortal(name("bare")),
            ),
            (
                "incomplete",
                "https://x.example/",
                LinkError::UrlWithoutPortal(name("incomplete")),
            ),
        ] {
            let (resolution, asked) = resolve_with(&link(profile, Some(url), None, None), None);
            assert_eq!(resolution, Err(expected), "{profile} {url}");
            assert!(asked.is_empty());
        }
    }

    #[test]
    fn a_link_that_repeats_the_local_gateway_and_portal_is_accepted() {
        for (gateway, portal) in [
            ("proxy.corp.example", PORTAL),
            ("PROXY.corp.example:443", PORTAL),
        ] {
            let (resolution, asked) = resolve_with(
                &link(
                    "corp",
                    Some("https://portal.corp.example/app"),
                    Some(gateway),
                    Some(portal),
                ),
                None,
            );
            assert_eq!(
                resolution,
                Ok(launch("corp", Some("https://portal.corp.example/app")))
            );
            assert!(asked.is_empty());
        }
        let (resolution, _) = resolve_with(
            &link(
                "partner",
                None,
                Some("10.0.0.1:3128"),
                Some("https://partner.example:8443/x"),
            ),
            None,
        );
        assert_eq!(
            resolution,
            Ok(launch("partner", Some("https://partner.example:8443/x")))
        );
    }

    #[test]
    fn a_link_that_disagrees_with_a_local_profile_is_refused_without_asking() {
        for (profile, gateway, portal) in [
            ("corp", "evil.example", PORTAL),
            ("corp", "proxy.corp.example:8443", PORTAL),
            (
                "corp",
                "proxy.corp.example",
                "https://portal.corp.example/other",
            ),
            ("corp", "proxy.corp.example", "https://portal.corp.example"),
            ("bare", "bare.example:8443", "https://bare.example/"),
            ("incomplete", "x.example", "https://x.example/"),
            ("partner", "10.0.0.2:3128", "https://partner.example:8443/x"),
        ] {
            let (resolution, asked) =
                resolve_with(&link(profile, None, Some(gateway), Some(portal)), None);
            assert_eq!(
                resolution,
                Err(LinkError::GatewayMismatch(name(profile))),
                "{profile} {gateway} {portal}"
            );
            assert!(asked.is_empty());
        }
    }

    #[test]
    fn an_unknown_profile_without_a_gateway_is_refused_with_advice() {
        let (resolution, asked) = resolve_with(&link("nope", None, None, None), None);
        let error = resolution.unwrap_err();
        assert_eq!(error, LinkError::UnknownProfile(name("nope")));
        assert!(asked.is_empty());
        let text = error.to_string();
        assert!(text.contains("unknown gateway \"nope\""), "{text}");
        assert!(text.contains("portal"), "{text}");
        assert!(text.contains("administrator"), "{text}");
    }

    fn new_link(url: Option<&str>) -> LaunchRequest {
        link(
            "newco",
            url,
            Some("Proxy.Newco.Example"),
            Some("https://portal.newco.example/home"),
        )
    }

    fn confirmation() -> Confirmation {
        Confirmation {
            profile: name("newco"),
            gateway: "proxy.newco.example:443".parse().unwrap(),
            portal: "https://portal.newco.example/home".parse().unwrap(),
        }
    }

    #[test]
    fn a_new_gateway_needs_a_decision_naming_it() {
        let (resolution, asked) = resolve_with(&new_link(None), Some(Decision::Defer));
        assert_eq!(resolution, Ok(Resolution::Confirm(confirmation())));
        assert_eq!(asked, vec![confirmation()]);
    }

    #[test]
    fn an_approved_gateway_is_added_and_opens_the_link_or_its_portal() {
        for (url, start) in [
            (None, "https://portal.newco.example/home"),
            (
                Some("https://portal.newco.example/app"),
                "https://portal.newco.example/app",
            ),
        ] {
            let (resolution, asked) = resolve_with(&new_link(url), Some(Decision::Approve));
            assert_eq!(asked.len(), 1);
            assert_eq!(
                resolution,
                Ok(Resolution::Launch(Launch {
                    profile: name("newco"),
                    start_page: Some(start.parse().unwrap()),
                    add: Some(LinkedGateway {
                        name: name("newco"),
                        address: "proxy.newco.example:443".parse().unwrap(),
                        portal_url: "https://portal.newco.example/home".parse().unwrap(),
                        approved_at: Some(NOW),
                    }),
                }))
            );
        }
    }

    #[test]
    fn a_denied_gateway_is_refused() {
        let (resolution, asked) = resolve_with(&new_link(None), Some(Decision::Deny));
        assert_eq!(resolution, Err(LinkError::Denied(name("newco"))));
        assert_eq!(asked.len(), 1);
    }

    #[test]
    fn a_new_name_for_a_known_gateway_is_refused_with_the_existing_name() {
        for (gateway, existing) in [
            ("proxy.corp.example:443", "corp"),
            ("10.0.0.1:3128", "partner"),
            ("[::ffff:10.0.0.1]:3128", "partner"),
        ] {
            let (resolution, asked) = resolve_with(
                &link("other", None, Some(gateway), Some("https://other.example/")),
                Some(Decision::Approve),
            );
            assert_eq!(
                resolution,
                Err(LinkError::KnownGateway {
                    profile: name("other"),
                    existing: name(existing)
                })
            );
            assert!(asked.is_empty());
        }
    }

    #[test]
    fn a_profile_that_differs_from_a_known_one_only_by_case_is_refused() {
        for (profile, gateway, existing) in [
            ("Corp", None, "corp"),
            ("CORP", Some("other.example"), "corp"),
            ("Partner", Some("10.0.0.9"), "partner"),
        ] {
            let portal = gateway.map(|_| "https://other.example/");
            let (resolution, asked) = resolve_with(
                &link(profile, None, gateway, portal),
                Some(Decision::Approve),
            );
            let error = resolution.unwrap_err();
            assert_eq!(
                error,
                LinkError::LookAlikeProfile {
                    profile: name(profile),
                    existing: name(existing)
                }
            );
            assert!(asked.is_empty());
            let text = error.to_string();
            assert!(text.contains(&format!("\"{existing}\"")), "{text}");
            assert!(text.contains("case"), "{text}");
        }
    }

    #[test]
    fn the_agent_echo_must_name_the_same_gateway_as_the_link() {
        let echo = confirmation().echo();
        assert_eq!(
            echo,
            vec![
                "gateway: newco",
                "address: proxy.newco.example:443",
                "portal: https://portal.newco.example",
            ]
        );
        let token = "confirm: 0123456789abcdef0123456789abcdef".to_owned();
        let with_token = |lines: &[&str]| {
            std::iter::once(token.clone())
                .chain(lines.iter().map(|line| (*line).to_owned()))
                .collect::<Vec<_>>()
        };
        assert!(confirmation().echoed_by(&with_token(&[
            "gateway: newco",
            "address: proxy.newco.example:443",
            "portal: https://portal.newco.example",
        ])));
        for lines in [
            vec![
                "gateway: newco",
                "address: evil.example:443",
                "portal: https://portal.newco.example",
            ],
            vec![
                "gateway: other",
                "address: proxy.newco.example:443",
                "portal: https://portal.newco.example",
            ],
            vec![
                "gateway: newco",
                "address: proxy.newco.example:443",
                "portal: https://evil.example",
            ],
            vec!["gateway: newco", "address: proxy.newco.example:443"],
            vec![
                "gateway: newco",
                "address: proxy.newco.example:443",
                "portal: https://portal.newco.example",
                "extra: x",
            ],
        ] {
            assert!(!confirmation().echoed_by(&with_token(&lines)), "{lines:?}");
        }
    }

    #[test]
    fn the_confirmation_warns_about_local_and_private_addresses() {
        const LOCAL: &str = "This address is on your computer or local network.";
        let with = |gateway: &str| {
            Confirmation {
                gateway: gateway.parse().unwrap(),
                ..confirmation()
            }
            .message()
        };
        for gateway in [
            "127.0.0.1",
            "127.8.9.1:8443",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
            "169.254.1.1",
            "0.0.0.0",
            "[::1]",
            "[::]",
            "[fe80::1]",
            "[fd12:3456::1]",
            "[fc00::1]",
            "[::ffff:192.168.1.1]",
            "[::ffff:127.0.0.1]",
            "localhost",
            "app.localhost",
            "100.64.0.1",
            "100.127.255.254",
            "0.1.2.3",
            "0.255.255.255",
            "255.255.255.255",
            "[64:ff9b::7f00:1]",
            "[64:ff9b::192.168.1.1]",
            "[64:ff9b::a00:1]",
            "[64:ff9b::100.64.0.1]",
        ] {
            assert!(with(gateway).contains(LOCAL), "{gateway}");
        }
        for gateway in [
            "proxy.example",
            "8.8.8.8",
            "172.32.0.1",
            "[2001:db8::1]",
            "[::ffff:8.8.8.8]",
            "localhost.example",
            "100.63.255.255",
            "100.128.0.1",
            "1.0.0.1",
            "255.255.255.254",
            "[64:ff9b::808:808]",
            "[64:ff9b:1::7f00:1]",
        ] {
            assert!(!with(gateway).contains(LOCAL), "{gateway}");
        }
    }

    #[test]
    fn a_new_gateway_with_a_start_page_off_its_portal_is_refused_before_asking() {
        let mut request = new_link(None);
        request.url = Some("https://evil.example/".parse().unwrap());
        let (resolution, asked) = resolve_with(&request, Some(Decision::Approve));
        assert_eq!(resolution, Err(LinkError::UrlOutsidePortal(name("newco"))));
        assert!(asked.is_empty());
    }

    #[test]
    fn every_resolved_start_page_shares_the_portal_origin() {
        let urls = [
            None,
            Some("https://portal.corp.example/a"),
            Some("https://evil.example/"),
            Some("https://partner.example:8443/b"),
        ];
        for profile in ["corp", "bare", "partner", "incomplete", "nope"] {
            for url in urls {
                let (resolution, _) =
                    resolve_with(&link(profile, url, None, None), Some(Decision::Approve));
                if let Ok(Resolution::Launch(launch)) = resolution
                    && let Some(url) = url
                {
                    let portal = profiles()
                        .into_iter()
                        .find(|p| p.name == launch.profile)
                        .unwrap()
                        .portal_url
                        .unwrap();
                    assert_eq!(Origin::of(&url.parse().unwrap()), Origin::of(&portal));
                }
            }
        }
    }

    #[test]
    fn the_confirmation_names_the_profile_gateway_and_portal_origin_and_warns() {
        let text = confirmation().message();
        for expected in [
            "\"newco\"",
            "proxy.newco.example:443",
            "https://portal.newco.example",
            "identity",
            "traffic",
            "trust",
        ] {
            assert!(text.contains(expected), "{expected}: {text}");
        }
        assert!(!text.contains("/home"), "{text}");
    }

    fn config_file(text: &str) -> ConfigFile {
        ConfigFile::parse(text).unwrap()
    }

    fn linked(text: &str, host: &str) -> LinkedGateway {
        LinkedGateway {
            name: name(text),
            address: host.parse().unwrap(),
            portal_url: format!("https://{text}.example/").parse().unwrap(),
            approved_at: None,
        }
    }

    #[test]
    fn known_gateways_list_the_config_first_and_hide_shadowed_links() {
        let config = config_file(
            "[gateways.corp]\nhost = \"proxy.corp.example\"\nport = 443\n[gateways.empty]\n",
        );
        let known = known_gateways(
            &config,
            &[
                linked("corp", "evil.example"),
                linked("newco", "[::1]:8443"),
            ],
        );
        assert_eq!(
            known,
            vec![
                KnownGateway {
                    name: name("corp"),
                    host: Some("proxy.corp.example".to_owned()),
                    port: Some(443),
                    portal_url: None,
                    source: Source::Config,
                },
                KnownGateway {
                    name: name("empty"),
                    host: None,
                    port: None,
                    portal_url: None,
                    source: Source::Config,
                },
                KnownGateway {
                    name: name("newco"),
                    host: Some("::1".to_owned()),
                    port: Some(8443),
                    portal_url: Some("https://newco.example/".parse().unwrap()),
                    source: Source::Linked,
                },
            ]
        );
    }

    #[test]
    fn a_linked_gateway_gets_the_settings_of_a_minimal_config_gateway() {
        let base = "[limits]\nconnect_timeout_seconds = 7\n[gateways.corp]\nhost = \"proxy.corp.example\"\nport = 443\nca_file = \"/etc/corp.pem\"\n";
        let gateway = linked("newco", "proxy.newco.example:8443");
        let merged =
            config_file(base).with_linked(&[gateway.clone(), linked("corp", "evil.example")]);
        let expected = config_file(&format!(
            "{base}[gateways.newco]\nhost = \"proxy.newco.example\"\nport = 8443\nportal_url = \"https://newco.example/\"\n"
        ));
        for profile in ["newco", "corp"] {
            let overrides = crate::config::Overrides {
                gateway: Some(name(profile)),
                ..Default::default()
            };
            assert_eq!(
                merged.settings(&overrides).unwrap(),
                expected.settings(&overrides).unwrap(),
                "{profile}"
            );
        }
        let settings = merged
            .settings(&crate::config::Overrides {
                gateway: Some(name("newco")),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(settings.gateway.upstream.ca_file, None);
        assert_eq!(settings.gateway.upstream.server_name, "proxy.newco.example");
        assert_eq!(settings.gateway.client_cert_file, None);
        assert!(!settings.gateway.self_signed_client_cert);
        assert_eq!(settings.gateway.tls_mode, crate::tls::TlsMode::default());
        assert_eq!(
            settings.gateway.client_certificate,
            crate::identity::client_cert::ClientCertificateMode::default()
        );
    }

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
    fn windows_device_names_are_refused_as_gateway_hosts() {
        let mut reserved = vec![
            "con",
            "CON.example",
            "Nul.example",
            "aux",
            "prn.corp.example",
        ];
        let numbered: Vec<String> = (0..10)
            .flat_map(|n| [format!("com{n}.example"), format!("LPT{n}")])
            .collect();
        reserved.extend(numbered.iter().map(String::as_str));
        for host in reserved {
            assert_eq!(
                host.parse::<GatewayAddress>(),
                Err(InvalidGatewayAddress::Reserved),
                "{host}"
            );
        }
        for host in [
            "console.example",
            "com10.example",
            "lpt.example",
            "a.con",
            "nul-1.example",
        ] {
            assert!(host.parse::<GatewayAddress>().is_ok(), "{host}");
        }
    }

    #[test]
    fn names_that_read_as_ipv6_with_dashes_are_refused() {
        for host in ["fe80--1", "a-b-c-d-e-f-1-2", "abcd--ef", "fe80--1:8443"] {
            assert_eq!(
                host.parse::<GatewayAddress>(),
                Err(InvalidGatewayAddress::Syntax),
                "{host}"
            );
        }
        for host in ["proxy-a.example", "a-b", "face-b00c.example"] {
            assert!(host.parse::<GatewayAddress>().is_ok(), "{host}");
        }
    }

    #[test]
    fn ipv4_mapped_gateways_are_stored_as_ipv4() {
        let address: GatewayAddress = "[::ffff:10.0.0.1]:3128".parse().unwrap();
        assert_eq!(address.to_string(), "10.0.0.1:3128");
        assert_eq!(address.host(), "10.0.0.1");
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

    #[test]
    fn ipv4_mapped_ipv6_addresses_match_their_ipv4_address() {
        let mapped: GatewayAddress = "[::ffff:10.0.0.1]:3128".parse().unwrap();
        assert!(mapped.matches("10.0.0.1", 3128));
        assert!(mapped.matches("::ffff:10.0.0.1", 3128));
        assert!(!mapped.matches("10.0.0.2", 3128));
        let plain: GatewayAddress = "10.0.0.1:3128".parse().unwrap();
        assert!(plain.matches("::ffff:10.0.0.1", 3128));
        assert!(plain.matches("::ffff:a00:1", 3128));
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
