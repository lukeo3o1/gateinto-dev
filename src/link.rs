use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::Deserialize;

use crate::config::{self, ConfigFile, GatewayName, PortalUrl};
use crate::http::{self, Authority, Host};
use crate::ipc::ConfirmToken;
use crate::uri::LaunchRequest;

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

    pub fn message(&self) -> String {
        format!(
            "A website asks to add the gateway \"{}\" to Gateinto and to open a browser \
             session through it.\n\n\
             Gateway: {}\n\
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
    known: &[KnownGateway],
    confirm: &mut dyn Confirm,
    now: u64,
) -> Result<Resolution, LinkError> {
    let profile = &link.profile;
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
    let (Some(gateway), Some(portal)) = (&link.gateway, &link.portal) else {
        return Err(LinkError::UnknownProfile(profile.clone()));
    };
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

pub const STORE_FILE: &str = "linked-gateways.toml";
pub const MAX_LINKED: usize = 32;
const MAX_STORE_BYTES: u64 = 256 * 1024;

pub fn default_store_path() -> Option<PathBuf> {
    Some(config::default_path()?.with_file_name(STORE_FILE))
}

#[derive(Debug)]
pub enum StoreError {
    Io(PathBuf, io::Error),
    Invalid(PathBuf, String),
    Exists(GatewayName),
    Full,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(path, error) => write!(f, "linked gateways {}: {error}", path.display()),
            Self::Invalid(path, error) => {
                write!(f, "linked gateways {}: {error}", path.display())
            }
            Self::Exists(name) => write!(f, "a linked gateway \"{name}\" already exists"),
            Self::Full => write!(
                f,
                "{MAX_LINKED} linked gateways are stored already; remove one with \
                 `gateinto gateway forget <name>`"
            ),
        }
    }
}

impl std::error::Error for StoreError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreFile {
    #[serde(default)]
    gateways: BTreeMap<GatewayName, StoreEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreEntry {
    host: String,
    port: NonZeroU16,
    portal_url: PortalUrl,
    approved_at: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct LinkedStore {
    path: PathBuf,
}

impl LinkedStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn invalid(&self, error: impl fmt::Display) -> StoreError {
        StoreError::Invalid(self.path.clone(), error.to_string())
    }

    pub fn load(&self) -> Result<Vec<LinkedGateway>, StoreError> {
        let io = |error| StoreError::Io(self.path.clone(), error);
        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(io(error)),
        };
        let mut text = String::new();
        file.take(MAX_STORE_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(io)?;
        if text.len() as u64 > MAX_STORE_BYTES {
            return Err(self.invalid(format!("larger than {MAX_STORE_BYTES} bytes")));
        }
        let file: StoreFile = toml::from_str(&text)
            .map_err(|error| self.invalid(error.to_string().trim_end().replace('\n', " ")))?;
        file.gateways
            .into_iter()
            .map(|(name, entry)| {
                let address = if entry.host.contains(':') {
                    format!("[{}]:{}", entry.host, entry.port)
                } else {
                    format!("{}:{}", entry.host, entry.port)
                };
                let address: GatewayAddress = address
                    .parse()
                    .map_err(|error| self.invalid(format!("gateway \"{name}\": {error}")))?;
                if Origin::of(&entry.portal_url).is_none() {
                    return Err(self.invalid(format!(
                        "gateway \"{name}\": portal_url has no https origin"
                    )));
                }
                Ok(LinkedGateway {
                    name,
                    address,
                    portal_url: entry.portal_url,
                    approved_at: entry.approved_at,
                })
            })
            .collect()
    }

    pub fn add(&self, gateway: &LinkedGateway) -> Result<(), StoreError> {
        let mut gateways = self.load()?;
        if gateways.iter().any(|known| known.name == gateway.name) {
            return Err(StoreError::Exists(gateway.name.clone()));
        }
        if gateways.len() >= MAX_LINKED {
            return Err(StoreError::Full);
        }
        gateways.push(gateway.clone());
        gateways.sort_by(|a, b| a.name.cmp(&b.name));
        self.save(&gateways)
    }

    pub fn forget(&self, name: &GatewayName) -> Result<bool, StoreError> {
        let mut gateways = self.load()?;
        let before = gateways.len();
        gateways.retain(|gateway| &gateway.name != name);
        if gateways.len() == before {
            return Ok(false);
        }
        self.save(&gateways)?;
        Ok(true)
    }

    fn save(&self, gateways: &[LinkedGateway]) -> Result<(), StoreError> {
        let io = |error| StoreError::Io(self.path.clone(), error);
        let mut text = String::from(
            "# Gateways added from gateinto:// links after confirmation.\n\
             # Remove one with `gateinto gateway forget <name>`.\n",
        );
        for gateway in gateways {
            text.push_str(&format!(
                "\n[gateways.{}]\nhost = \"{}\"\nport = {}\nportal_url = \"{}\"\n",
                gateway.name,
                gateway.address.host(),
                gateway.address.port(),
                gateway.portal_url
            ));
            if let Some(approved_at) = gateway.approved_at {
                text.push_str(&format!("approved_at = {approved_at}\n"));
            }
        }
        let dir = self.path.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(dir).map_err(io)?;
        let temp = dir.join(format!(
            ".{STORE_FILE}.{}.{}.tmp",
            std::process::id(),
            ConfirmToken::random().map_err(io)?
        ));
        let written =
            write_new(&temp, text.as_bytes()).and_then(|()| std::fs::rename(&temp, &self.path));
        if written.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        written.map_err(io)
    }
}

fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
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
        let resolution = resolve(link, &profiles(), &mut confirm, NOW);
        (resolution, confirm.asked)
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

    fn store() -> LinkedStore {
        static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("gateinto-linked-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        LinkedStore::new(dir.join("sub").join(STORE_FILE))
    }

    #[test]
    fn a_missing_store_is_empty_and_adding_creates_it() {
        let store = store();
        assert_eq!(store.load().unwrap(), Vec::new());
        let mut gateway = linked("newco", "Proxy.Newco.Example:8443");
        gateway.approved_at = Some(NOW);
        store.add(&gateway).unwrap();
        store.add(&linked("other", "[2001:db8::1]")).unwrap();
        assert_eq!(
            store.load().unwrap(),
            vec![gateway.clone(), linked("other", "[2001:db8::1]")]
        );
        let text = std::fs::read_to_string(store.path()).unwrap();
        assert!(text.contains("[gateways.newco]\nhost = \"proxy.newco.example\"\nport = 8443\nportal_url = \"https://newco.example/\"\napproved_at = 1760000000\n"), "{text}");
        let leftovers: Vec<_> = std::fs::read_dir(store.path().parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(leftovers, vec![std::ffi::OsString::from(STORE_FILE)]);
    }

    #[test]
    fn adding_never_replaces_an_entry() {
        let store = store();
        store.add(&linked("newco", "a.example")).unwrap();
        let error = store.add(&linked("newco", "b.example")).unwrap_err();
        assert!(error.to_string().contains("\"newco\""), "{error}");
        assert_eq!(store.load().unwrap(), vec![linked("newco", "a.example")]);
    }

    #[test]
    fn the_store_holds_a_bounded_number_of_gateways() {
        let store = store();
        for n in 0..MAX_LINKED {
            store
                .add(&linked(&format!("g{n}"), &format!("g{n}.example")))
                .unwrap();
        }
        let error = store.add(&linked("more", "more.example")).unwrap_err();
        assert!(error.to_string().contains("gateway forget"), "{error}");
        assert_eq!(store.load().unwrap().len(), MAX_LINKED);
    }

    #[test]
    fn forgetting_removes_only_the_named_gateway() {
        let store = store();
        assert!(!store.forget(&name("newco")).unwrap());
        store.add(&linked("newco", "a.example")).unwrap();
        store.add(&linked("other", "b.example")).unwrap();
        assert!(store.forget(&name("newco")).unwrap());
        assert!(!store.forget(&name("newco")).unwrap());
        assert_eq!(store.load().unwrap(), vec![linked("other", "b.example")]);
    }

    #[test]
    fn a_store_with_anything_but_host_port_and_portal_is_rejected() {
        let store = store();
        std::fs::create_dir_all(store.path().parent().unwrap()).unwrap();
        for text in [
            "[gateways.a]\nhost = \"a.example\"\nport = 443\nportal_url = \"https://a.example/\"\nca_file = \"x.pem\"\n",
            "[gateways.a]\nhost = \"a.example\"\nport = 443\nportal_url = \"https://a.example/\"\ntls_mode = \"classical\"\n",
            "[gateways.a]\nhost = \"a.example\"\nport = 443\nportal_url = \"https://a.example/\"\nclient_cert_file = \"c.pem\"\n",
            "[gateways.a]\nhost = \"a.example\"\nport = 443\nportal_url = \"https://a.example/\"\n[device_session]\ngateway = \"a\"\n",
            "[gateways.a]\nhost = \"user@a.example\"\nport = 443\nportal_url = \"https://a.example/\"\n",
            "[gateways.a]\nhost = \"a.example\"\nport = 0\nportal_url = \"https://a.example/\"\n",
            "[gateways.a]\nhost = \"a.example\"\nport = 443\nportal_url = \"http://a.example/\"\n",
            "[gateways.a]\nhost = \"a.example\"\nport = 443\n",
            "[gateways.\"a b\"]\nhost = \"a.example\"\nport = 443\nportal_url = \"https://a.example/\"\n",
            "not toml",
        ] {
            std::fs::write(store.path(), text).unwrap();
            let error = store.load().unwrap_err().to_string();
            assert!(
                error.contains(&store.path().display().to_string()),
                "{text}: {error}"
            );
        }
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
