use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::io;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use rustls::pki_types::ServerName;
use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, Visitor};

use crate::http::DEFAULT_MAX_HEADER_BYTES;
use crate::identity::client_cert::ClientCertificateMode;
use crate::identity::device_key::{Backend, KeyName};
use crate::link::LinkedGateway;
use crate::tls::TlsMode;

pub const FILE_NAME: &str = "gateinto.toml";

pub fn default_path() -> Option<PathBuf> {
    default_path_from(|name| std::env::var_os(name))
}

pub fn default_path_from(env: impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    let absolute = |name| {
        env(name)
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
    };
    let dir = if cfg!(windows) {
        absolute("APPDATA").map(|dir| dir.join("Gateinto"))
    } else {
        absolute("XDG_CONFIG_HOME")
            .or_else(|| absolute("HOME").map(|home| home.join(".config")))
            .map(|dir| dir.join("gateinto"))
    };
    dir.map(|dir| dir.join(FILE_NAME))
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    #[serde(skip)]
    path: Option<PathBuf>,
    #[serde(
        default,
        rename = "device_session",
        deserialize_with = "removed_device_session"
    )]
    _device_session: (),
    #[serde(default)]
    pub gateways: Gateways,
    #[serde(default)]
    pub device_key: DeviceKey,
    #[serde(default)]
    pub limits: LimitsSection,
    #[serde(default)]
    pub browser: BrowserSection,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct GatewayName(String);

impl GatewayName {
    pub const MAX_LEN: usize = 64;

    pub fn command_line() -> Self {
        Self("command-line".to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for GatewayName {
    type Err = InvalidGatewayName;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        let valid = (1..=Self::MAX_LEN).contains(&name.len())
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-');
        if valid {
            Ok(Self(name.to_owned()))
        } else {
            Err(InvalidGatewayName(name.to_owned()))
        }
    }
}

impl TryFrom<String> for GatewayName {
    type Error = InvalidGatewayName;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        name.parse()
    }
}

impl fmt::Display for GatewayName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct PortalUrl(String);

impl PortalUrl {
    pub const MAX_LEN: usize = 2048;

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for PortalUrl {
    type Err = InvalidPortalUrl;

    fn from_str(url: &str) -> Result<Self, Self::Err> {
        const SCHEME: &str = "https://";
        let printable = url
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !br#""<>\^`{|}"#.contains(&byte));
        let authority = url
            .get(..SCHEME.len())
            .filter(|scheme| scheme.eq_ignore_ascii_case(SCHEME))
            .and_then(|_| url[SCHEME.len()..].split(['/', '?', '#']).next())
            .unwrap_or_default();
        let host = match authority.rsplit_once(':') {
            Some((host, port)) if port.bytes().all(|byte| byte.is_ascii_digit()) => host,
            _ => authority,
        };
        if url.len() <= Self::MAX_LEN && printable && !host.is_empty() && !authority.contains('@') {
            Ok(Self(url.to_owned()))
        } else {
            Err(InvalidPortalUrl)
        }
    }
}

impl TryFrom<String> for PortalUrl {
    type Error = InvalidPortalUrl;

    fn try_from(url: String) -> Result<Self, Self::Error> {
        url.parse()
    }
}

impl fmt::Display for PortalUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidPortalUrl;

impl fmt::Display for InvalidPortalUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "portal_url must be an https:// URL with a host and no user information, of at most \
             {} printable ASCII characters without spaces, quotes or backslashes",
            PortalUrl::MAX_LEN
        )
    }
}

impl std::error::Error for InvalidPortalUrl {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidGatewayName(String);

impl fmt::Display for InvalidGatewayName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid gateway name \"{}\": use 1 to {} characters from A-Z, a-z, 0-9, _ and -",
            self.0,
            GatewayName::MAX_LEN
        )
    }
}

impl std::error::Error for InvalidGatewayName {}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Gateways(BTreeMap<GatewayName, GatewaySection>);

impl Gateways {
    pub fn iter(&self) -> impl Iterator<Item = (&GatewayName, &GatewaySection)> {
        self.0.iter()
    }

    fn names(&self) -> String {
        if self.0.is_empty() {
            return "none".to_owned();
        }
        let names: Vec<&str> = self.0.keys().map(GatewayName::as_str).collect();
        names.join(", ")
    }
}

impl<'de> Deserialize<'de> for Gateways {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct GatewaysVisitor;

        impl<'de> Visitor<'de> for GatewaysVisitor {
            type Value = Gateways;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a table of gateways")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Gateways, M::Error> {
                let mut gateways = BTreeMap::new();
                while let Some(name) = map.next_key::<GatewayName>()? {
                    let section = map.next_value().map_err(|error| {
                        let message = error.to_string().trim_end().replace('\n', " ");
                        de::Error::custom(format!("gateway \"{name}\": {message}"))
                    })?;
                    gateways.insert(name, section);
                }
                Ok(Gateways(gateways))
            }
        }

        deserializer.deserialize_map(GatewaysVisitor)
    }
}

fn removed_device_session<'de, D: Deserializer<'de>>(_: D) -> Result<(), D::Error> {
    Err(de::Error::custom(
        "[device_session] was removed: Gateinto no longer runs a shared local proxy; delete the \
         section and start browser sessions with `gateinto open` or a gateinto:// link",
    ))
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewaySection {
    pub host: Option<String>,
    pub port: Option<NonZeroU16>,
    pub server_name: Option<String>,
    pub ca_file: Option<PathBuf>,
    pub tls_mode: Option<TlsMode>,
    pub client_certificate: Option<ClientCertificateMode>,
    pub client_cert_file: Option<PathBuf>,
    pub self_signed_client_cert: Option<bool>,
    pub portal_url: Option<PortalUrl>,
}

impl GatewaySection {
    fn merge(self, overrides: &Self) -> Self {
        let overrides = overrides.clone();
        Self {
            host: overrides.host.or(self.host),
            port: overrides.port.or(self.port),
            server_name: overrides.server_name.or(self.server_name),
            ca_file: overrides.ca_file.or(self.ca_file),
            tls_mode: overrides.tls_mode.or(self.tls_mode),
            client_certificate: overrides.client_certificate.or(self.client_certificate),
            client_cert_file: overrides.client_cert_file.or(self.client_cert_file),
            self_signed_client_cert: overrides
                .self_signed_client_cert
                .or(self.self_signed_client_cert),
            portal_url: overrides.portal_url.or(self.portal_url),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceKey {
    pub name: Option<KeyName>,
    pub preferred: Option<Backend>,
    pub software_fallback_on_first_create: Option<bool>,
}

impl DeviceKey {
    fn merge(&self, overrides: &Self) -> Self {
        Self {
            name: overrides.name.clone().or(self.name.clone()),
            preferred: overrides.preferred.or(self.preferred),
            software_fallback_on_first_create: overrides
                .software_fallback_on_first_create
                .or(self.software_fallback_on_first_create),
        }
    }

    pub fn settings(&self) -> DeviceKeySettings {
        let defaults = DeviceKeySettings::default();
        DeviceKeySettings {
            name: self.name.clone().unwrap_or(defaults.name),
            preferred: self.preferred.unwrap_or(defaults.preferred),
            software_fallback_on_first_create: self
                .software_fallback_on_first_create
                .unwrap_or(defaults.software_fallback_on_first_create),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsSection {
    pub max_concurrent_tunnels: Option<NonZeroU32>,
    pub connect_timeout_seconds: Option<NonZeroU64>,
    pub idle_timeout_seconds: Option<NonZeroU64>,
    pub header_max_bytes: Option<NonZeroU32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserSection {
    pub executable: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Overrides {
    pub gateway: Option<GatewayName>,
    pub gateway_settings: GatewaySection,
    pub device_key: DeviceKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub gateway: GatewayProfile,
    pub device_key: DeviceKeySettings,
    pub limits: LimitSettings,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayProfile {
    pub name: GatewayName,
    pub upstream: UpstreamSettings,
    pub tls_mode: TlsMode,
    pub client_certificate: ClientCertificateMode,
    pub client_cert_file: Option<PathBuf>,
    pub self_signed_client_cert: bool,
    pub portal_url: Option<PortalUrl>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamSettings {
    pub host: String,
    pub port: u16,
    pub server_name: String,
    pub ca_file: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceKeySettings {
    pub name: KeyName,
    pub preferred: Backend,
    pub software_fallback_on_first_create: bool,
}

impl Default for DeviceKeySettings {
    fn default() -> Self {
        Self {
            name: KeyName::default(),
            preferred: Backend::Tpm,
            software_fallback_on_first_create: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitSettings {
    pub max_concurrent_tunnels: u32,
    pub connect_timeout_seconds: u64,
    pub idle_timeout_seconds: u64,
    pub header_max_bytes: u32,
}

impl Default for LimitSettings {
    fn default() -> Self {
        Self {
            max_concurrent_tunnels: 64,
            connect_timeout_seconds: 10,
            idle_timeout_seconds: 300,
            header_max_bytes: DEFAULT_MAX_HEADER_BYTES as u32,
        }
    }
}

impl ConfigFile {
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        toml::from_str(text).map_err(|error| ConfigError::new(ErrorKind::Parse(error)))
    }

    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let in_file = |error: ConfigError| ConfigError {
            path: Some(path.to_owned()),
            ..error
        };
        let text = std::fs::read_to_string(path)
            .map_err(|error| in_file(ConfigError::new(ErrorKind::Read(error))))?;
        let mut file = Self::parse(&text).map_err(in_file)?;
        let base = path.parent().unwrap_or(Path::new(""));
        for gateway in file.gateways.0.values_mut() {
            for relative in [&mut gateway.ca_file, &mut gateway.client_cert_file]
                .into_iter()
                .flatten()
            {
                *relative = base.join(&*relative);
            }
        }
        if let Some(executable) = &mut file.browser.executable {
            *executable = base.join(&*executable);
        }
        file.path = Some(path.to_owned());
        Ok(file)
    }

    pub fn with_linked(&self, linked: &[LinkedGateway]) -> Self {
        let mut file = self.clone();
        for gateway in linked {
            file.gateways
                .0
                .entry(gateway.name.clone())
                .or_insert_with(|| GatewaySection {
                    host: Some(gateway.address.host()),
                    port: NonZeroU16::new(gateway.address.port()),
                    portal_url: gateway.portal_url.clone(),
                    ..GatewaySection::default()
                });
        }
        file
    }

    pub fn device_key_settings(&self) -> DeviceKeySettings {
        self.device_key.settings()
    }

    pub fn gateway(&self, name: &GatewayName) -> Result<GatewayProfile, ConfigError> {
        let section = self.gateways.0.get(name).ok_or_else(|| {
            self.error(ErrorKind::UnknownGateway {
                name: name.clone(),
                from_flag: false,
                configured: self.gateways.names(),
            })
        })?;
        self.profile(Some(name.clone()), section.clone())
    }

    pub fn settings(&self, overrides: &Overrides) -> Result<Settings, ConfigError> {
        let (name, section) = self.select_gateway(overrides.gateway.as_ref())?;
        let gateway = self.profile(name, section.merge(&overrides.gateway_settings))?;
        let defaults = LimitSettings::default();
        let file = &self.limits;
        let max_concurrent_tunnels = file
            .max_concurrent_tunnels
            .map_or(defaults.max_concurrent_tunnels, NonZeroU32::get);
        if max_concurrent_tunnels > crate::proxy::MAX_TUNNELS {
            return Err(self.error(ErrorKind::TunnelLimit(max_concurrent_tunnels)));
        }
        Ok(Settings {
            gateway,
            device_key: self.device_key.merge(&overrides.device_key).settings(),
            limits: LimitSettings {
                max_concurrent_tunnels,
                connect_timeout_seconds: file
                    .connect_timeout_seconds
                    .map_or(defaults.connect_timeout_seconds, NonZeroU64::get),
                idle_timeout_seconds: file
                    .idle_timeout_seconds
                    .map_or(defaults.idle_timeout_seconds, NonZeroU64::get),
                header_max_bytes: file
                    .header_max_bytes
                    .map_or(defaults.header_max_bytes, NonZeroU32::get),
            },
        })
    }

    fn select_gateway(
        &self,
        requested: Option<&GatewayName>,
    ) -> Result<(Option<GatewayName>, GatewaySection), ConfigError> {
        if let Some(name) = requested {
            let section = self.gateways.0.get(name).ok_or_else(|| {
                self.error(ErrorKind::UnknownGateway {
                    name: name.clone(),
                    from_flag: true,
                    configured: self.gateways.names(),
                })
            })?;
            return Ok((Some(name.clone()), section.clone()));
        }
        let mut gateways = self.gateways.0.iter();
        match (gateways.next(), gateways.next()) {
            (None, _) => Ok((None, GatewaySection::default())),
            (Some((name, section)), None) => Ok((Some(name.clone()), section.clone())),
            (Some(_), Some(_)) => Err(self.error(ErrorKind::AmbiguousGateway {
                count: self.gateways.0.len(),
                configured: self.gateways.names(),
            })),
        }
    }

    fn profile(
        &self,
        name: Option<GatewayName>,
        section: GatewaySection,
    ) -> Result<GatewayProfile, ConfigError> {
        let invalid = |kind| {
            self.error(ErrorKind::Gateway {
                name: name.clone(),
                kind,
            })
        };
        let (Some(host), Some(port)) = (section.host, section.port) else {
            return Err(invalid(GatewayErrorKind::NoUpstream));
        };
        let server_name = section.server_name.unwrap_or_else(|| host.clone());
        if let Err(error) = ServerName::try_from(server_name.as_str()) {
            return Err(invalid(GatewayErrorKind::ServerName(
                server_name.clone(),
                error.to_string(),
            )));
        }
        let self_signed_client_cert = section.self_signed_client_cert.unwrap_or(false);
        if self_signed_client_cert && section.client_cert_file.is_some() {
            return Err(invalid(GatewayErrorKind::ClientCertificateConflict));
        }
        Ok(GatewayProfile {
            name: name.unwrap_or_else(GatewayName::command_line),
            upstream: UpstreamSettings {
                host,
                port: port.get(),
                server_name,
                ca_file: section.ca_file,
            },
            tls_mode: section.tls_mode.unwrap_or_default(),
            client_certificate: section.client_certificate.unwrap_or_default(),
            client_cert_file: section.client_cert_file,
            self_signed_client_cert,
            portal_url: section.portal_url,
        })
    }

    fn error(&self, kind: ErrorKind) -> ConfigError {
        ConfigError {
            path: self.path.clone(),
            kind,
        }
    }
}

#[derive(Debug)]
pub struct ConfigError {
    path: Option<PathBuf>,
    kind: ErrorKind,
}

#[derive(Debug)]
enum ErrorKind {
    Read(io::Error),
    Parse(toml::de::Error),
    UnknownGateway {
        name: GatewayName,
        from_flag: bool,
        configured: String,
    },
    AmbiguousGateway {
        count: usize,
        configured: String,
    },
    Gateway {
        name: Option<GatewayName>,
        kind: GatewayErrorKind,
    },
    TunnelLimit(u32),
}

#[derive(Debug)]
enum GatewayErrorKind {
    NoUpstream,
    ServerName(String, String),
    ClientCertificateConflict,
}

impl ConfigError {
    fn new(kind: ErrorKind) -> Self {
        Self { path: None, kind }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(path) = &self.path {
            write!(f, "config file {}: ", path.display())?;
        }
        match &self.kind {
            ErrorKind::Read(error) => write!(f, "{error}"),
            ErrorKind::TunnelLimit(limit) => write!(
                f,
                "max_concurrent_tunnels is {limit}; the maximum is {}",
                crate::proxy::MAX_TUNNELS
            ),
            ErrorKind::Parse(error) => write!(f, "{}", error.to_string().trim_end()),
            ErrorKind::UnknownGateway {
                name,
                from_flag,
                configured,
            } => {
                if *from_flag {
                    f.write_str("--gateway names the ")?;
                }
                write!(
                    f,
                    "unknown gateway \"{name}\"; configured gateways: {configured}"
                )
            }
            ErrorKind::AmbiguousGateway { count, configured } => write!(
                f,
                "{count} gateways are configured ({configured}); pass --gateway to choose one"
            ),
            ErrorKind::Gateway { name: None, kind } => match kind {
                GatewayErrorKind::NoUpstream => f.write_str(
                    "no upstream configured; pass --upstream-host and --upstream-port, or \
                         add a [gateways.<name>] table with host and port to the --config file",
                ),
                kind => kind.fmt(f),
            },
            ErrorKind::Gateway {
                name: Some(name),
                kind,
            } => {
                write!(f, "gateway \"{name}\": ")?;
                match kind {
                    GatewayErrorKind::NoUpstream => write!(
                        f,
                        "no upstream configured; set host and port in [gateways.{name}] or pass \
                         --upstream-host and --upstream-port"
                    ),
                    kind => kind.fmt(f),
                }
            }
        }
    }
}

impl fmt::Display for GatewayErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoUpstream => f.write_str("no upstream configured"),
            Self::ServerName(name, error) => {
                write!(f, "invalid upstream server name \"{name}\": {error}")
            }
            Self::ClientCertificateConflict => f.write_str(
                "a client certificate file and a self-signed client certificate cannot be \
                 combined; set either client_cert_file (--client-cert-file) or \
                 self_signed_client_cert (--self-signed-client-cert)",
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let pairs: Vec<(String, OsString)> = pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), OsString::from(value)))
            .collect();
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        }
    }

    #[cfg(windows)]
    #[test]
    fn the_default_config_file_is_in_the_roaming_app_data_folder() {
        assert_eq!(
            default_path_from(vars(&[("APPDATA", r"C:\Users\me\AppData\Roaming")])),
            Some(PathBuf::from(
                r"C:\Users\me\AppData\Roaming\Gateinto\gateinto.toml"
            ))
        );
        assert_eq!(default_path_from(vars(&[("APPDATA", "relative")])), None);
        assert_eq!(default_path_from(vars(&[])), None);
    }

    #[cfg(not(windows))]
    #[test]
    fn the_default_config_file_is_in_the_xdg_config_folder() {
        assert_eq!(
            default_path_from(vars(&[("XDG_CONFIG_HOME", "/cfg"), ("HOME", "/home/me")])),
            Some(PathBuf::from("/cfg/gateinto/gateinto.toml"))
        );
        assert_eq!(
            default_path_from(vars(&[("XDG_CONFIG_HOME", "rel"), ("HOME", "/home/me")])),
            Some(PathBuf::from("/home/me/.config/gateinto/gateinto.toml"))
        );
        assert_eq!(default_path_from(vars(&[("HOME", "rel")])), None);
        assert_eq!(default_path_from(vars(&[])), None);
    }

    const FULL: &str = r#"
[gateways.office]
host = "proxy.example.test"
port = 8443
server_name = "name.example.test"
ca_file = "/etc/gateinto/ca.pem"
tls_mode = "hybrid_required"
client_certificate = "required"
client_cert_file = "/etc/gateinto/client.pem"
portal_url = "https://portal.example.test/start?from=gateinto"

[gateways.home]
host = "home.example.test"
port = 443

[device_key]
name = "gateinto-other"
preferred = "software"
software_fallback_on_first_create = false

[limits]
max_concurrent_tunnels = 8
connect_timeout_seconds = 3
idle_timeout_seconds = 60
header_max_bytes = 4096
"#;

    const MINIMAL: &str = r#"
[gateways.main]
host = "proxy.example.test"
port = 443
"#;

    fn name(name: &str) -> GatewayName {
        name.parse().unwrap()
    }

    fn settings(text: &str) -> Result<Settings, ConfigError> {
        ConfigFile::parse(text)?.settings(&Overrides::default())
    }

    fn office() -> Overrides {
        Overrides {
            gateway: Some(name("office")),
            ..Overrides::default()
        }
    }

    #[test]
    fn every_section_is_read() {
        let settings = ConfigFile::parse(FULL)
            .unwrap()
            .settings(&office())
            .unwrap();
        assert_eq!(
            settings,
            Settings {
                gateway: GatewayProfile {
                    name: name("office"),
                    upstream: UpstreamSettings {
                        host: "proxy.example.test".to_owned(),
                        port: 8443,
                        server_name: "name.example.test".to_owned(),
                        ca_file: Some(PathBuf::from("/etc/gateinto/ca.pem")),
                    },
                    tls_mode: TlsMode::HybridRequired,
                    client_certificate: ClientCertificateMode::Required,
                    client_cert_file: Some(PathBuf::from("/etc/gateinto/client.pem")),
                    self_signed_client_cert: false,
                    portal_url: Some(
                        "https://portal.example.test/start?from=gateinto"
                            .parse()
                            .unwrap()
                    ),
                },
                device_key: DeviceKeySettings {
                    name: "gateinto-other".parse().unwrap(),
                    preferred: Backend::Software,
                    software_fallback_on_first_create: false,
                },
                limits: LimitSettings {
                    max_concurrent_tunnels: 8,
                    connect_timeout_seconds: 3,
                    idle_timeout_seconds: 60,
                    header_max_bytes: 4096,
                },
            }
        );
    }

    #[test]
    fn omitted_values_take_the_defaults() {
        let settings = settings(MINIMAL).unwrap();
        assert_eq!(settings.gateway.name, name("main"));
        assert_eq!(settings.gateway.upstream.server_name, "proxy.example.test");
        assert_eq!(settings.gateway.upstream.ca_file, None);
        assert_eq!(settings.gateway.tls_mode, TlsMode::HybridPreferred);
        assert_eq!(
            settings.gateway.client_certificate,
            ClientCertificateMode::Optional
        );
        assert_eq!(settings.gateway.client_cert_file, None);
        assert_eq!(settings.gateway.portal_url, None);
        assert_eq!(
            settings.device_key,
            DeviceKeySettings {
                name: KeyName::default(),
                preferred: Backend::Tpm,
                software_fallback_on_first_create: true,
            }
        );
        assert_eq!(
            settings.limits,
            LimitSettings {
                max_concurrent_tunnels: 64,
                connect_timeout_seconds: 10,
                idle_timeout_seconds: 300,
                header_max_bytes: 16384,
            }
        );
    }

    #[test]
    fn an_empty_file_is_valid_but_has_no_upstream() {
        let file = ConfigFile::parse("").unwrap();
        assert_eq!(file, ConfigFile::default());
        assert_eq!(file.device_key_settings(), DeviceKeySettings::default());
        let error = file
            .settings(&Overrides::default())
            .unwrap_err()
            .to_string();
        assert!(error.contains("no upstream configured"), "{error}");
        assert!(error.contains("--upstream-host"), "{error}");
        assert!(error.contains("--upstream-port"), "{error}");
        assert!(error.contains("[gateways.<name>]"), "{error}");
    }

    #[test]
    fn an_incomplete_gateway_is_an_error_naming_it() {
        for text in [
            "[gateways.main]\nhost = \"proxy.example.test\"\n",
            "[gateways.main]\nport = 443\n",
            "[gateways.main]\nserver_name = \"proxy.example.test\"\n",
        ] {
            let error = settings(text).unwrap_err().to_string();
            assert!(
                error.starts_with("gateway \"main\": no upstream configured"),
                "{text}: {error}"
            );
            assert!(error.contains("[gateways.main]"), "{text}: {error}");
            assert!(error.contains("--upstream-host"), "{text}: {error}");
        }
    }

    #[test]
    fn a_gateway_named_command_line_gets_the_per_gateway_error() {
        let error = settings("[gateways.command-line]\nport = 443\n")
            .unwrap_err()
            .to_string();
        assert!(
            error.starts_with("gateway \"command-line\": no upstream configured"),
            "{error}"
        );
        assert!(error.contains("[gateways.command-line]"), "{error}");
    }

    #[test]
    fn the_only_gateway_is_used_by_default() {
        let settings = settings(MINIMAL).unwrap();
        assert_eq!(settings.gateway.name, name("main"));
        assert_eq!(settings.gateway.upstream.host, "proxy.example.test");
    }

    #[test]
    fn the_removed_device_session_section_fails_closed_naming_it() {
        for text in [
            "[device_session]\n",
            "[device_session]\ngateway = \"main\"\nauth = \"none\"\n",
            "[device_session]\nlisten = \"0.0.0.0:18736\"\n",
            "device_session = 1\n",
        ] {
            let error = ConfigFile::parse(&format!("{text}{MINIMAL}"))
                .unwrap_err()
                .to_string();
            assert!(
                error.contains(
                    "[device_session] was removed: Gateinto no longer runs a shared local proxy"
                ),
                "{text}: {error}"
            );
            assert!(error.contains("delete the section"), "{text}: {error}");
        }
    }

    #[test]
    fn several_gateways_need_a_gateway_flag() {
        let text = format!("{MINIMAL}[gateways.other]\nhost = \"other.test\"\nport = 443\n");
        let error = settings(&text).unwrap_err().to_string();
        assert_eq!(
            error,
            "2 gateways are configured (main, other); pass --gateway to choose one"
        );
    }

    #[test]
    fn an_unknown_gateway_reference_is_an_error_naming_it() {
        let overrides = Overrides {
            gateway: Some(name("absent")),
            ..Overrides::default()
        };
        let error = ConfigFile::parse(MINIMAL)
            .unwrap()
            .settings(&overrides)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "--gateway names the unknown gateway \"absent\"; configured gateways: main"
        );

        let error = ConfigFile::default()
            .settings(&overrides)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "--gateway names the unknown gateway \"absent\"; configured gateways: none"
        );
    }

    #[test]
    fn gateway_names_are_validated() {
        let longest = "a".repeat(64);
        for valid in ["a", "Office_2", "home-vpn", "0", longest.as_str()] {
            assert_eq!(name(valid).as_str(), valid);
            let text = format!("[gateways.\"{valid}\"]\nhost = \"h.test\"\nport = 1\n");
            assert_eq!(settings(&text).unwrap().gateway.name.as_str(), valid);
        }
        let too_long = "a".repeat(65);
        for invalid in ["", "a b", "a.b", "é", "a/b", too_long.as_str()] {
            let error = invalid.parse::<GatewayName>().unwrap_err().to_string();
            assert_eq!(
                error,
                format!(
                    "invalid gateway name \"{invalid}\": use 1 to 64 characters from A-Z, \
                     a-z, 0-9, _ and -"
                )
            );
            let text = format!("[gateways.\"{invalid}\"]\nhost = \"h.test\"\nport = 1\n");
            let parsed = ConfigFile::parse(&text).unwrap_err().to_string();
            assert!(parsed.contains(&error), "{text}: {parsed}");
        }
    }

    #[test]
    fn gateway_lookup_only_reads_the_loaded_file() {
        let file = ConfigFile::parse(FULL).unwrap();
        let home = file.gateway(&name("home")).unwrap();
        assert_eq!(home.name, name("home"));
        assert_eq!(home.upstream.host, "home.example.test");
        assert_eq!(home.upstream.server_name, "home.example.test");
        assert_eq!(home.upstream.ca_file, None);

        let error = file.gateway(&name("other")).unwrap_err().to_string();
        assert_eq!(
            error,
            "unknown gateway \"other\"; configured gateways: home, office"
        );
    }

    #[test]
    fn unknown_keys_are_rejected() {
        for (text, key) in [
            ("unknown = 1\n", "unknown"),
            ("[proxy]\nport = 1\n", "proxy"),
            ("[listen]\naddress = \"127.0.0.1:1\"\n", "listen"),
            ("[upstream]\nhost = \"x\"\n", "upstream"),
            ("[tls]\nmode = \"classical_only\"\n", "tls"),
            ("[gateways.main]\nlisten = \"127.0.0.1:1\"\n", "listen"),
            ("[device_key]\nbackend = \"tpm\"\n", "backend"),
            ("[limits]\nmax_tunnels = 1\n", "max_tunnels"),
        ] {
            let error = ConfigFile::parse(text).unwrap_err().to_string();
            assert!(error.contains(key), "{text}: {error}");
        }
        let error = ConfigFile::parse("[gateways.main]\nhostname = \"x\"\n")
            .unwrap_err()
            .to_string();
        assert!(error.contains("gateway \"main\""), "{error}");
        assert!(error.contains("hostname"), "{error}");
    }

    #[test]
    fn non_loopback_listen_cannot_be_allowed_from_the_file() {
        for (text, key) in [
            (
                "unsafe_allow_non_loopback_listen = true\n",
                "unsafe_allow_non_loopback_listen",
            ),
            (
                "[gateways.main]\nunsafe_allow_non_loopback_listen = true\n",
                "unsafe_allow_non_loopback_listen",
            ),
            (
                "[limits]\nallow_non_loopback = true\n",
                "allow_non_loopback",
            ),
        ] {
            let error = ConfigFile::parse(text).unwrap_err().to_string();
            assert!(
                error.contains(&format!("unknown field `{key}`")),
                "{text}: {error}"
            );
        }
    }

    #[test]
    fn invalid_values_are_rejected() {
        for (text, expected) in [
            ("[gateways]\nmain = 1\n", "gateway \"main\""),
            ("[gateways.main]\nport = 0\n", "port"),
            ("[gateways.main]\nport = 70000\n", "port"),
            (
                "[gateways.main]\ntls_mode = \"hybrid\"\n",
                "hybrid_preferred",
            ),
            (
                "[gateways.main]\nclient_certificate = \"sometimes\"\n",
                "optional",
            ),
            ("[device_key]\nname = \"\"\n", "key name must not be empty"),
            ("[device_key]\npreferred = \"hsm\"\n", "tpm"),
            (
                "[limits]\nmax_concurrent_tunnels = 0\n",
                "max_concurrent_tunnels",
            ),
            (
                "[limits]\nconnect_timeout_seconds = 0\n",
                "connect_timeout_seconds",
            ),
            (
                "[limits]\nidle_timeout_seconds = -1\n",
                "idle_timeout_seconds",
            ),
            ("[limits]\nheader_max_bytes = 0\n", "header_max_bytes"),
            ("[gateways.main]\nhost = 1\n", "host"),
            ("[gateways.main\n", "TOML"),
        ] {
            let error = ConfigFile::parse(text).unwrap_err().to_string();
            assert!(error.contains(expected), "{text}: {error}");
        }
    }

    #[test]
    fn tunnel_limits_above_the_http2_window_bound_are_rejected() {
        for limit in [32767, 32768] {
            let text = format!("{MINIMAL}[limits]\nmax_concurrent_tunnels = {limit}\n");
            let mut file = ConfigFile::parse(&text).unwrap();
            file.path = Some(PathBuf::from("gateinto.toml"));
            let result = file.settings(&Overrides::default());
            if limit == 32767 {
                assert_eq!(result.unwrap().limits.max_concurrent_tunnels, 32767);
            } else {
                assert_eq!(
                    result.unwrap_err().to_string(),
                    "config file gateinto.toml: max_concurrent_tunnels is 32768; the maximum is \
                     32767"
                );
            }
        }
    }

    #[test]
    fn portal_urls_must_be_plain_https_urls() {
        for url in [
            "https://portal.example.test",
            "HTTPS://portal.example.test/",
            "https://portal.example.test:8443/a/b?c=d&e=%20#top",
            "https://10.0.0.1/",
            "https://[::1]:443/",
        ] {
            let parsed: PortalUrl = url.parse().unwrap();
            assert_eq!(parsed.as_str(), url);
        }
        let long = format!(
            "https://portal.example.test/{}",
            "a".repeat(PortalUrl::MAX_LEN)
        );
        for url in [
            "",
            "http://portal.example.test/",
            "https:portal.example.test",
            "https:/portal.example.test",
            "https://",
            "https:///path",
            "https://:443/",
            "https://?q",
            "https://user@portal.example.test/",
            "https://user:secret@portal.example.test/",
            "https://portal.example.test/a b",
            "https://portal.example.test/\"quoted\"",
            "https://portal.example.test/<script>",
            "https://portal.example.test/\\path",
            "https://portal.example.test/\n",
            "https://portal.example.test/caf\u{e9}",
            " https://portal.example.test/",
            "javascript:alert(1)",
            "file:///C:/Windows",
            "data:text/html,hi",
            "--disable-web-security",
            &long,
        ] {
            assert!(url.parse::<PortalUrl>().is_err(), "{url:?}");
        }
    }

    #[test]
    fn an_invalid_portal_url_is_an_error_naming_the_gateway() {
        let text = format!("{MINIMAL}portal_url = \"http://portal.example.test/\"\n");
        let error = ConfigFile::parse(&text).unwrap_err().to_string();
        assert!(error.contains("gateway \"main\""), "{error}");
        assert!(error.contains("portal_url"), "{error}");
        assert!(error.contains("https"), "{error}");
    }

    #[test]
    fn the_browser_section_names_an_executable() {
        let file = ConfigFile::parse("[browser]\nexecutable = \"/opt/chrome/chrome\"\n").unwrap();
        assert_eq!(
            file.browser.executable,
            Some(PathBuf::from("/opt/chrome/chrome"))
        );
        assert_eq!(ConfigFile::parse("").unwrap().browser.executable, None);
        let error = ConfigFile::parse("[browser]\nargs = []\n")
            .unwrap_err()
            .to_string();
        assert!(error.contains("args"), "{error}");
    }

    #[test]
    fn self_signed_client_cert_is_off_unless_enabled() {
        assert!(!settings(MINIMAL).unwrap().gateway.self_signed_client_cert);
        assert!(
            !ConfigFile::parse(FULL)
                .unwrap()
                .settings(&office())
                .unwrap()
                .gateway
                .self_signed_client_cert
        );
        let text = format!("{MINIMAL}self_signed_client_cert = true\n");
        assert!(settings(&text).unwrap().gateway.self_signed_client_cert);
        let error = ConfigFile::parse("[gateways.main]\nself_signed_client_cert = \"yes\"\n")
            .unwrap_err()
            .to_string();
        assert!(error.contains("self_signed_client_cert"), "{error}");
    }

    #[test]
    fn self_signed_client_cert_and_client_cert_file_are_exclusive() {
        let text =
            format!("{MINIMAL}self_signed_client_cert = true\nclient_cert_file = \"client.pem\"\n");
        assert_eq!(
            settings(&text).unwrap_err().to_string(),
            "gateway \"main\": a client certificate file and a self-signed client certificate \
             cannot be combined; set either client_cert_file (--client-cert-file) or \
             self_signed_client_cert (--self-signed-client-cert)"
        );
        let disabled = format!(
            "{MINIMAL}self_signed_client_cert = false\nclient_cert_file = \"client.pem\"\n"
        );
        assert!(settings(&disabled).is_ok());
    }

    #[test]
    fn self_signed_client_cert_can_be_enabled_by_an_override() {
        let overrides = Overrides {
            gateway_settings: GatewaySection {
                self_signed_client_cert: Some(true),
                ..GatewaySection::default()
            },
            ..Overrides::default()
        };
        let file = ConfigFile::parse(MINIMAL).unwrap();

        assert!(
            file.settings(&overrides)
                .unwrap()
                .gateway
                .self_signed_client_cert
        );
    }

    #[test]
    fn invalid_upstream_server_name_is_rejected() {
        let text = format!("{MINIMAL}server_name = \"not a name\"\n");
        let error = settings(&text).unwrap_err().to_string();
        assert!(error.starts_with("gateway \"main\": "), "{error}");
        assert!(error.contains("server name"), "{error}");
    }

    #[test]
    fn overrides_take_precedence_field_by_field() {
        let file = ConfigFile::parse(FULL).unwrap();
        let overrides = Overrides {
            gateway: Some(name("office")),
            gateway_settings: GatewaySection {
                port: NonZeroU16::new(9443),
                tls_mode: Some(TlsMode::ClassicalOnly),
                ..GatewaySection::default()
            },
            device_key: DeviceKey {
                software_fallback_on_first_create: Some(true),
                ..DeviceKey::default()
            },
        };

        let settings = file.settings(&overrides).unwrap();

        assert_eq!(settings.gateway.name, name("office"));
        assert_eq!(settings.gateway.upstream.host, "proxy.example.test");
        assert_eq!(settings.gateway.upstream.port, 9443);
        assert_eq!(settings.gateway.upstream.server_name, "name.example.test");
        assert_eq!(settings.gateway.tls_mode, TlsMode::ClassicalOnly);
        assert_eq!(
            settings.gateway.client_certificate,
            ClientCertificateMode::Required
        );
        assert_eq!(settings.device_key.preferred, Backend::Software);
        assert!(settings.device_key.software_fallback_on_first_create);
        assert_eq!(settings.limits.idle_timeout_seconds, 60);
        assert_eq!(settings.limits.max_concurrent_tunnels, 8);
    }

    #[test]
    fn overrides_apply_to_the_selected_gateway_only() {
        let file = ConfigFile::parse(FULL).unwrap();
        let overrides = Overrides {
            gateway: Some(name("home")),
            gateway_settings: GatewaySection {
                tls_mode: Some(TlsMode::ClassicalOnly),
                ..GatewaySection::default()
            },
            ..Overrides::default()
        };

        let home = file.settings(&overrides).unwrap().gateway;

        assert_eq!(home.name, name("home"));
        assert_eq!(home.upstream.host, "home.example.test");
        assert_eq!(home.tls_mode, TlsMode::ClassicalOnly);
        assert_eq!(home.client_certificate, ClientCertificateMode::Optional);
        let office = file.gateway(&name("office")).unwrap();
        assert_eq!(office.tls_mode, TlsMode::HybridRequired);
    }

    #[test]
    fn overrides_alone_can_supply_the_upstream() {
        let overrides = Overrides {
            gateway_settings: GatewaySection {
                host: Some("cli.example.test".to_owned()),
                port: NonZeroU16::new(443),
                ..GatewaySection::default()
            },
            ..Overrides::default()
        };
        let settings = ConfigFile::default().settings(&overrides).unwrap();
        assert_eq!(settings.gateway.name, GatewayName::command_line());
        assert_eq!(settings.gateway.name.as_str(), "command-line");
        assert_eq!(settings.gateway.upstream.host, "cli.example.test");
        assert_eq!(settings.gateway.upstream.server_name, "cli.example.test");
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("gateinto-config-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn relative_paths_are_resolved_against_the_file() {
        let dir = temp_dir("relative");
        let path = dir.join("gateinto.toml");
        let absolute = std::env::temp_dir().join("client.pem");
        assert!(absolute.is_absolute());
        std::fs::write(
            &path,
            format!(
                "{MINIMAL}ca_file = \"certs/ca.pem\"\nclient_cert_file = '{}'\n\
                 [gateways.other]\nhost = \"other.test\"\nport = 1\nca_file = \"other.pem\"\n\
                 client_cert_file = \"keys/client.pem\"\n\
                 [browser]\nexecutable = \"bin/chrome\"\n",
                absolute.display()
            ),
        )
        .unwrap();

        let file = ConfigFile::load(&path).unwrap();
        let main = file.gateway(&name("main")).unwrap();
        let other = file.gateway(&name("other")).unwrap();

        assert_eq!(main.upstream.ca_file, Some(dir.join("certs/ca.pem")));
        assert_eq!(main.client_cert_file, Some(absolute));
        assert_eq!(other.upstream.ca_file, Some(dir.join("other.pem")));
        assert_eq!(other.client_cert_file, Some(dir.join("keys/client.pem")));
        assert_eq!(file.browser.executable, Some(dir.join("bin/chrome")));
    }

    #[test]
    fn errors_name_the_file() {
        let dir = temp_dir("errors");
        let missing = dir.join("missing.toml");
        let error = ConfigFile::load(&missing).unwrap_err().to_string();
        assert!(error.contains(&missing.display().to_string()), "{error}");

        let invalid = dir.join("invalid.toml");
        std::fs::write(&invalid, "[gateways.main]\nhostname = \"x\"\n").unwrap();
        let error = ConfigFile::load(&invalid).unwrap_err().to_string();
        assert!(error.contains(&invalid.display().to_string()), "{error}");
        assert!(error.contains("hostname"), "{error}");

        let incomplete = dir.join("incomplete.toml");
        std::fs::write(&incomplete, "[gateways.main]\nport = 1\n").unwrap();
        let file = ConfigFile::load(&incomplete).unwrap();
        for error in [
            file.settings(&Overrides::default()).unwrap_err(),
            file.gateway(&name("main")).unwrap_err(),
            file.gateway(&name("other")).unwrap_err(),
        ] {
            let error = error.to_string();
            assert!(
                error.starts_with(&format!("config file {}: ", incomplete.display())),
                "{error}"
            );
        }
    }

    #[test]
    fn the_installer_template_comments_out_every_example_setting() {
        let template = include_str!("../packaging/wix/gateinto.toml");
        assert_eq!(ConfigFile::parse(template).unwrap(), ConfigFile::default());
        assert!(
            template
                .lines()
                .all(|line| line.is_empty() || line.starts_with('#')),
            "{template}"
        );
        let commented: Vec<&str> = template.lines().collect();
        let example = include_str!("../config.example.toml");
        for line in example
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            let wanted = format!("# {line}");
            assert!(commented.contains(&wanted.as_str()), "{line}");
        }
    }

    #[test]
    fn the_installer_never_reinstalls_or_removes_the_config_template() {
        let wxs = include_str!("../packaging/wix/gateinto.wxs");
        let component = wxs
            .lines()
            .find(|line| line.contains(r#"<Component Id="ConfigTemplate""#))
            .unwrap();
        for wanted in [
            r#"Permanent="yes""#,
            r#"NeverOverwrite="yes""#,
            r#"Condition="NOT CONFIGEXISTS""#,
        ] {
            assert!(component.contains(wanted), "{wanted}");
        }
        assert!(!component.contains("Transitive"), "{component}");
    }

    #[test]
    fn example_file_parses() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.example.toml");
        let file = ConfigFile::load(&path).unwrap();
        let settings = file.settings(&Overrides::default()).unwrap();
        assert_eq!(settings.gateway.name, name("default"));
        assert!(
            settings.gateway.upstream.host.ends_with(".invalid"),
            "{settings:?}"
        );
        assert_eq!(settings.gateway.tls_mode, TlsMode::HybridPreferred);
        assert_eq!(settings.limits, LimitSettings::default());
        assert_eq!(settings.device_key, DeviceKeySettings::default());
    }
}
