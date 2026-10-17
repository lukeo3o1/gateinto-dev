use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::path::{Path, PathBuf};

use rustls::pki_types::ServerName;
use serde::Deserialize;

use crate::http::DEFAULT_MAX_HEADER_BYTES;
use crate::identity::client_cert::ClientCertificateMode;
use crate::identity::device_key::{Backend, KeyName};
use crate::proxy::DEFAULT_LISTEN;
use crate::tls::TlsMode;

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    #[serde(default)]
    pub listen: Listen,
    #[serde(default)]
    pub upstream: UpstreamSection,
    #[serde(default)]
    pub tls: Tls,
    #[serde(default)]
    pub device_key: DeviceKey,
    #[serde(default)]
    pub limits: LimitsSection,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listen {
    pub address: Option<SocketAddr>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamSection {
    pub host: Option<String>,
    pub port: Option<NonZeroU16>,
    pub server_name: Option<String>,
    pub ca_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    pub mode: Option<TlsMode>,
    pub client_certificate: Option<ClientCertificateMode>,
    pub client_cert_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceKey {
    pub name: Option<KeyName>,
    pub preferred: Option<Backend>,
    pub software_fallback_on_first_create: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsSection {
    pub max_concurrent_tunnels: Option<NonZeroU32>,
    pub connect_timeout_seconds: Option<NonZeroU64>,
    pub idle_timeout_seconds: Option<NonZeroU64>,
    pub header_max_bytes: Option<NonZeroU32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub listen: SocketAddr,
    pub upstream: UpstreamSettings,
    pub tls_mode: TlsMode,
    pub client_certificate: ClientCertificateMode,
    pub client_cert_file: Option<PathBuf>,
    pub device_key: DeviceKeySettings,
    pub limits: LimitSettings,
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
        for relative in [&mut file.upstream.ca_file, &mut file.tls.client_cert_file]
            .into_iter()
            .flatten()
        {
            *relative = base.join(&*relative);
        }
        Ok(file)
    }

    pub fn merge(self, overrides: Self) -> Self {
        Self {
            listen: Listen {
                address: overrides.listen.address.or(self.listen.address),
            },
            upstream: UpstreamSection {
                host: overrides.upstream.host.or(self.upstream.host),
                port: overrides.upstream.port.or(self.upstream.port),
                server_name: overrides.upstream.server_name.or(self.upstream.server_name),
                ca_file: overrides.upstream.ca_file.or(self.upstream.ca_file),
            },
            tls: Tls {
                mode: overrides.tls.mode.or(self.tls.mode),
                client_certificate: overrides
                    .tls
                    .client_certificate
                    .or(self.tls.client_certificate),
                client_cert_file: overrides.tls.client_cert_file.or(self.tls.client_cert_file),
            },
            device_key: DeviceKey {
                name: overrides.device_key.name.or(self.device_key.name),
                preferred: overrides.device_key.preferred.or(self.device_key.preferred),
                software_fallback_on_first_create: overrides
                    .device_key
                    .software_fallback_on_first_create
                    .or(self.device_key.software_fallback_on_first_create),
            },
            limits: LimitsSection {
                max_concurrent_tunnels: overrides
                    .limits
                    .max_concurrent_tunnels
                    .or(self.limits.max_concurrent_tunnels),
                connect_timeout_seconds: overrides
                    .limits
                    .connect_timeout_seconds
                    .or(self.limits.connect_timeout_seconds),
                idle_timeout_seconds: overrides
                    .limits
                    .idle_timeout_seconds
                    .or(self.limits.idle_timeout_seconds),
                header_max_bytes: overrides
                    .limits
                    .header_max_bytes
                    .or(self.limits.header_max_bytes),
            },
        }
    }

    pub fn device_key_settings(&self) -> DeviceKeySettings {
        let defaults = DeviceKeySettings::default();
        let section = &self.device_key;
        DeviceKeySettings {
            name: section.name.clone().unwrap_or(defaults.name),
            preferred: section.preferred.unwrap_or(defaults.preferred),
            software_fallback_on_first_create: section
                .software_fallback_on_first_create
                .unwrap_or(defaults.software_fallback_on_first_create),
        }
    }

    pub fn settings(&self) -> Result<Settings, ConfigError> {
        let upstream = &self.upstream;
        let (Some(host), Some(port)) = (&upstream.host, upstream.port) else {
            return Err(ConfigError::new(ErrorKind::NoUpstream));
        };
        let server_name = upstream.server_name.clone().unwrap_or_else(|| host.clone());
        ServerName::try_from(server_name.as_str()).map_err(|error| {
            ConfigError::new(ErrorKind::ServerName(
                server_name.clone(),
                error.to_string(),
            ))
        })?;
        let defaults = LimitSettings::default();
        let limits = &self.limits;
        Ok(Settings {
            listen: self.listen.address.unwrap_or(DEFAULT_LISTEN),
            upstream: UpstreamSettings {
                host: host.clone(),
                port: port.get(),
                server_name,
                ca_file: upstream.ca_file.clone(),
            },
            tls_mode: self.tls.mode.unwrap_or_default(),
            client_certificate: self.tls.client_certificate.unwrap_or_default(),
            client_cert_file: self.tls.client_cert_file.clone(),
            device_key: self.device_key_settings(),
            limits: LimitSettings {
                max_concurrent_tunnels: limits
                    .max_concurrent_tunnels
                    .map_or(defaults.max_concurrent_tunnels, NonZeroU32::get),
                connect_timeout_seconds: limits
                    .connect_timeout_seconds
                    .map_or(defaults.connect_timeout_seconds, NonZeroU64::get),
                idle_timeout_seconds: limits
                    .idle_timeout_seconds
                    .map_or(defaults.idle_timeout_seconds, NonZeroU64::get),
                header_max_bytes: limits
                    .header_max_bytes
                    .map_or(defaults.header_max_bytes, NonZeroU32::get),
            },
        })
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
    NoUpstream,
    ServerName(String, String),
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
            ErrorKind::Parse(error) => write!(f, "{}", error.to_string().trim_end()),
            ErrorKind::NoUpstream => f.write_str(
                "no upstream configured; pass --upstream-host and --upstream-port, \
                 or set host and port in the [upstream] section of the --config file",
            ),
            ErrorKind::ServerName(name, error) => {
                write!(f, "invalid upstream server name \"{name}\": {error}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const FULL: &str = r#"
[listen]
address = "127.0.0.2:8080"

[upstream]
host = "proxy.example.test"
port = 8443
server_name = "name.example.test"
ca_file = "/etc/gateinto/ca.pem"

[tls]
mode = "hybrid_required"
client_certificate = "required"
client_cert_file = "/etc/gateinto/client.pem"

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
[upstream]
host = "proxy.example.test"
port = 443
"#;

    fn settings(text: &str) -> Result<Settings, ConfigError> {
        ConfigFile::parse(text)?.settings()
    }

    #[test]
    fn every_section_is_read() {
        let settings = settings(FULL).unwrap();
        assert_eq!(
            settings,
            Settings {
                listen: "127.0.0.2:8080".parse().unwrap(),
                upstream: UpstreamSettings {
                    host: "proxy.example.test".to_owned(),
                    port: 8443,
                    server_name: "name.example.test".to_owned(),
                    ca_file: Some(PathBuf::from("/etc/gateinto/ca.pem")),
                },
                tls_mode: TlsMode::HybridRequired,
                client_certificate: ClientCertificateMode::Required,
                client_cert_file: Some(PathBuf::from("/etc/gateinto/client.pem")),
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
        assert_eq!(settings.listen, crate::proxy::DEFAULT_LISTEN);
        assert_eq!(settings.upstream.server_name, "proxy.example.test");
        assert_eq!(settings.upstream.ca_file, None);
        assert_eq!(settings.tls_mode, TlsMode::HybridPreferred);
        assert_eq!(settings.client_certificate, ClientCertificateMode::Optional);
        assert_eq!(settings.client_cert_file, None);
        assert_eq!(settings.device_key, DeviceKeySettings::default());
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
        let error = file.settings().unwrap_err().to_string();
        assert!(error.contains("no upstream configured"), "{error}");
        assert!(error.contains("--upstream-host"), "{error}");
        assert!(error.contains("--upstream-port"), "{error}");
        assert!(error.contains("[upstream]"), "{error}");
    }

    #[test]
    fn an_incomplete_upstream_is_an_error() {
        for text in [
            "[upstream]\nhost = \"proxy.example.test\"\n",
            "[upstream]\nport = 443\n",
            "[upstream]\nserver_name = \"proxy.example.test\"\n",
        ] {
            let error = settings(text).unwrap_err().to_string();
            assert!(error.contains("no upstream configured"), "{text}: {error}");
        }
    }

    #[test]
    fn unknown_keys_are_rejected() {
        for (text, key) in [
            ("unknown = 1\n", "unknown"),
            ("[proxy]\nport = 1\n", "proxy"),
            ("[listen]\nport = 1\n", "port"),
            ("[upstream]\nhostname = \"x\"\n", "hostname"),
            ("[tls]\nversion = \"1.3\"\n", "version"),
            ("[device_key]\nbackend = \"tpm\"\n", "backend"),
            ("[limits]\nmax_tunnels = 1\n", "max_tunnels"),
        ] {
            let error = ConfigFile::parse(text).unwrap_err().to_string();
            assert!(error.contains(key), "{text}: {error}");
        }
    }

    #[test]
    fn non_loopback_listen_cannot_be_allowed_from_the_file() {
        for text in [
            "unsafe_allow_non_loopback_listen = true\n",
            "[listen]\nunsafe_allow_non_loopback_listen = true\n",
            "[listen]\nallow_non_loopback = true\n",
        ] {
            assert!(ConfigFile::parse(text).is_err(), "{text}");
        }
        let text = format!("[listen]\naddress = \"0.0.0.0:18736\"\n{MINIMAL}");
        let settings = settings(&text).unwrap();
        assert!(!settings.listen.ip().is_loopback());
    }

    #[test]
    fn invalid_values_are_rejected() {
        for (text, expected) in [
            ("[listen]\naddress = \"localhost\"\n", "address"),
            ("[upstream]\nport = 0\n", "port"),
            ("[upstream]\nport = 70000\n", "port"),
            ("[tls]\nmode = \"hybrid\"\n", "hybrid_preferred"),
            ("[tls]\nclient_certificate = \"sometimes\"\n", "optional"),
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
            ("[upstream]\nhost = 1\n", "host"),
            ("[upstream\n", "TOML"),
        ] {
            let error = ConfigFile::parse(text).unwrap_err().to_string();
            assert!(error.contains(expected), "{text}: {error}");
        }
    }

    #[test]
    fn invalid_upstream_server_name_is_rejected() {
        let text =
            "[upstream]\nhost = \"proxy.example.test\"\nport = 443\nserver_name = \"not a name\"\n";
        let error = settings(text).unwrap_err().to_string();
        assert!(error.contains("server name"), "{error}");
    }

    #[test]
    fn overrides_take_precedence_field_by_field() {
        let file = ConfigFile::parse(FULL).unwrap();
        let overrides = ConfigFile {
            listen: Listen {
                address: Some("127.0.0.3:9000".parse().unwrap()),
            },
            upstream: UpstreamSection {
                port: NonZeroU16::new(9443),
                ..UpstreamSection::default()
            },
            tls: Tls {
                mode: Some(TlsMode::ClassicalOnly),
                ..Tls::default()
            },
            device_key: DeviceKey {
                software_fallback_on_first_create: Some(true),
                ..DeviceKey::default()
            },
            limits: LimitsSection {
                idle_timeout_seconds: NonZeroU64::new(5),
                ..LimitsSection::default()
            },
        };

        let settings = file.merge(overrides).settings().unwrap();

        assert_eq!(settings.listen, "127.0.0.3:9000".parse().unwrap());
        assert_eq!(settings.upstream.host, "proxy.example.test");
        assert_eq!(settings.upstream.port, 9443);
        assert_eq!(settings.upstream.server_name, "name.example.test");
        assert_eq!(settings.tls_mode, TlsMode::ClassicalOnly);
        assert_eq!(settings.client_certificate, ClientCertificateMode::Required);
        assert_eq!(settings.device_key.preferred, Backend::Software);
        assert!(settings.device_key.software_fallback_on_first_create);
        assert_eq!(settings.limits.idle_timeout_seconds, 5);
        assert_eq!(settings.limits.max_concurrent_tunnels, 8);
    }

    #[test]
    fn overrides_alone_can_supply_the_upstream() {
        let overrides = ConfigFile {
            upstream: UpstreamSection {
                host: Some("cli.example.test".to_owned()),
                port: NonZeroU16::new(443),
                ..UpstreamSection::default()
            },
            ..ConfigFile::default()
        };
        let settings = ConfigFile::default().merge(overrides).settings().unwrap();
        assert_eq!(settings.upstream.host, "cli.example.test");
        assert_eq!(settings.upstream.server_name, "cli.example.test");
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
        std::fs::write(
            &path,
            format!(
                "{MINIMAL}ca_file = \"certs/ca.pem\"\n[tls]\nclient_cert_file = \"/abs/client.pem\"\n"
            ),
        )
        .unwrap();

        let settings = ConfigFile::load(&path).unwrap().settings().unwrap();

        assert_eq!(settings.upstream.ca_file, Some(dir.join("certs/ca.pem")));
        assert_eq!(
            settings.client_cert_file,
            Some(PathBuf::from("/abs/client.pem"))
        );
    }

    #[test]
    fn load_errors_name_the_file() {
        let dir = temp_dir("errors");
        let missing = dir.join("missing.toml");
        let error = ConfigFile::load(&missing).unwrap_err().to_string();
        assert!(error.contains(&missing.display().to_string()), "{error}");

        let invalid = dir.join("invalid.toml");
        std::fs::write(&invalid, "[upstream]\nhostname = \"x\"\n").unwrap();
        let error = ConfigFile::load(&invalid).unwrap_err().to_string();
        assert!(error.contains(&invalid.display().to_string()), "{error}");
        assert!(error.contains("hostname"), "{error}");
    }

    #[test]
    fn example_file_parses() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.example.toml");
        let file = ConfigFile::load(&path).unwrap();
        let settings = file.settings().unwrap();
        assert!(settings.listen.ip().is_loopback());
        assert!(settings.upstream.host.ends_with(".invalid"), "{settings:?}");
        assert_eq!(settings.tls_mode, TlsMode::HybridPreferred);
        assert_eq!(settings.limits, LimitSettings::default());
        assert_eq!(settings.device_key, DeviceKeySettings::default());
    }
}
