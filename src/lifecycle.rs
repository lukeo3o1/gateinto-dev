use std::fmt;
use std::io::BufRead;
use std::path::{Path, PathBuf};

use crate::config::ConfigFile;
use crate::identity::device_key::{
    self, Backend, KeyName, KeyStore, PurgeError, PurgedKey, SpkiConfirmation,
};
use crate::link::store::LinkedStore;
use crate::link::{KnownGateway, Origin};
use crate::proxy::DEFAULT_LISTEN;
use crate::registration::{self, RegistrationError};

pub const ELEVATED_NOTE: &str = "note: running elevated. The device key is still created for \
     this Windows user, not for the machine; other users and services cannot use it";

pub fn service_account(sid: &str) -> Option<&'static str> {
    match sid {
        "S-1-5-18" => Some("LocalSystem"),
        "S-1-5-19" => Some("LocalService"),
        "S-1-5-20" => Some("NetworkService"),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAccount {
    pub name: &'static str,
    pub sid: String,
}

impl fmt::Display for ServiceAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "refusing to run as {} ({}): the device key belongs to the Windows user who uses \
             Gateinto, so run `gateinto setup` or `gateinto key init` as that user, not from \
             an installer, a service or a scheduled task running as a service account",
            self.name, self.sid
        )
    }
}

impl std::error::Error for ServiceAccount {}

pub fn check_account(sid: &str, elevated: bool) -> Result<Option<&'static str>, ServiceAccount> {
    if let Some(name) = service_account(sid) {
        return Err(ServiceAccount {
            name,
            sid: sid.to_owned(),
        });
    }
    Ok(elevated.then_some(ELEVATED_NOTE))
}

#[cfg(windows)]
pub fn check_current_account() -> Result<Option<&'static str>, Box<dyn std::error::Error>> {
    Ok(check_account(
        &crate::ipc::user_sid()?,
        windows::elevated()?,
    )?)
}

#[cfg(not(windows))]
pub fn check_current_account() -> Result<Option<&'static str>, Box<dyn std::error::Error>> {
    Ok(None)
}

#[cfg(windows)]
mod windows {
    use std::io;
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    pub fn elevated() -> io::Result<bool> {
        let mut token = null_mut();
        // SAFETY: GetCurrentProcess returns a pseudo handle; token receives an owned handle.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut len = 0;
        // SAFETY: elevation is a TOKEN_ELEVATION of the size passed; token is closed below.
        let queried = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                (&raw mut elevation).cast(),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut len,
            )
        };
        let error = io::Error::last_os_error();
        // SAFETY: token is an owned handle closed once.
        unsafe { CloseHandle(token) };
        if queried == 0 {
            return Err(error);
        }
        Ok(elevation.TokenIsElevated != 0)
    }
}

pub fn handler_state(registered: Result<Option<String>, RegistrationError>) -> String {
    match registered {
        Ok(None) => "not registered".to_owned(),
        Ok(Some(command)) if registration::is_handler_command(&command) => {
            format!("gateinto: {command}")
        }
        Ok(Some(command)) => format!("another program: {command}"),
        Err(RegistrationError::Unsupported) => "not supported on this platform".to_owned(),
        Err(error) => format!("unknown: {error}"),
    }
}

fn address_line(gateway: &KnownGateway) -> String {
    match (&gateway.host, gateway.port) {
        (Some(host), Some(port)) if host.contains(':') => {
            format!("{}: [{host}]:{port}", gateway.name)
        }
        (Some(host), Some(port)) => format!("{}: {host}:{port}", gateway.name),
        _ => format!("{}: no upstream host:port", gateway.name),
    }
}

pub fn gateway_lines(known: &[KnownGateway]) -> Vec<String> {
    known
        .iter()
        .map(|gateway| format!("{} ({})", address_line(gateway), gateway.source))
        .collect()
}

pub fn gateway_list(known: &[KnownGateway]) -> Vec<String> {
    known
        .iter()
        .map(|gateway| {
            let portal = match &gateway.portal_url {
                None => "none".to_owned(),
                Some(url) => Origin::of(url).map_or_else(
                    || "set, without a strict origin".to_owned(),
                    |o| o.to_string(),
                ),
            };
            format!(
                "{}, portal {portal} ({})",
                address_line(gateway),
                gateway.source
            )
        })
        .collect()
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Purge {
    pub config: Option<PathBuf>,
    pub linked: Vec<PathBuf>,
    pub linked_dir: Option<PathBuf>,
}

impl Purge {
    pub fn items(&self) -> Vec<String> {
        let mut items = Vec::new();
        if let Some(path) = &self.config {
            items.push(format!("the Gateinto config file {}", path.display()));
        }
        items.extend(self.linked_summary());
        items
    }

    pub fn linked_summary(&self) -> Option<String> {
        let dir = self.linked_dir.as_ref()?;
        let gateways = self
            .linked
            .iter()
            .filter(|path| path.to_string_lossy().ends_with(".toml"))
            .count();
        let temps = self.linked.len() - gateways;
        let temps_text = |count: usize| {
            let plural = if count == 1 { "file" } else { "files" };
            format!("{count} leftover temporary {plural}")
        };
        match (gateways, temps) {
            (0, 0) => None,
            (0, temps) => Some(format!("{} in {}", temps_text(temps), dir.display())),
            (gateways, temps) => {
                let what = match gateways {
                    1 => "the gateway".to_owned(),
                    count => format!("the {count} gateways"),
                };
                let mut text = format!("{what} added from links in {}", dir.display());
                if temps > 0 {
                    text.push_str(&format!(" (and {})", temps_text(temps)));
                }
                Some(text)
            }
        }
    }

    pub fn describe(&self) -> String {
        self.items()
            .iter()
            .map(|item| format!("and {item}.\n"))
            .collect()
    }
}

fn regular_file(path: &Path) -> Result<PathBuf, String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => std::path::absolute(path)
            .map_err(|error| format!("reading {}: {error}", path.display())),
        Ok(_) => Err(format!(
            "{} is not a regular file; --purge-config deletes only Gateinto files",
            path.display()
        )),
        Err(error) => Err(format!("reading {}: {error}", path.display())),
    }
}

pub fn files_to_purge(config: Option<&Path>, store: Option<&LinkedStore>) -> Result<Purge, String> {
    let config = match config {
        Some(path) => Some(regular_file(path)?),
        None => None,
    };
    let linked = match store {
        Some(store) => store
            .purge_candidates()
            .map_err(|error| error.to_string())?,
        None => Vec::new(),
    };
    let linked_dir = store
        .filter(|_| !linked.is_empty())
        .map(|store| store.dir().to_owned());
    Ok(Purge {
        config,
        linked,
        linked_dir,
    })
}

pub fn device_session_line(file: &ConfigFile) -> String {
    match &file.device_session.gateway {
        Some(gateway) => format!(
            "gateway {gateway}, listen {}",
            file.device_session.listen.unwrap_or(DEFAULT_LISTEN)
        ),
        None => "none".to_owned(),
    }
}

pub fn purge_warning(name: &KeyName, backend: Backend, fingerprint: &str, files: &Purge) -> String {
    let config = files.describe();
    format!(
        "This permanently deletes the Gateinto device key:\n\
         \x20 provider: {}\n\
         \x20 key name: {name} (current Windows user)\n\
         \x20 spki-sha256: {fingerprint}\n\
         {config}\
         \n\
         - The device identity becomes invalid. Gateways that enrolled this key will not \
         recognise the device; a new key may need to be enrolled again.\n\
         - Deleting the key locally does NOT revoke the device at any gateway. Ask the gateway \
         operator to revoke it.\n\
         - The key cannot be recovered. No other key, provider or TPM is changed.\n\
         - The gateinto:// handler stays registered; use the installer or \
         `gateinto uri unregister` to remove it.\n",
        backend.provider()
    )
}

pub fn confirm_from(input: &mut impl BufRead, fingerprint: &str) -> bool {
    let mut line = String::new();
    if input.read_line(&mut line).is_err() {
        return false;
    }
    line.trim()
        .parse::<SpkiConfirmation>()
        .is_ok_and(|confirmation| confirmation.matches(fingerprint))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResetError {
    Purge(PurgeError),
    StopAgent(String),
}

impl fmt::Display for ResetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Purge(error) => write!(f, "{error}"),
            Self::StopAgent(error) => write!(
                f,
                "stopping the running agent failed: {error}; nothing was deleted"
            ),
        }
    }
}

impl std::error::Error for ResetError {}

pub async fn purge_device_identity<S: KeyStore>(
    store: &S,
    name: &KeyName,
    confirmation: &SpkiConfirmation,
    stop_agent: impl Future<Output = Result<(), String>>,
) -> Result<PurgedKey, ResetError> {
    drop(device_key::confirmed(store, name, confirmation).map_err(ResetError::Purge)?);
    stop_agent.await.map_err(ResetError::StopAgent)?;
    device_key::purge(store, name, confirmation).map_err(ResetError::Purge)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::store::{self, LinkedStore};
    use crate::link::{self, LinkedGateway};

    #[test]
    fn service_accounts_are_recognised_by_sid() {
        assert_eq!(service_account("S-1-5-18"), Some("LocalSystem"));
        assert_eq!(service_account("S-1-5-19"), Some("LocalService"));
        assert_eq!(service_account("S-1-5-20"), Some("NetworkService"));
        for sid in ["S-1-5-21-1-2-3-1001", "S-1-5-180", "S-1-5-1", ""] {
            assert_eq!(service_account(sid), None, "{sid}");
        }
    }

    #[test]
    fn setup_refuses_service_accounts_and_notes_elevation() {
        let user = "S-1-5-21-1-2-3-1001";
        assert_eq!(check_account(user, false), Ok(None));
        assert_eq!(check_account(user, true), Ok(Some(ELEVATED_NOTE)));
        let error = check_account("S-1-5-18", true).unwrap_err();
        assert_eq!(
            error.to_string(),
            "refusing to run as LocalSystem (S-1-5-18): the device key belongs to the Windows \
             user who uses Gateinto, so run `gateinto setup` or `gateinto key init` as that \
             user, not from an installer, a service or a scheduled task running as a service \
             account"
        );
    }

    #[test]
    fn handler_states_say_whose_handler_is_registered() {
        let ours = r#""C:\Users\me\AppData\Local\Programs\Gateinto\gateinto.exe" open -- "%1""#;
        let foreign = r#""C:\Other\other.exe" "%1""#;
        assert_eq!(handler_state(Ok(None)), "not registered");
        assert_eq!(
            handler_state(Ok(Some(ours.to_owned()))),
            format!("gateinto: {ours}")
        );
        assert_eq!(
            handler_state(Ok(Some(foreign.to_owned()))),
            format!("another program: {foreign}")
        );
        assert_eq!(
            handler_state(Err(RegistrationError::Unsupported)),
            "not supported on this platform"
        );
        assert_eq!(
            handler_state(Err(RegistrationError::Registry {
                operation: "RegOpenKeyExW",
                code: 5
            })),
            "unknown: RegOpenKeyExW failed with Windows error 5"
        );
    }

    fn known_gateways() -> Vec<KnownGateway> {
        let file = ConfigFile::parse(
            "[device_session]\ngateway = \"office\"\n\
             [gateways.office]\nhost = \"proxy.example.com\"\nport = 443\nca_file = \"ca.pem\"\n\
             [gateways.lab]\nhost = \"10.0.0.1\"\nport = 8443\n\
             portal_url = \"https://portal.example.com/?token=secret\"\n\
             [gateways.broken]\nhost = \"x.example.com\"\n\
             [gateways.v6]\nhost = \"::1\"\nport = 443\n",
        )
        .unwrap();
        let linked = LinkedGateway {
            name: "newco".parse().unwrap(),
            address: "proxy.newco.example:8443".parse().unwrap(),
            portal_url: "https://portal.newco.example:444/home?secret=1"
                .parse()
                .unwrap(),
            approved_at: Some(1),
        };
        link::known_gateways(&file, &[linked])
    }

    #[test]
    fn gateways_are_listed_with_host_port_and_source_only() {
        assert_eq!(
            gateway_lines(&known_gateways()),
            vec![
                "broken: no upstream host:port (config)",
                "lab: 10.0.0.1:8443 (config)",
                "office: proxy.example.com:443 (config)",
                "v6: [::1]:443 (config)",
                "newco: proxy.newco.example:8443 (linked)",
            ]
        );
    }

    #[test]
    fn the_gateway_list_adds_the_portal_origin_without_its_path() {
        assert_eq!(
            gateway_list(&known_gateways()),
            vec![
                "broken: no upstream host:port, portal none (config)",
                "lab: 10.0.0.1:8443, portal https://portal.example.com (config)",
                "office: proxy.example.com:443, portal none (config)",
                "v6: [::1]:443, portal none (config)",
                "newco: proxy.newco.example:8443, portal https://portal.newco.example:444 (linked)",
            ]
        );
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("gateinto-lifecycle-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn purging_the_config_also_takes_the_gateway_files() {
        let dir = temp_dir("purge");
        let config = dir.join("gateinto.toml");
        let store = LinkedStore::new(dir.join(store::DIR_NAME));
        let missing = dir.join("missing.toml");
        std::fs::write(&config, "").unwrap();
        let config_only = Purge {
            config: Some(std::path::absolute(&config).unwrap()),
            ..Purge::default()
        };
        assert_eq!(
            files_to_purge(Some(&config), Some(&store)).unwrap(),
            config_only
        );
        assert_eq!(files_to_purge(Some(&config), None).unwrap(), config_only);
        std::fs::create_dir(store.dir()).unwrap();
        let gateway = store.dir().join("a.example.toml");
        std::fs::write(&gateway, "garbage").unwrap();
        std::fs::write(store.dir().join("notes.txt"), "").unwrap();
        let both = Purge {
            config: Some(std::path::absolute(&config).unwrap()),
            linked: vec![gateway.clone()],
            linked_dir: Some(store.dir().to_owned()),
        };
        assert_eq!(files_to_purge(Some(&config), Some(&store)).unwrap(), both);
        assert_eq!(
            files_to_purge(None, Some(&store)).unwrap(),
            Purge {
                config: None,
                ..both.clone()
            }
        );
        let error = files_to_purge(Some(&missing), Some(&store)).unwrap_err();
        assert!(error.contains("missing.toml"), "{error}");
        let error = files_to_purge(Some(store.dir()), None).unwrap_err();
        assert!(error.contains("not a regular file"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_device_session_line_names_the_gateway_and_listen_address() {
        let none = ConfigFile::default();
        assert_eq!(device_session_line(&none), "none");
        let file = ConfigFile::parse(
            "[device_session]\ngateway = \"office\"\nlisten = \"127.0.0.1:9000\"\n\
             [gateways.office]\nhost = \"proxy.example.com\"\nport = 443\n",
        )
        .unwrap();
        assert_eq!(
            device_session_line(&file),
            "gateway office, listen 127.0.0.1:9000"
        );
        let default_listen = ConfigFile::parse("[device_session]\ngateway = \"office\"\n").unwrap();
        assert_eq!(
            device_session_line(&default_listen),
            "gateway office, listen 127.0.0.1:18736"
        );
    }

    #[test]
    fn the_purge_warning_names_the_key_and_what_is_lost() {
        let fingerprint = "ab".repeat(32);
        let warning = purge_warning(
            &"gateinto-device-v1".parse().unwrap(),
            Backend::Software,
            &fingerprint,
            &Purge {
                config: Some(PathBuf::from("/home/me/gateinto.toml")),
                linked: vec![
                    PathBuf::from("/home/me/gateways/a.example.toml"),
                    PathBuf::from("/home/me/gateways/b.example.toml"),
                ],
                linked_dir: Some(PathBuf::from("/home/me/gateways")),
            },
        );
        assert_eq!(
            warning,
            format!(
                "This permanently deletes the Gateinto device key:\n\
                 \x20 provider: Microsoft Software Key Storage Provider\n\
                 \x20 key name: gateinto-device-v1 (current Windows user)\n\
                 \x20 spki-sha256: {fingerprint}\n\
                 and the Gateinto config file /home/me/gateinto.toml.\n\
                 and the 2 gateways added from links in /home/me/gateways.\n\
                 \n\
                 - The device identity becomes invalid. Gateways that enrolled this key will not \
                 recognise the device; a new key may need to be enrolled again.\n\
                 - Deleting the key locally does NOT revoke the device at any gateway. Ask the \
                 gateway operator to revoke it.\n\
                 - The key cannot be recovered. No other key, provider or TPM is changed.\n\
                 - The gateinto:// handler stays registered; use the installer or \
                 `gateinto uri unregister` to remove it.\n"
            )
        );
        let without_config = purge_warning(
            &"gateinto-device-v1".parse().unwrap(),
            Backend::Tpm,
            &fingerprint,
            &Purge::default(),
        );
        assert!(without_config.contains("provider: Microsoft Platform Crypto Provider\n"));
        assert!(without_config.contains(&format!("spki-sha256: {fingerprint}\n\n")));
        assert!(!without_config.contains("config file"));
        assert!(!without_config.contains("links"));
    }

    #[test]
    fn the_purge_counts_gateway_files_apart_from_leftover_temporary_files() {
        let dir = PathBuf::from("/home/me/gateways");
        let purge = |names: &[&str]| Purge {
            config: None,
            linked: names.iter().map(|name| dir.join(name)).collect(),
            linked_dir: Some(dir.clone()),
        };
        let temp = ".42.0123456789abcdef0123456789abcdef.tmp";
        for (names, expected) in [
            (
                vec!["a.example.toml", "b.example.toml", temp],
                "the 2 gateways added from links in /home/me/gateways (and 1 leftover \
                 temporary file)",
            ),
            (
                vec!["a.example.toml"],
                "the gateway added from links in /home/me/gateways",
            ),
            (
                vec![".toml", temp],
                "the gateway added from links in /home/me/gateways (and 1 leftover temporary \
                 file)",
            ),
            (
                vec![temp, temp],
                "2 leftover temporary files in /home/me/gateways",
            ),
        ] {
            assert_eq!(
                purge(&names).items(),
                vec![expected.to_owned()],
                "{names:?}"
            );
            assert_eq!(purge(&names).linked_summary().as_deref(), Some(expected));
        }
        assert_eq!(purge(&[]).items(), Vec::<String>::new());
        assert_eq!(purge(&[]).linked_summary(), None);
    }

    #[test]
    fn interactive_confirmation_needs_the_fingerprint_prefix() {
        let fingerprint = "0123456789abcdef".repeat(4);
        for (input, expected) in [
            ("0123456789abcdef\n", true),
            ("0123456789ABCDEF\r\n", true),
            (" 0123456789abcdef \n", true),
            (&format!("{fingerprint}\n"), true),
            ("0123456789abcde\n", false),
            ("1123456789abcdef\n", false),
            ("purge\n", false),
            ("yes\n", false),
            ("", false),
        ] {
            assert_eq!(
                confirm_from(&mut input.as_bytes(), &fingerprint),
                expected,
                "{input:?}"
            );
        }
    }
}
