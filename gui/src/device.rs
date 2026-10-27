use std::net::SocketAddr;

use gateinto::config::ConfigFile;
use gateinto::identity::UnsupportedPlatform;
use gateinto::identity::device_key::{self, Backend, KeyError, KeyName, KeyStore};
use gateinto::link::{Known, Source};
use gateinto::proxy::DEFAULT_LISTEN;

use crate::agent::AgentState;

pub const SUBTITLE: &str = "What gateways see when this PC signs in";
pub const STORAGE: &str = "Storage";
pub const DEVICE_ID: &str = "Device ID";
pub const USED_WITH: &str = "Used with";
pub const COPY_FAILED: &str = "Could not copy the device ID";
pub const VERSION: &str = match option_env!("GATEINTO_BUILD_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
    pub backend: Backend,
    pub name: KeyName,
    pub fingerprint: String,
    pub duplicate: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyState {
    Present(Key),
    Missing(KeyName),
    Unsupported(String),
    Failed(String),
}

pub fn key<S: KeyStore>(store: Result<S, UnsupportedPlatform>, name: &KeyName) -> KeyState {
    let store = match store {
        Ok(store) => store,
        Err(error) => return KeyState::Unsupported(error.to_string()),
    };
    match device_key::info(&store, name) {
        Ok((key, duplicate)) => KeyState::Present(Key {
            backend: key.backend,
            name: name.clone(),
            fingerprint: key.fingerprint(),
            duplicate: duplicate.is_some(),
        }),
        Err(KeyError::NotFound(name)) => KeyState::Missing(name),
        Err(error) => KeyState::Failed(error.to_string()),
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct System {
    pub computer: Option<String>,
    pub account: Option<String>,
    pub product: Option<String>,
    pub build: Option<u32>,
    pub arch: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Probe {
    pub key: KeyState,
    pub listen: Result<SocketAddr, String>,
    pub system: System,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyCard {
    pub title: &'static str,
    pub note: String,
    pub alert: bool,
    pub rows: Vec<(&'static str, String)>,
    pub copy: Option<&'static str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Computer {
    pub name: String,
    pub account: Option<String>,
    pub rows: Vec<(&'static str, String)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gateway {
    pub label: String,
    pub address: String,
    pub source: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page {
    pub subtitle: String,
    pub failed: bool,
    pub key: KeyCard,
    pub computer: Option<Computer>,
    pub gateways: Result<Vec<Gateway>, String>,
}

const PROVIDER_NOTE_TPM: &str = "Kept in this PC's TPM; the private key is hardware-protected";
const PROVIDER_NOTE_SOFTWARE: &str =
    "Kept in software; not protected against copying by an administrator or malware";
const DUPLICATE: &str = "A software key has the same name; gateways see the TPM key shown here";
const MISSING: &str = "No device key yet. Run `gateinto setup` to create one.";
const READING: &str = "Reading the device key\u{2026}";
const HARDWARE_KEY: &str = "Hardware key";
const DEVICE_KEY: &str = "Device key";
const KEY_NAME: &str = "Key name";
const COPY: &str = "Copy device ID";
const COPIED: &str = "Copied";
const THIS_PC: &str = "This PC";
const LOOPBACK: &str = "Loopback only";
const FIRST_WINDOWS_11_BUILD: u32 = 22000;

fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or_default().to_owned()
}

fn edition(product: &str, build: Option<u32>) -> String {
    match product.strip_prefix("Windows 10") {
        Some(rest) if build.is_some_and(|build| build >= FIRST_WINDOWS_11_BUILD) => {
            format!("Windows 11{rest}")
        }
        _ => product.to_owned(),
    }
}

fn architecture(code: u16) -> Option<&'static str> {
    match code {
        0 => Some("x86"),
        5 => Some("ARM"),
        9 => Some("x64"),
        12 => Some("ARM64"),
        _ => None,
    }
}

pub fn os(system: &System) -> Option<String> {
    let parts: Vec<String> = [
        system
            .product
            .as_deref()
            .map(|product| edition(product, system.build)),
        system.arch.and_then(architecture).map(str::to_owned),
    ]
    .into_iter()
    .flatten()
    .collect();
    (!parts.is_empty()).then(|| parts.join(" \u{b7} "))
}

pub fn exposure(listen: &Result<SocketAddr, String>, state: &AgentState) -> String {
    let listen = match listen {
        Ok(listen) => *listen,
        Err(error) => return format!("Unknown: {}", first_line(error)),
    };
    let sessions = match state {
        AgentState::Running(sessions) => sessions.as_slice(),
        AgentState::Stopped | AgentState::Unreachable(_) => &[],
    };
    std::iter::once(listen)
        .chain(sessions.iter().map(|session| session.listen))
        .find(|addr| !addr.ip().to_canonical().is_loopback())
        .map_or_else(
            || LOOPBACK.to_owned(),
            |addr| format!("Open to the network on {addr}"),
        )
}

pub fn device_id(probe: Option<&Probe>) -> Option<&str> {
    match probe.map(|probe| &probe.key) {
        Some(KeyState::Present(key)) => Some(&key.fingerprint),
        _ => None,
    }
}

fn storage(backend: Backend) -> String {
    let kind = match backend {
        Backend::Tpm => "TPM",
        Backend::Software => "Software",
    };
    format!("{kind} ({})", backend.provider())
}

fn key_card(key: Option<&KeyState>, copied: bool) -> KeyCard {
    let card = |note: String, alert, rows| KeyCard {
        title: DEVICE_KEY,
        note,
        alert,
        rows,
        copy: None,
    };
    match key {
        None => card(READING.to_owned(), false, Vec::new()),
        Some(KeyState::Present(key)) => {
            let tpm = key.backend == Backend::Tpm;
            let note = match (tpm, key.duplicate) {
                (_, true) => DUPLICATE,
                (true, false) => PROVIDER_NOTE_TPM,
                (false, false) => PROVIDER_NOTE_SOFTWARE,
            };
            KeyCard {
                title: if tpm { HARDWARE_KEY } else { DEVICE_KEY },
                note: note.to_owned(),
                alert: key.duplicate || !tpm,
                rows: vec![
                    (STORAGE, storage(key.backend)),
                    ("Algorithm", device_key::ALGORITHM.to_owned()),
                    (KEY_NAME, key.name.to_string()),
                    (DEVICE_ID, key.fingerprint.clone()),
                ],
                copy: Some(if copied { COPIED } else { COPY }),
            }
        }
        Some(KeyState::Missing(name)) => {
            card(MISSING.to_owned(), true, vec![(KEY_NAME, name.to_string())])
        }
        Some(KeyState::Unsupported(error) | KeyState::Failed(error)) => {
            card(first_line(error), true, Vec::new())
        }
    }
}

fn computer(probe: &Probe, state: &AgentState) -> Computer {
    let system = &probe.system;
    let rows = os(system)
        .map(|os| ("System", os))
        .into_iter()
        .chain([
            ("Gateinto", VERSION.to_owned()),
            ("Agent", exposure(&probe.listen, state)),
        ])
        .collect();
    Computer {
        name: system
            .computer
            .clone()
            .unwrap_or_else(|| THIS_PC.to_owned()),
        account: system
            .account
            .as_ref()
            .map(|account| format!("Signed in as {account}")),
        rows,
    }
}

fn gateways(listing: &Result<Known, String>) -> Result<Vec<Gateway>, String> {
    let known = listing.as_ref().map_err(|error| first_line(error))?;
    Ok(known
        .gateways
        .iter()
        .map(|gateway| Gateway {
            label: crate::gateways::label(gateway),
            address: crate::gateways::address(gateway.host.as_deref(), gateway.port),
            source: match gateway.source {
                Source::Config => "Config file",
                Source::Linked => "Linked",
            },
        })
        .collect())
}

pub fn probe<S: KeyStore>(
    file: &Result<ConfigFile, String>,
    store: impl FnOnce() -> Result<S, UnsupportedPlatform>,
    system: System,
) -> Probe {
    let (key, listen) = match file {
        Ok(file) => (
            key(store(), &file.device_key.settings().name),
            Ok(file.device_session.listen.unwrap_or(DEFAULT_LISTEN)),
        ),
        Err(error) => (KeyState::Failed(error.clone()), Err(error.clone())),
    };
    Probe {
        key,
        listen,
        system,
    }
}

pub fn page(
    probe: Option<&Probe>,
    state: &AgentState,
    listing: &Result<Known, String>,
    failure: Option<&str>,
    copied: bool,
) -> Page {
    Page {
        subtitle: failure.unwrap_or(SUBTITLE).to_owned(),
        failed: failure.is_some(),
        key: key_card(probe.map(|probe| &probe.key), copied),
        computer: probe.map(|probe| computer(probe, state)),
        gateways: gateways(listing),
    }
}

#[cfg(test)]
mod tests {
    use gateinto::config::GatewayName;
    use gateinto::identity::device_key::StoreError;
    use gateinto::identity::encoding::{P256Point, p256_spki_der, sha256_fingerprint};
    use gateinto::ipc::{SessionAuth, SessionInfo, SessionKind, SessionRoute};
    use gateinto::link::KnownGateway;

    use super::*;

    struct Store {
        tpm: Result<P256Point, StoreError>,
        software: Result<P256Point, StoreError>,
    }

    impl Store {
        fn slot(&self, backend: Backend) -> &Result<P256Point, StoreError> {
            match backend {
                Backend::Tpm => &self.tpm,
                Backend::Software => &self.software,
            }
        }
    }

    impl KeyStore for Store {
        type Key = Backend;

        fn open(&self, backend: Backend, _: &KeyName) -> Result<Backend, StoreError> {
            self.slot(backend)
                .as_ref()
                .map(|_| backend)
                .map_err(Clone::clone)
        }

        fn create(&self, _: Backend, _: &KeyName) -> Result<Backend, StoreError> {
            panic!("created a device key")
        }

        fn delete(&self, _: Backend) -> Result<(), StoreError> {
            panic!("deleted a device key")
        }

        fn public_point(&self, key: &Backend) -> Result<P256Point, StoreError> {
            self.slot(*key).clone()
        }

        fn sign_digest(&self, _: &Backend, _: &[u8]) -> Result<Vec<u8>, StoreError> {
            panic!("signed with the device key")
        }
    }

    fn point(byte: u8) -> P256Point {
        let mut point = [byte; 65];
        point[0] = 4;
        point
    }

    fn id(byte: u8) -> String {
        sha256_fingerprint(&p256_spki_der(&point(byte)))
    }

    fn store(
        tpm: Result<P256Point, StoreError>,
        software: Result<P256Point, StoreError>,
    ) -> Result<Store, UnsupportedPlatform> {
        Ok(Store { tpm, software })
    }

    fn present(backend: Backend, fingerprint: String, duplicate: bool) -> KeyState {
        KeyState::Present(Key {
            backend,
            name: KeyName::default(),
            fingerprint,
            duplicate,
        })
    }

    #[test]
    fn a_tpm_key_is_read_with_its_spki_fingerprint() {
        let state = key(
            store(Ok(point(1)), Err(StoreError::NotFound)),
            &KeyName::default(),
        );
        assert_eq!(state, present(Backend::Tpm, id(1), false));
    }

    #[test]
    fn a_software_key_is_reported_as_software() {
        let unavailable = Err(StoreError::ProviderUnavailable("no tpm".to_owned()));
        let state = key(store(unavailable, Ok(point(2))), &KeyName::default());
        assert_eq!(state, present(Backend::Software, id(2), false));
    }

    #[test]
    fn keys_in_both_providers_show_the_tpm_one_and_flag_the_duplicate() {
        let state = key(store(Ok(point(1)), Ok(point(2))), &KeyName::default());
        assert_eq!(state, present(Backend::Tpm, id(1), true));
    }

    #[test]
    fn no_key_is_missing_and_nothing_is_created() {
        let name: KeyName = "work".parse().unwrap();
        let state = key(
            store(Err(StoreError::NotFound), Err(StoreError::NotFound)),
            &name,
        );
        assert_eq!(state, KeyState::Missing(name));
    }

    #[test]
    fn a_store_error_is_a_failure() {
        let broken = Err(StoreError::Failed("access denied".to_owned()));
        let state = key(
            store(broken, Err(StoreError::NotFound)),
            &KeyName::default(),
        );
        assert_eq!(
            state,
            KeyState::Failed(
                "opening the existing tpm device key failed: access denied; no new key was created"
                    .to_owned()
            )
        );
    }

    #[test]
    fn another_platform_has_no_device_key() {
        let state = key::<Store>(Err(UnsupportedPlatform), &KeyName::default());
        assert_eq!(
            state,
            KeyState::Unsupported("device keys are only supported on Windows".to_owned())
        );
    }

    fn system() -> System {
        System {
            computer: Some("DESK-7".to_owned()),
            account: Some("CORP\\ana".to_owned()),
            product: Some("Windows 10 Pro".to_owned()),
            build: Some(26100),
            arch: Some(9),
        }
    }

    #[test]
    fn the_system_line_names_the_edition_and_architecture() {
        assert_eq!(os(&system()).as_deref(), Some("Windows 11 Pro \u{b7} x64"));
        let ten = System {
            build: Some(19045),
            arch: Some(12),
            ..system()
        };
        assert_eq!(os(&ten).as_deref(), Some("Windows 10 Pro \u{b7} ARM64"));
        let x86 = System {
            arch: Some(0),
            build: None,
            ..system()
        };
        assert_eq!(os(&x86).as_deref(), Some("Windows 10 Pro \u{b7} x86"));
    }

    #[test]
    fn only_windows_10_names_are_corrected_on_a_windows_11_build() {
        let server = System {
            product: Some("Windows Server 2025 Datacenter".to_owned()),
            ..system()
        };
        assert_eq!(
            os(&server).as_deref(),
            Some("Windows Server 2025 Datacenter \u{b7} x64")
        );
    }

    #[test]
    fn unknown_parts_of_the_system_line_are_left_out() {
        let odd = System {
            arch: Some(77),
            ..system()
        };
        assert_eq!(os(&odd).as_deref(), Some("Windows 11 Pro"));
        let bare = System {
            product: None,
            ..system()
        };
        assert_eq!(os(&bare).as_deref(), Some("x64"));
        assert_eq!(os(&System::default()), None);
    }

    fn session(listen: &str) -> SessionInfo {
        SessionInfo {
            id: 1,
            kind: SessionKind::Browser,
            gateway: "office".to_owned(),
            upstream: "proxy.example.com:443".to_owned(),
            listen: listen.parse().unwrap(),
            route: SessionRoute::All,
            auth: SessionAuth::OsUser,
            started: 0,
            tunnels: 0,
            browser: None,
        }
    }

    fn listen(addr: &str) -> Result<SocketAddr, String> {
        Ok(addr.parse().unwrap())
    }

    #[test]
    fn a_loopback_listen_and_loopback_sessions_are_loopback_only() {
        let running = AgentState::Running(vec![session("127.0.0.1:50100"), session("[::1]:9")]);
        assert_eq!(
            exposure(&listen("127.0.0.1:18736"), &running),
            "Loopback only"
        );
        assert_eq!(
            exposure(&listen("[::1]:18736"), &AgentState::Stopped),
            "Loopback only"
        );
    }

    #[test]
    fn a_network_listen_in_the_config_or_a_session_is_called_out() {
        assert_eq!(
            exposure(&listen("0.0.0.0:18736"), &AgentState::Stopped),
            "Open to the network on 0.0.0.0:18736"
        );
        let running = AgentState::Running(vec![session("192.168.1.5:8080")]);
        assert_eq!(
            exposure(&listen("127.0.0.1:18736"), &running),
            "Open to the network on 192.168.1.5:8080"
        );
    }

    #[test]
    fn an_ipv6_wildcard_listen_is_open_to_the_network() {
        assert_eq!(
            exposure(&listen("[::]:18736"), &AgentState::Stopped),
            "Open to the network on [::]:18736"
        );
    }

    #[test]
    fn an_ipv4_mapped_loopback_listen_is_loopback_only() {
        assert_eq!(
            exposure(&listen("[::ffff:127.0.0.1]:18736"), &AgentState::Stopped),
            "Loopback only"
        );
        assert_eq!(
            exposure(&listen("[::ffff:10.0.0.2]:18736"), &AgentState::Stopped),
            "Open to the network on [::ffff:10.0.0.2]:18736"
        );
    }

    #[test]
    fn an_unreadable_listen_setting_is_not_reported_as_loopback() {
        let broken = Err("config file c.toml: expected `=`\n  |".to_owned());
        assert_eq!(
            exposure(&broken, &AgentState::Stopped),
            "Unknown: config file c.toml: expected `=`"
        );
    }

    fn probed(key: KeyState) -> Probe {
        Probe {
            key,
            listen: listen("127.0.0.1:18736"),
            system: system(),
        }
    }

    fn tpm() -> KeyState {
        present(Backend::Tpm, id(1), false)
    }

    fn known(gateways: Vec<KnownGateway>) -> Result<Known, String> {
        Ok(Known {
            gateways,
            ..Known::default()
        })
    }

    fn draw(probe: Option<&Probe>) -> Page {
        page(probe, &AgentState::Stopped, &known(Vec::new()), None, false)
    }

    #[test]
    fn a_tpm_key_is_a_hardware_key_with_its_device_id() {
        let probe = probed(tpm());
        assert_eq!(
            draw(Some(&probe)).key,
            KeyCard {
                title: "Hardware key",
                note: "Kept in this PC's TPM; the private key is hardware-protected".to_owned(),
                alert: false,
                rows: vec![
                    (
                        STORAGE,
                        "TPM (Microsoft Platform Crypto Provider)".to_owned()
                    ),
                    ("Algorithm", "ECDSA P-256".to_owned()),
                    ("Key name", "gateinto-device-v1".to_owned()),
                    (DEVICE_ID, id(1)),
                ],
                copy: Some("Copy device ID"),
            }
        );
        assert_eq!(device_id(Some(&probe)), Some(id(1).as_str()));
    }

    #[test]
    fn a_software_key_is_never_called_a_hardware_key() {
        let probe = probed(present(Backend::Software, id(2), false));
        let card = draw(Some(&probe)).key;
        assert_eq!(card.title, "Device key");
        assert_eq!(
            card.note,
            "Kept in software; not protected against copying by an administrator or malware"
        );
        assert!(card.alert);
        assert_eq!(
            card.rows[0],
            (
                STORAGE,
                "Software (Microsoft Software Key Storage Provider)".to_owned()
            )
        );
        assert!(card.rows.iter().all(|(_, value)| !value.contains("TPM")));
        assert_eq!(card.rows[3], (DEVICE_ID, id(2)));
    }

    #[test]
    fn a_duplicate_key_says_gateways_see_the_tpm_key() {
        let probe = probed(present(Backend::Tpm, id(1), true));
        let card = draw(Some(&probe)).key;
        assert_eq!(
            card.note,
            "A software key has the same name; gateways see the TPM key shown here"
        );
        assert!(card.alert);
    }

    #[test]
    fn copying_turns_the_button_into_a_confirmation() {
        let probe = probed(tpm());
        let page = page(
            Some(&probe),
            &AgentState::Stopped,
            &known(Vec::new()),
            None,
            true,
        );
        assert_eq!(page.key.copy, Some("Copied"));
    }

    #[test]
    fn a_missing_key_says_how_to_create_one_without_offering_to() {
        let probe = probed(KeyState::Missing("work".parse().unwrap()));
        let card = draw(Some(&probe)).key;
        assert_eq!(
            card,
            KeyCard {
                title: "Device key",
                note: "No device key yet. Run `gateinto setup` to create one.".to_owned(),
                alert: true,
                rows: vec![("Key name", "work".to_owned())],
                copy: None,
            }
        );
        assert_eq!(device_id(Some(&probe)), None);
    }

    #[test]
    fn an_unreadable_or_unsupported_key_shows_why() {
        let failed = probed(KeyState::Failed("opening failed: denied\nmore".to_owned()));
        let card = draw(Some(&failed)).key;
        assert_eq!(
            (card.title, card.note.as_str(), card.alert, card.copy),
            ("Device key", "opening failed: denied", true, None)
        );
        assert!(card.rows.is_empty());
        let other = probed(KeyState::Unsupported("only on Windows".to_owned()));
        assert_eq!(draw(Some(&other)).key.note, "only on Windows");
    }

    #[test]
    fn before_the_first_probe_only_the_key_card_waits() {
        let page = draw(None);
        assert_eq!(page.subtitle, SUBTITLE);
        assert_eq!(
            page.key,
            KeyCard {
                title: "Device key",
                note: "Reading the device key\u{2026}".to_owned(),
                alert: false,
                rows: Vec::new(),
                copy: None,
            }
        );
        assert_eq!(page.computer, None);
        assert_eq!(device_id(None), None);
    }

    #[test]
    fn the_computer_card_shows_who_is_signed_in_and_how_the_agent_listens() {
        let probe = probed(tpm());
        assert_eq!(
            draw(Some(&probe)).computer,
            Some(Computer {
                name: "DESK-7".to_owned(),
                account: Some("Signed in as CORP\\ana".to_owned()),
                rows: vec![
                    ("System", "Windows 11 Pro \u{b7} x64".to_owned()),
                    ("Gateinto", VERSION.to_owned()),
                    ("Agent", "Loopback only".to_owned()),
                ],
            })
        );
    }

    #[test]
    fn unknown_computer_details_are_dropped_rather_than_guessed() {
        let probe = Probe {
            system: System::default(),
            ..probed(tpm())
        };
        let computer = draw(Some(&probe)).computer.unwrap();
        assert_eq!(computer.name, "This PC");
        assert_eq!(computer.account, None);
        assert_eq!(computer.rows[0], ("Gateinto", VERSION.to_owned()));
        assert_eq!(computer.rows.len(), 2);
    }

    #[test]
    fn the_agent_row_follows_the_running_sessions() {
        let probe = probed(tpm());
        let running = AgentState::Running(vec![session("0.0.0.0:8080")]);
        let page = page(Some(&probe), &running, &known(Vec::new()), None, false);
        assert_eq!(
            page.computer.unwrap().rows[2],
            ("Agent", "Open to the network on 0.0.0.0:8080".to_owned())
        );
    }

    fn gateway(name: &str, host: &str, port: u16, source: Source) -> KnownGateway {
        KnownGateway {
            name: name.parse::<GatewayName>().unwrap(),
            host: Some(host.to_owned()),
            port: Some(port),
            portal_url: None,
            source,
        }
    }

    #[test]
    fn gateways_list_their_address_and_where_they_come_from() {
        let listing = known(vec![
            gateway("office", "proxy.example.com", 443, Source::Config),
            gateway("lab", "lab.example", 8443, Source::Linked),
        ]);
        let page = page(None, &AgentState::Stopped, &listing, None, false);
        assert_eq!(
            page.gateways,
            Ok(vec![
                Gateway {
                    label: "office".to_owned(),
                    address: "proxy.example.com".to_owned(),
                    source: "Config file",
                },
                Gateway {
                    label: "lab".to_owned(),
                    address: "lab.example:8443".to_owned(),
                    source: "Linked",
                },
            ])
        );
    }

    #[test]
    fn a_broken_gateway_listing_shows_its_first_line() {
        let listing = Err("config file c.toml: bad\n  |".to_owned());
        let page = page(None, &AgentState::Stopped, &listing, None, false);
        assert_eq!(page.gateways, Err("config file c.toml: bad".to_owned()));
    }

    #[test]
    fn a_failure_replaces_the_subtitle() {
        let page = page(
            None,
            &AgentState::Stopped,
            &known(Vec::new()),
            Some("Could not copy the device ID"),
            false,
        );
        assert_eq!(
            (page.subtitle.as_str(), page.failed),
            ("Could not copy the device ID", true)
        );
        assert!(!draw(None).failed);
    }

    #[test]
    fn a_probe_reads_the_configured_key_name_and_listen_address() {
        let file = ConfigFile::parse(
            "[device_key]\nname = \"work\"\n[device_session]\nlisten = \"0.0.0.0:9000\"\n",
        )
        .map_err(|error| error.to_string());
        let found = probe(
            &file,
            || store(Err(StoreError::NotFound), Err(StoreError::NotFound)),
            system(),
        );
        assert_eq!(
            found,
            Probe {
                key: KeyState::Missing("work".parse().unwrap()),
                listen: listen("0.0.0.0:9000"),
                system: system(),
            }
        );
    }

    #[test]
    fn a_probe_without_settings_uses_the_default_key_and_listen_address() {
        let found = probe(
            &Ok(ConfigFile::default()),
            || store(Ok(point(1)), Err(StoreError::NotFound)),
            System::default(),
        );
        assert_eq!(found.key, tpm());
        assert_eq!(found.listen, Ok(gateinto::proxy::DEFAULT_LISTEN));
    }

    #[test]
    fn a_broken_config_opens_no_key() {
        let broken = Err("config file c.toml: bad".to_owned());
        let found = probe::<Store>(&broken, || panic!("opened the key store"), system());
        assert_eq!(
            found.key,
            KeyState::Failed("config file c.toml: bad".to_owned())
        );
        assert_eq!(found.listen, broken.map(|_| unreachable!()));
    }
}
