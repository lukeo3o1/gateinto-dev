use gateinto::config::ConfigFile;
use gateinto::identity::UnsupportedPlatform;
use gateinto::identity::device_key::{self, Backend, KeyError, KeyName, KeyStore};
use gateinto::link::{Known, Source};

use crate::i18n::{Text, fill, tr};

pub const SUBTITLE: Text = Text::DeviceSubtitle;
pub const STORAGE: Text = Text::Storage;
pub const DEVICE_ID: Text = Text::DeviceId;
pub const USED_WITH: Text = Text::UsedWith;
pub const COPY_FAILED: Text = Text::CopyDeviceIdFailed;
pub const VERSION: &str = match option_env!("GATEINTO_BUILD_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
    pub backend: Backend,
    pub name: KeyName,
    pub fingerprint: String,
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
        Ok((key, _)) => KeyState::Present(Key {
            backend: key.backend,
            name: name.clone(),
            fingerprint: key.fingerprint(),
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
    pub system: System,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyCard {
    pub title: &'static str,
    pub note: Option<String>,
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

const MISSING: Text = Text::NoDeviceKey;
const READING: Text = Text::ReadingDeviceKey;
const HARDWARE_KEY: Text = Text::HardwareKey;
const DEVICE_KEY: Text = Text::DeviceKey;
const KEY_NAME: Text = Text::KeyName;
const COPY: Text = Text::CopyDeviceId;
const COPIED: Text = Text::Copied;
const THIS_PC: Text = Text::ThisPc;
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

pub fn device_id(probe: Option<&Probe>) -> Option<&str> {
    match probe.map(|probe| &probe.key) {
        Some(KeyState::Present(key)) => Some(&key.fingerprint),
        _ => None,
    }
}

fn storage(backend: Backend) -> String {
    let kind = match backend {
        Backend::Tpm => "TPM",
        Backend::Software => tr(Text::Software),
    };
    format!("{kind} ({})", backend.provider())
}

fn key_card(key: Option<&KeyState>, copied: bool) -> KeyCard {
    let card = |note: String, alert, rows| KeyCard {
        title: tr(DEVICE_KEY),
        note: Some(note),
        alert,
        rows,
        copy: None,
    };
    match key {
        None => card(tr(READING).to_owned(), false, Vec::new()),
        Some(KeyState::Present(key)) => {
            let tpm = key.backend == Backend::Tpm;
            KeyCard {
                title: tr(if tpm { HARDWARE_KEY } else { DEVICE_KEY }),
                note: None,
                alert: false,
                rows: vec![
                    (tr(STORAGE), storage(key.backend)),
                    (tr(Text::Algorithm), device_key::ALGORITHM.to_owned()),
                    (tr(KEY_NAME), key.name.to_string()),
                    (tr(DEVICE_ID), key.fingerprint.clone()),
                ],
                copy: Some(tr(if copied { COPIED } else { COPY })),
            }
        }
        Some(KeyState::Missing(name)) => card(
            tr(MISSING).to_owned(),
            true,
            vec![(tr(KEY_NAME), name.to_string())],
        ),
        Some(KeyState::Unsupported(error) | KeyState::Failed(error)) => {
            card(first_line(error), true, Vec::new())
        }
    }
}

fn computer(probe: &Probe) -> Computer {
    let system = &probe.system;
    let rows = os(system)
        .map(|os| (tr(Text::System), os))
        .into_iter()
        .chain([("Gateinto", VERSION.to_owned())])
        .collect();
    Computer {
        name: system
            .computer
            .clone()
            .unwrap_or_else(|| tr(THIS_PC).to_owned()),
        account: system
            .account
            .as_ref()
            .map(|account| fill(Text::SignedInAs, &[account])),
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
            source: tr(match gateway.source {
                Source::Config => Text::ConfigFile,
                Source::Linked => Text::AddedHere,
            }),
        })
        .collect())
}

pub fn probe<S: KeyStore>(
    file: &Result<ConfigFile, String>,
    store: impl FnOnce() -> Result<S, UnsupportedPlatform>,
    system: System,
) -> Probe {
    let key = match file {
        Ok(file) => key(store(), &file.device_key.settings().name),
        Err(error) => KeyState::Failed(error.clone()),
    };
    Probe { key, system }
}

pub fn page(
    probe: Option<&Probe>,
    listing: &Result<Known, String>,
    failure: Option<&str>,
    copied: bool,
) -> Page {
    Page {
        subtitle: failure.unwrap_or(tr(SUBTITLE)).to_owned(),
        failed: failure.is_some(),
        key: key_card(probe.map(|probe| &probe.key), copied),
        computer: probe.map(computer),
        gateways: gateways(listing),
    }
}

#[cfg(test)]
mod tests {
    use gateinto::config::GatewayName;
    use gateinto::identity::device_key::StoreError;
    use gateinto::identity::encoding::{P256Point, p256_spki_der, sha256_fingerprint};
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

    fn present(backend: Backend, fingerprint: String) -> KeyState {
        KeyState::Present(Key {
            backend,
            name: KeyName::default(),
            fingerprint,
        })
    }

    #[test]
    fn a_tpm_key_is_read_with_its_spki_fingerprint() {
        let state = key(
            store(Ok(point(1)), Err(StoreError::NotFound)),
            &KeyName::default(),
        );
        assert_eq!(state, present(Backend::Tpm, id(1)));
    }

    #[test]
    fn a_software_key_is_reported_as_software() {
        let unavailable = Err(StoreError::ProviderUnavailable("no tpm".to_owned()));
        let state = key(store(unavailable, Ok(point(2))), &KeyName::default());
        assert_eq!(state, present(Backend::Software, id(2)));
    }

    #[test]
    fn keys_in_both_providers_show_the_tpm_one() {
        let state = key(store(Ok(point(1)), Ok(point(2))), &KeyName::default());
        assert_eq!(state, present(Backend::Tpm, id(1)));
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

    fn probed(key: KeyState) -> Probe {
        Probe {
            key,
            system: system(),
        }
    }

    fn tpm() -> KeyState {
        present(Backend::Tpm, id(1))
    }

    fn known(gateways: Vec<KnownGateway>) -> Result<Known, String> {
        Ok(Known {
            gateways,
            ..Known::default()
        })
    }

    fn draw(probe: Option<&Probe>) -> Page {
        page(probe, &known(Vec::new()), None, false)
    }

    #[test]
    fn the_device_page_speaks_chinese() {
        let _zh = crate::i18n::speaking(crate::i18n::Language::Chinese);
        let probe = probed(present(Backend::Software, id(2)));
        let page = page(
            Some(&probe),
            &known(vec![KnownGateway {
                name: "office".parse::<GatewayName>().unwrap(),
                host: Some("proxy.example.com".to_owned()),
                port: None,
                portal_url: None,
                source: Source::Linked,
            }]),
            None,
            true,
        );
        assert_eq!(page.subtitle, "這部電腦登入時閘道看到的資訊");
        let card = page.key;
        assert_eq!(card.title, "裝置金鑰");
        let keys: Vec<&str> = card.rows.iter().map(|(k, _)| *k).collect();
        assert_eq!(keys, ["儲存位置", "演算法", "金鑰名稱", "裝置識別碼"]);
        assert_eq!(
            card.rows[0].1,
            "軟體 (Microsoft Software Key Storage Provider)"
        );
        assert_eq!(card.copy, Some("已複製"));
        let computer = page.computer.unwrap();
        assert_eq!(computer.account.as_deref(), Some("登入身分：CORP\\ana"));
        assert_eq!(
            computer.rows,
            [
                ("系統", "Windows 11 Pro \u{b7} x64".to_owned()),
                ("Gateinto", VERSION.to_owned()),
            ]
        );
        assert_eq!(page.gateways.unwrap()[0].source, "在這部裝置上新增");
        assert_eq!(draw(None).key.note.as_deref(), Some("正在讀取裝置金鑰…"));
        assert_eq!(draw(Some(&probed(tpm()))).key.title, "硬體金鑰");
        assert_eq!(draw(Some(&probed(tpm()))).key.copy, Some("複製裝置識別碼"));
        let missing = draw(Some(&probed(KeyState::Missing(KeyName::default()))));
        assert_eq!(
            missing.key.note.as_deref(),
            Some("尚無裝置金鑰。請執行 `gateinto setup` 建立。")
        );
        let nameless = Probe {
            key: tpm(),
            system: System::default(),
        };
        assert_eq!(draw(Some(&nameless)).computer.unwrap().name, "這部電腦");
    }

    #[test]
    fn a_tpm_key_is_a_hardware_key_with_its_device_id() {
        let probe = probed(tpm());
        assert_eq!(
            draw(Some(&probe)).key,
            KeyCard {
                title: "Hardware key",
                note: None,
                alert: false,
                rows: vec![
                    (
                        tr(STORAGE),
                        "TPM (Microsoft Platform Crypto Provider)".to_owned()
                    ),
                    ("Algorithm", "ECDSA P-256".to_owned()),
                    ("Key name", "gateinto-device-v1".to_owned()),
                    (tr(DEVICE_ID), id(1)),
                ],
                copy: Some("Copy device ID"),
            }
        );
        assert_eq!(device_id(Some(&probe)), Some(id(1).as_str()));
    }

    #[test]
    fn a_software_key_is_never_called_a_hardware_key() {
        let probe = probed(present(Backend::Software, id(2)));
        let card = draw(Some(&probe)).key;
        assert_eq!(card.title, "Device key");
        assert_eq!(card.note, None);
        assert_eq!(
            card.rows[0],
            (
                tr(STORAGE),
                "Software (Microsoft Software Key Storage Provider)".to_owned()
            )
        );
        assert!(card.rows.iter().all(|(_, value)| !value.contains("TPM")));
        assert_eq!(card.rows[3], (tr(DEVICE_ID), id(2)));
    }

    #[test]
    fn copying_turns_the_button_into_a_confirmation() {
        let probe = probed(tpm());
        let page = page(Some(&probe), &known(Vec::new()), None, true);
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
                note: Some("No device key yet. Run `gateinto setup` to create one.".to_owned()),
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
            (card.title, card.note.as_deref(), card.alert, card.copy),
            ("Device key", Some("opening failed: denied"), true, None)
        );
        assert!(card.rows.is_empty());
        let other = probed(KeyState::Unsupported("only on Windows".to_owned()));
        assert_eq!(
            draw(Some(&other)).key.note.as_deref(),
            Some("only on Windows")
        );
    }

    #[test]
    fn before_the_first_probe_only_the_key_card_waits() {
        let page = draw(None);
        assert_eq!(page.subtitle, tr(SUBTITLE));
        assert_eq!(
            page.key,
            KeyCard {
                title: "Device key",
                note: Some("Reading the device key\u{2026}".to_owned()),
                alert: false,
                rows: Vec::new(),
                copy: None,
            }
        );
        assert_eq!(page.computer, None);
        assert_eq!(device_id(None), None);
    }

    #[test]
    fn the_computer_card_shows_who_is_signed_in_and_the_gateinto_version() {
        let probe = probed(tpm());
        assert_eq!(
            draw(Some(&probe)).computer,
            Some(Computer {
                name: "DESK-7".to_owned(),
                account: Some("Signed in as CORP\\ana".to_owned()),
                rows: vec![
                    ("System", "Windows 11 Pro \u{b7} x64".to_owned()),
                    ("Gateinto", VERSION.to_owned()),
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
        assert_eq!(computer.rows, [("Gateinto", VERSION.to_owned())]);
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
        let page = page(None, &listing, None, false);
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
                    source: "Added on this device",
                },
            ])
        );
    }

    #[test]
    fn a_broken_gateway_listing_shows_its_first_line() {
        let listing = Err("config file c.toml: bad\n  |".to_owned());
        let page = page(None, &listing, None, false);
        assert_eq!(page.gateways, Err("config file c.toml: bad".to_owned()));
    }

    #[test]
    fn a_failure_replaces_the_subtitle() {
        let page = page(
            None,
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
    fn a_probe_reads_the_configured_key_name() {
        let file =
            ConfigFile::parse("[device_key]\nname = \"work\"\n").map_err(|error| error.to_string());
        let found = probe(
            &file,
            || store(Err(StoreError::NotFound), Err(StoreError::NotFound)),
            system(),
        );
        assert_eq!(
            found,
            Probe {
                key: KeyState::Missing("work".parse().unwrap()),
                system: system(),
            }
        );
    }

    #[test]
    fn a_probe_without_settings_uses_the_default_key() {
        let found = probe(
            &Ok(ConfigFile::default()),
            || store(Ok(point(1)), Err(StoreError::NotFound)),
            System::default(),
        );
        assert_eq!(found.key, tpm());
    }

    #[test]
    fn a_broken_config_opens_no_key() {
        let broken = Err("config file c.toml: bad".to_owned());
        let found = probe::<Store>(&broken, || panic!("opened the key store"), system());
        assert_eq!(
            found.key,
            KeyState::Failed("config file c.toml: bad".to_owned())
        );
    }
}
