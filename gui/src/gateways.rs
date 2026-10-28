use std::path::PathBuf;

use gateinto::config::{ConfigFile, GatewayName, Gateways};
use gateinto::identity::client_cert::ClientCertificateMode;
use gateinto::ipc::{SessionInfo, SessionRoute};
use gateinto::link::store::{LinkedStore, Loaded};
use gateinto::link::{Known, KnownGateway, Source};
use gateinto::tls::TlsMode;

use crate::agent::AgentState;
use crate::i18n::{Text, fill, tr};
use crate::sessions::gateway_label;

pub const SUBTITLE: Text = Text::GatewaysSubtitle;
pub const EMPTY: Text = Text::NoGatewaysHint;
pub const FOOTNOTE: Text = Text::ConfigReadOnly;
pub const START: Text = Text::StartBrowser;
pub const ADD: Text = Text::AddGateway;
pub const ROUTE_PER_START: Text = Text::RoutePerStart;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub label: String,
    pub address: String,
    pub sessions: String,
    pub lit: bool,
    pub config: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page {
    pub subtitle: String,
    pub rows: Vec<Row>,
    pub empty: bool,
    pub footnote: bool,
    pub launch: bool,
}

pub fn read(config: Option<PathBuf>) -> Result<ConfigFile, String> {
    match config.filter(|path| path.is_file()) {
        Some(path) => ConfigFile::load(&path).map_err(|error| error.to_string()),
        None => Ok(ConfigFile::default()),
    }
}

pub fn catalog(file: &ConfigFile, store: Option<PathBuf>) -> Known {
    let linked = store.map_or(Ok(Loaded::default()), |dir| LinkedStore::new(dir).load());
    Known::new(file, linked)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Launches {
    sent: u64,
    done: u64,
}

impl Launches {
    pub fn busy(&self) -> bool {
        self.sent > self.done
    }

    pub fn start(&mut self, names: &[GatewayName], row: usize) -> Option<GatewayName> {
        if self.busy() {
            return None;
        }
        let name = names.get(row)?.clone();
        self.sent += 1;
        Some(name)
    }

    pub fn settle(&mut self, launched: u64) {
        self.done = launched;
    }
}

pub fn page(
    listing: &Result<Known, String>,
    state: &AgentState,
    failure: Option<&str>,
    busy: bool,
) -> Page {
    let sessions = running(state);
    let (rows, problem) = match listing {
        Ok(known) => (
            known
                .gateways
                .iter()
                .map(|gateway| row(gateway, sessions))
                .collect(),
            known
                .unavailable
                .clone()
                .or_else(|| known.invalid.first().map(ToString::to_string)),
        ),
        Err(error) => (Vec::new(), Some(error.clone())),
    };
    Page {
        subtitle: failure
            .map(str::to_owned)
            .or(problem)
            .unwrap_or_else(|| tr(SUBTITLE).to_owned()),
        empty: listing.is_ok() && rows.is_empty(),
        footnote: rows.iter().any(|row: &Row| row.config),
        launch: matches!(state, AgentState::Running(_)) && !busy,
        rows,
    }
}

pub fn names(listing: &Result<Known, String>) -> Vec<GatewayName> {
    listing.as_ref().map_or(Vec::new(), |known| {
        known.gateways.iter().map(|g| g.name.clone()).collect()
    })
}

pub fn label(gateway: &KnownGateway) -> String {
    let address = address(gateway.host.as_deref(), gateway.port);
    gateway_label(gateway.name.as_str(), &address)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Details {
    pub title: String,
    pub address: String,
    pub facts: Vec<(Text, String)>,
}

pub fn details(
    listing: &Result<Known, String>,
    sections: &Gateways,
    state: &AgentState,
    name: &GatewayName,
) -> Option<Details> {
    let gateway = listing
        .as_ref()
        .ok()?
        .gateways
        .iter()
        .find(|gateway| &gateway.name == name)?;
    let section = sections
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, section)| section);
    let open = open(gateway, running(state));
    let title = label(gateway);
    let host = gateway
        .host
        .clone()
        .unwrap_or_else(|| tr(Text::NotSet).to_owned());
    let server_name = section
        .and_then(|section| section.server_name.clone())
        .unwrap_or_else(|| host.clone());
    let tls = section
        .and_then(|section| section.tls_mode)
        .unwrap_or_default();
    let certificate = section
        .and_then(|section| section.client_certificate)
        .unwrap_or_default();
    let self_signed = section.and_then(|section| section.self_signed_client_cert) == Some(true);
    Some(Details {
        facts: vec![
            (
                Text::Name,
                if title == name.as_str() {
                    title.clone()
                } else {
                    tr(Text::NoValue).to_owned()
                },
            ),
            (Text::Host, host),
            (Text::Port, gateway.port.unwrap_or(443).to_string()),
            (Text::ServerName, server_name),
            (
                Text::Source,
                tr(match gateway.source {
                    Source::Config => Text::ConfigFile,
                    Source::Linked => Text::AddedHere,
                })
                .to_owned(),
            ),
            (Text::Route, routes(&open)),
            (
                Text::PortalPage,
                gateway
                    .portal_url
                    .as_ref()
                    .map_or_else(|| tr(Text::NoValue).to_owned(), ToString::to_string),
            ),
            (
                Text::TlsMode,
                tr(match tls {
                    TlsMode::HybridPreferred => Text::HybridPreferred,
                    TlsMode::HybridRequired => Text::HybridRequired,
                    TlsMode::ClassicalOnly => Text::ClassicalOnly,
                })
                .to_owned(),
            ),
            (
                Text::ClientCertificate,
                certificate_text(certificate, self_signed),
            ),
            (Text::ActiveSessions, count(open.len())),
        ],
        address: address(gateway.host.as_deref(), gateway.port),
        title,
    })
}

fn running(state: &AgentState) -> &[SessionInfo] {
    match state {
        AgentState::Running(sessions) => sessions.as_slice(),
        AgentState::Stopped | AgentState::Unreachable(_) => &[],
    }
}

fn open<'a>(gateway: &KnownGateway, sessions: &'a [SessionInfo]) -> Vec<&'a SessionInfo> {
    sessions
        .iter()
        .filter(|session| session.gateway == gateway.name.as_str())
        .collect()
}

fn count(sessions: usize) -> String {
    match sessions {
        0 => tr(Text::NoSessions).to_owned(),
        1 => fill(Text::SessionCount, &[&1]),
        n => fill(Text::SessionsCount, &[&n]),
    }
}

fn routes(open: &[&SessionInfo]) -> String {
    let all = open
        .iter()
        .any(|session| session.route == SessionRoute::All);
    let mixed = open
        .iter()
        .any(|session| session.route == SessionRoute::Mixed);
    tr(match (all, mixed) {
        (true, true) => Text::GatewayAndMixed,
        (true, false) => Text::Gateway,
        (false, true) => Text::Mixed,
        (false, false) => ROUTE_PER_START,
    })
    .to_owned()
}

fn certificate_text(mode: ClientCertificateMode, self_signed: bool) -> String {
    let mode = match mode {
        ClientCertificateMode::Off => return tr(Text::Off).to_owned(),
        ClientCertificateMode::Optional => Text::Optional,
        ClientCertificateMode::Required => Text::Required,
    };
    if self_signed {
        fill(Text::SelfSigned, &[&mode])
    } else {
        tr(mode).to_owned()
    }
}

fn row(gateway: &KnownGateway, sessions: &[SessionInfo]) -> Row {
    let open = open(gateway, sessions);
    Row {
        label: label(gateway),
        sessions: count(open.len()),
        lit: open.iter().any(|session| session.tunnels > 0),
        config: gateway.source == Source::Config,
        address: address(gateway.host.as_deref(), gateway.port),
    }
}

pub fn address(host: Option<&str>, port: Option<u16>) -> String {
    let Some(host) = host else {
        return String::new();
    };
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    match port {
        Some(port) if port != 443 => format!("{host}:{port}"),
        _ => host,
    }
}

#[cfg(test)]
mod tests {
    use gateinto::ipc::{SessionAuth, SessionKind, SessionRoute};
    use gateinto::link::store::InvalidEntry;

    use super::*;

    const PROFILE: &str = "g-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd";

    fn name(name: &str) -> GatewayName {
        name.parse().unwrap()
    }

    fn gateway(n: &str, host: Option<&str>, port: Option<u16>, source: Source) -> KnownGateway {
        KnownGateway {
            name: name(n),
            host: host.map(str::to_owned),
            port,
            portal_url: None,
            source,
        }
    }

    fn known(gateways: Vec<KnownGateway>) -> Result<Known, String> {
        Ok(Known {
            gateways,
            ..Known::default()
        })
    }

    fn session(id: u64, gateway: &str, tunnels: u64) -> SessionInfo {
        SessionInfo {
            id,
            kind: SessionKind::Browser,
            gateway: gateway.to_owned(),
            upstream: "proxy.example.com:443".to_owned(),
            listen: "127.0.0.1:8080".parse().unwrap(),
            route: SessionRoute::All,
            auth: SessionAuth::OsUser,
            started: 0,
            tunnels,
            browser: None,
        }
    }

    fn office() -> KnownGateway {
        gateway(
            "office",
            Some("proxy.example.com"),
            Some(443),
            Source::Config,
        )
    }

    #[test]
    fn a_gateway_row_shows_its_name_address_and_sessions() {
        let listing = known(vec![office()]);
        let state = AgentState::Running(vec![session(1, "office", 0)]);
        assert_eq!(
            page(&listing, &state, None, false),
            Page {
                subtitle: SUBTITLE.english().to_owned(),
                rows: vec![Row {
                    label: "office".to_owned(),
                    address: "proxy.example.com".to_owned(),
                    sessions: "1 session".to_owned(),
                    lit: false,
                    config: true,
                }],
                empty: false,
                footnote: true,
                launch: true,
            }
        );
    }

    #[test]
    fn sessions_are_counted_per_gateway_and_light_the_eyes_while_relaying() {
        let listing = known(vec![
            office(),
            gateway("home", Some("home.example"), None, Source::Config),
            gateway("lab", Some("lab.example"), None, Source::Config),
        ]);
        let state = AgentState::Running(vec![
            session(1, "office", 0),
            session(2, "office", 2),
            session(3, "lab", 0),
        ]);
        let rows = page(&listing, &state, None, false).rows;
        let seen: Vec<_> = rows.iter().map(|r| (r.sessions.as_str(), r.lit)).collect();
        assert_eq!(
            seen,
            [
                ("2 sessions", true),
                ("No sessions", false),
                ("1 session", false)
            ]
        );
    }

    fn sections(toml: &str) -> Gateways {
        ConfigFile::parse(toml).unwrap().gateways
    }

    fn facts(details: &Details) -> Vec<(&str, &str)> {
        details
            .facts
            .iter()
            .map(|(key, value)| (crate::i18n::tr(*key), value.as_str()))
            .collect()
    }

    #[test]
    fn config_gateway_details_show_its_settings_and_sessions() {
        let listing = known(vec![KnownGateway {
            port: Some(8443),
            portal_url: Some("https://portal.example.com/".parse().unwrap()),
            ..office()
        }]);
        let sections = sections(
            "[gateways.office]\nhost = \"proxy.example.com\"\nport = 8443\n\
             server_name = \"edge.example.com\"\ntls_mode = \"hybrid_required\"\n\
             client_certificate = \"required\"\nself_signed_client_cert = true\n",
        );
        let mixed = SessionInfo {
            route: SessionRoute::Mixed,
            ..session(2, "office", 0)
        };
        let state = AgentState::Running(vec![session(1, "office", 0), mixed]);
        let details = details(&listing, &sections, &state, &name("office")).unwrap();
        assert_eq!(details.title, "office");
        assert_eq!(details.address, "proxy.example.com:8443");
        assert_eq!(
            facts(&details),
            [
                ("Name", "office"),
                ("Host", "proxy.example.com"),
                ("Port", "8443"),
                ("Server name", "edge.example.com"),
                ("Source", "Config file"),
                ("Route", "Gateway and Mixed"),
                ("Portal page", "https://portal.example.com/"),
                ("TLS mode", "Hybrid required"),
                ("Client certificate", "Required, self-signed"),
                ("Active sessions", "2 sessions"),
            ]
        );
    }

    #[test]
    fn linked_gateway_details_fall_back_to_the_defaults() {
        let listing = known(vec![gateway(
            PROFILE,
            Some("edge.example"),
            Some(443),
            Source::Linked,
        )]);
        let details = details(
            &listing,
            &Gateways::default(),
            &AgentState::Stopped,
            &name(PROFILE),
        )
        .unwrap();
        assert_eq!(details.title, "edge.example");
        assert_eq!(
            facts(&details),
            [
                ("Name", "None"),
                ("Host", "edge.example"),
                ("Port", "443"),
                ("Server name", "edge.example"),
                ("Source", "Added on this device"),
                ("Route", tr(ROUTE_PER_START)),
                ("Portal page", "None"),
                ("TLS mode", "Hybrid preferred"),
                ("Client certificate", "Optional"),
                ("Active sessions", "No sessions"),
            ]
        );
    }

    #[test]
    fn the_gateways_page_and_details_speak_chinese() {
        let _zh = crate::i18n::speaking(crate::i18n::Language::Chinese);
        let state = AgentState::Running(vec![session(1, "office", 0), session(2, "office", 0)]);
        let listing = known(vec![office(), gateway(PROFILE, None, None, Source::Linked)]);
        let page = page(&listing, &state, None, false);
        assert_eq!(page.subtitle, "這部裝置可透過其轉送的遠端 HTTPS 代理");
        assert_eq!(page.rows[0].sessions, "2 個工作階段");
        assert_eq!(page.rows[1].sessions, "沒有工作階段");
        let details = details(&listing, &Gateways::default(), &state, &name(PROFILE)).unwrap();
        assert_eq!(
            facts(&details),
            [
                ("名稱", "無"),
                ("主機", "未設定"),
                ("連接埠", "443"),
                ("伺服器名稱", "未設定"),
                ("來源", "在這部裝置上新增"),
                ("路由", "每次啟動瀏覽器時設定；「啟動瀏覽器」使用閘道"),
                ("入口網頁", "無"),
                ("TLS 模式", "優先使用混合"),
                ("用戶端憑證", "選用"),
                ("使用中的工作階段", "沒有工作階段"),
            ]
        );
        assert_eq!(certificate_text(ClientCertificateMode::Off, false), "關閉");
        assert_eq!(
            certificate_text(ClientCertificateMode::Required, true),
            "必要，自我簽署"
        );
        assert_eq!(count(1), "1 個工作階段");
    }

    #[test]
    fn details_name_a_listed_gateway_only() {
        let listing = known(vec![office()]);
        let none = Gateways::default();
        let state = AgentState::Stopped;
        assert_eq!(details(&listing, &none, &state, &name("lab")), None);
        assert_eq!(
            details(&Err("x".to_owned()), &none, &state, &name("office")),
            None
        );
    }

    #[test]
    fn linked_profile_names_show_the_host_and_no_footnote() {
        let listing = known(vec![gateway(
            PROFILE,
            Some("edge.example"),
            Some(8443),
            Source::Linked,
        )]);
        let page = page(&listing, &AgentState::Stopped, None, false);
        assert_eq!(page.rows[0].label, "edge.example");
        assert_eq!(page.rows[0].address, "edge.example:8443");
        assert!(!page.rows[0].config);
        assert!(!page.footnote);
    }

    #[test]
    fn addresses_bracket_ipv6_hosts_and_drop_only_the_default_port() {
        let address = |host: Option<&str>, port| {
            let listing = known(vec![gateway("g", host, port, Source::Config)]);
            page(&listing, &AgentState::Stopped, None, false).rows[0]
                .address
                .clone()
        };
        assert_eq!(address(Some("2001:db8::1"), Some(443)), "[2001:db8::1]");
        assert_eq!(
            address(Some("2001:db8::1"), Some(4443)),
            "[2001:db8::1]:4443"
        );
        assert_eq!(address(Some("10.0.0.1"), Some(8080)), "10.0.0.1:8080");
        assert_eq!(address(Some("proxy.example"), None), "proxy.example");
        assert_eq!(address(None, Some(8443)), "");
    }

    #[test]
    fn only_a_running_agent_can_start_a_browser() {
        let listing = known(vec![office()]);
        assert!(page(&listing, &AgentState::Running(Vec::new()), None, false).launch);
        assert!(!page(&listing, &AgentState::Stopped, None, false).launch);
        let unreachable = AgentState::Unreachable(crate::i18n::Note::Agent("busy".to_owned()));
        assert!(!page(&listing, &unreachable, None, false).launch);
        assert_eq!(
            page(&listing, &AgentState::Stopped, None, false).rows[0].sessions,
            "No sessions"
        );
    }

    #[test]
    fn no_gateways_says_where_they_come_from() {
        let page = page(&known(Vec::new()), &AgentState::Stopped, None, false);
        assert!(page.empty);
        assert!(page.rows.is_empty());
        assert!(!page.footnote);
        assert_eq!(
            tr(EMPTY),
            "No gateways. Open a gateinto:// link or add one to the config file."
        );
        assert_eq!(tr(FOOTNOTE), "From the config file, read-only here.");
        assert_eq!(START.english(), "Start browser");
        assert_eq!(
            tr(SUBTITLE),
            "Remote HTTPS proxies this device can relay through"
        );
    }

    #[test]
    fn a_load_error_replaces_the_subtitle_and_the_list() {
        let listing = Err("config file c.toml: expected `=`".to_owned());
        let page = page(&listing, &AgentState::Stopped, None, false);
        assert_eq!(page.subtitle, "config file c.toml: expected `=`");
        assert!(page.rows.is_empty());
        assert!(!page.empty);
    }

    #[test]
    fn unreadable_linked_gateways_are_reported_beside_the_config_ones() {
        let unavailable = Ok(Known {
            gateways: vec![office()],
            unavailable: Some("linked gateways d: denied".to_owned()),
            ..Known::default()
        });
        let page = page(&unavailable, &AgentState::Stopped, None, false);
        assert_eq!(page.subtitle, "linked gateways d: denied");
        assert_eq!(page.rows.len(), 1);
        let invalid = Ok(Known {
            invalid: vec![InvalidEntry {
                file: PathBuf::from("x.toml"),
                name: None,
                addresses: Vec::new(),
                reason: "bad".to_owned(),
            }],
            ..Known::default()
        });
        assert_eq!(
            super::page(&invalid, &AgentState::Stopped, None, false).subtitle,
            "x.toml: bad"
        );
    }

    #[test]
    fn names_follow_the_row_order() {
        let listing = known(vec![
            office(),
            gateway("home", Some("home.example"), None, Source::Linked),
        ]);
        let rows = page(&listing, &AgentState::Stopped, None, false).rows;
        let names = names(&listing);
        assert_eq!(names, [name("office"), name("home")]);
        assert!(
            rows.iter()
                .zip(&names)
                .all(|(row, name)| row.label == name.as_str())
        );
        assert!(super::names(&Err("broken".to_owned())).is_empty());
    }

    #[test]
    fn a_launch_in_flight_disables_every_start_browser_button() {
        let listing = known(vec![office()]);
        let running = AgentState::Running(Vec::new());
        assert!(page(&listing, &running, None, false).launch);
        assert!(!page(&listing, &running, None, true).launch);
    }

    #[test]
    fn a_second_start_before_the_launch_finishes_sends_nothing() {
        let names = [name("office"), name("home")];
        let mut launches = Launches::default();
        assert!(!launches.busy());
        assert_eq!(launches.start(&names, 1), Some(name("home")));
        assert!(launches.busy());
        assert_eq!(launches.start(&names, 0), None);
        launches.settle(0);
        assert!(launches.busy());
        assert_eq!(launches.start(&names, 0), None);
        launches.settle(1);
        assert!(!launches.busy());
        assert_eq!(launches.start(&names, 0), Some(name("office")));
        assert!(launches.busy());
    }

    #[test]
    fn a_row_that_is_gone_starts_nothing() {
        let mut launches = Launches::default();
        assert_eq!(launches.start(&[name("office")], 1), None);
        assert!(!launches.busy());
    }

    #[test]
    fn a_failed_launch_replaces_any_subtitle() {
        let listing = Err("broken".to_owned());
        let page = page(
            &listing,
            &AgentState::Stopped,
            Some("too many launches"),
            false,
        );
        assert_eq!(page.subtitle, "too many launches");
    }

    fn load(config: Option<PathBuf>, store: Option<PathBuf>) -> Result<Known, String> {
        Ok(catalog(&read(config)?, store))
    }

    fn scratch(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("gateinto-gui-{}-{test}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn loading_without_files_finds_no_gateways() {
        let dir = scratch("none");
        let listing = load(None, None);
        assert_eq!(listing, known(Vec::new()));
        let missing = load(Some(dir.join("config.toml")), Some(dir.join("gateways")));
        assert_eq!(missing, known(Vec::new()));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn loading_reads_the_config_gateways() {
        let dir = scratch("config");
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            "[gateways.office]\nhost = \"proxy.example.com\"\nport = 8443\n",
        )
        .unwrap();
        let listing = load(Some(path), Some(dir.join("gateways")));
        assert_eq!(
            listing,
            known(vec![gateway(
                "office",
                Some("proxy.example.com"),
                Some(8443),
                Source::Config
            )])
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn loading_a_broken_config_is_an_error() {
        let dir = scratch("broken");
        let path = dir.join("config.toml");
        std::fs::write(&path, "[gateways.office\n").unwrap();
        let error = load(Some(path), None).unwrap_err();
        assert!(error.starts_with("config file "), "{error}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn loading_reports_an_unusable_link_store() {
        let dir = scratch("store");
        let store = dir.join("gateways");
        std::fs::write(&store, "").unwrap();
        let listing = load(None, Some(store)).unwrap();
        assert!(listing.gateways.is_empty());
        assert!(
            listing
                .unavailable
                .as_deref()
                .is_some_and(|e| e.contains("not a directory")),
            "{listing:?}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
