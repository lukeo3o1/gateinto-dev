use std::path::PathBuf;

use gateinto::config::{ConfigFile, GatewayName};
use gateinto::ipc::SessionInfo;
use gateinto::link::store::{LinkedStore, Loaded};
use gateinto::link::{Known, KnownGateway, Source};

use crate::agent::AgentState;
use crate::sessions::gateway_label;

pub const SUBTITLE: &str = "Remote HTTPS proxies this device can relay through";
pub const EMPTY: &str = "No gateways. Open a gateinto:// link or add one to the config file.";
pub const FOOTNOTE: &str = "From the config file, read-only here.";
pub const START: &str = "Start browser";

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

pub fn load(config: Option<PathBuf>, store: Option<PathBuf>) -> Result<Known, String> {
    let file = match config.filter(|path| path.is_file()) {
        Some(path) => ConfigFile::load(&path).map_err(|error| error.to_string())?,
        None => ConfigFile::default(),
    };
    let linked = store.map_or(Ok(Loaded::default()), |dir| LinkedStore::new(dir).load());
    Ok(Known::new(&file, linked))
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
    let sessions = match state {
        AgentState::Running(sessions) => sessions.as_slice(),
        AgentState::Stopped | AgentState::Unreachable(_) => &[],
    };
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
            .unwrap_or_else(|| SUBTITLE.to_owned()),
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

fn row(gateway: &KnownGateway, sessions: &[SessionInfo]) -> Row {
    let open: Vec<_> = sessions
        .iter()
        .filter(|session| session.gateway == gateway.name.as_str())
        .collect();
    let address = address(gateway.host.as_deref(), gateway.port);
    Row {
        label: gateway_label(gateway.name.as_str(), &address),
        sessions: match open.len() {
            0 => "No sessions".to_owned(),
            1 => "1 session".to_owned(),
            n => format!("{n} sessions"),
        },
        lit: open.iter().any(|session| session.tunnels > 0),
        config: gateway.source == Source::Config,
        address,
    }
}

fn address(host: Option<&str>, port: Option<u16>) -> String {
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
                subtitle: SUBTITLE.to_owned(),
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
        let unreachable = AgentState::Unreachable("busy".to_owned());
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
            EMPTY,
            "No gateways. Open a gateinto:// link or add one to the config file."
        );
        assert_eq!(FOOTNOTE, "From the config file, read-only here.");
        assert_eq!(START, "Start browser");
        assert_eq!(
            SUBTITLE,
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
