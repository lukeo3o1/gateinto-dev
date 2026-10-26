use gateinto::ipc::{BrowserKind, SessionAuth, SessionInfo, SessionKind, SessionRoute};

use crate::agent::AgentState;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Eyes {
    Lit,
    Dim,
    Closed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub title: &'static str,
    pub subtitle: String,
    pub eyes: Eyes,
    pub stop: bool,
    pub launch: Launch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Launch {
    Hidden,
    Ready,
    Busy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Browser,
    Device,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub id: u64,
    pub kind: Kind,
    pub title: &'static str,
    pub number: String,
    pub auth: &'static str,
    pub gateway: String,
    pub route: &'static str,
    pub address: String,
    pub uptime: String,
    pub active: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page {
    pub status: Status,
    pub rows: Option<Vec<Row>>,
}

pub const EMPTY: &str = "No sessions. Start one from a gateinto:// link.";

pub fn page(state: &AgentState, failure: Option<&str>, now: u64, busy: bool) -> Page {
    let (status, rows) = match state {
        AgentState::Running(sessions) => {
            let active = sessions.iter().filter(|s| s.tunnels > 0).count();
            let plural = if sessions.len() == 1 { "" } else { "s" };
            let status = Status {
                title: if active > 0 { "Relaying" } else { "Idle" },
                subtitle: format!(
                    "Agent running on loopback only · {} session{plural} · {active} active",
                    sessions.len()
                ),
                eyes: if active > 0 { Eyes::Lit } else { Eyes::Dim },
                stop: true,
                launch: if busy { Launch::Busy } else { Launch::Ready },
            };
            (status, Some(sessions.iter().map(|s| row(s, now)).collect()))
        }
        AgentState::Stopped => (
            Status {
                title: "Stopped",
                subtitle: "The agent is not running".to_owned(),
                eyes: Eyes::Closed,
                stop: false,
                launch: Launch::Hidden,
            },
            None,
        ),
        AgentState::Unreachable(error) => (
            Status {
                title: "Agent unreachable",
                subtitle: error.clone(),
                eyes: Eyes::Dim,
                stop: false,
                launch: Launch::Hidden,
            },
            None,
        ),
    };
    let status = match failure {
        Some(failure) => Status {
            subtitle: failure.to_owned(),
            ..status
        },
        None => status,
    };
    Page { status, rows }
}

pub fn row(session: &SessionInfo, now: u64) -> Row {
    let (kind, title) = match session.kind {
        SessionKind::Browser => (
            Kind::Browser,
            match session.browser {
                Some(BrowserKind::Chrome) => "Chrome",
                Some(BrowserKind::Edge) => "Edge",
                Some(BrowserKind::Chromium) => "Chromium",
                Some(BrowserKind::Unknown) | None => "Browser",
            },
        ),
        SessionKind::Device => (Kind::Device, "Device proxy"),
        SessionKind::Unknown => (Kind::Device, "Session"),
    };
    Row {
        id: session.id,
        kind,
        title,
        number: format!(" #{}", session.id),
        auth: match session.auth {
            SessionAuth::OsUser => "OS user",
            SessionAuth::Password => "Password",
            SessionAuth::None => "No authentication",
            SessionAuth::Unknown => "Unknown",
        },
        gateway: gateway_label(&session.gateway, &session.upstream),
        route: match session.route {
            SessionRoute::All => "All",
            SessionRoute::Mixed => "Mixed",
            SessionRoute::Unknown => "Unknown",
        },
        address: address(&session.upstream),
        uptime: uptime(session.started, now),
        active: session.tunnels > 0,
    }
}

pub fn uptime(started: u64, now: u64) -> String {
    match now.saturating_sub(started) {
        ..60 => "<1 min".to_owned(),
        seconds @ ..3_600 => format!("{} min", seconds / 60),
        seconds @ ..86_400 => format!("{} h", seconds / 3_600),
        seconds => format!("{} d", seconds / 86_400),
    }
}

pub fn gateway_label(gateway: &str, upstream: &str) -> String {
    if is_profile(gateway) {
        split_port(upstream).0.to_owned()
    } else {
        gateway.to_owned()
    }
}

pub fn address(upstream: &str) -> String {
    match split_port(upstream) {
        (host, Some("443")) => host.to_owned(),
        _ => upstream.to_owned(),
    }
}

fn is_profile(name: &str) -> bool {
    name.strip_prefix("g-").is_some_and(|hex| {
        hex.len() == 62 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

fn split_port(authority: &str) -> (&str, Option<&str>) {
    if authority.starts_with('[') {
        return match authority.find(']') {
            Some(close) => {
                let (host, tail) = authority.split_at(close + 1);
                (host, tail.strip_prefix(':'))
            }
            None => (authority, None),
        };
    }
    match authority.split_once(':') {
        Some((host, port)) if !port.contains(':') => (host, Some(port)),
        _ => (authority, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: &str = "g-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd";

    fn session(id: u64, tunnels: u64) -> SessionInfo {
        SessionInfo {
            id,
            kind: SessionKind::Browser,
            gateway: "office".to_owned(),
            upstream: "proxy.example.com:443".to_owned(),
            listen: "127.0.0.1:8080".parse().unwrap(),
            route: SessionRoute::All,
            auth: SessionAuth::OsUser,
            started: 1_000,
            tunnels,
            browser: Some(BrowserKind::Edge),
        }
    }

    #[test]
    fn a_running_agent_relays_while_any_session_has_tunnels() {
        let state = AgentState::Running(vec![session(1, 0), session(2, 3), session(3, 1)]);
        let page = page(&state, None, 1_000, false);
        assert_eq!(
            page.status,
            Status {
                title: "Relaying",
                subtitle: "Agent running on loopback only · 3 sessions · 2 active".to_owned(),
                eyes: Eyes::Lit,
                stop: true,
                launch: Launch::Ready,
            }
        );
        let ids: Vec<u64> = page.rows.unwrap().iter().map(|r| r.id).collect();
        assert_eq!(ids, [1, 2, 3]);
    }

    #[test]
    fn the_start_browser_button_waits_for_a_launch_in_flight() {
        let running = AgentState::Running(Vec::new());
        assert_eq!(page(&running, None, 0, false).status.launch, Launch::Ready);
        assert_eq!(page(&running, None, 0, true).status.launch, Launch::Busy);
        let stopped = page(&AgentState::Stopped, None, 0, true).status.launch;
        assert_eq!(stopped, Launch::Hidden);
    }

    #[test]
    fn a_running_agent_without_tunnels_is_idle() {
        let page = page(
            &AgentState::Running(vec![session(4, 0)]),
            None,
            1_000,
            false,
        );
        assert_eq!(page.status.title, "Idle");
        assert_eq!(
            page.status.subtitle,
            "Agent running on loopback only · 1 session · 0 active"
        );
        assert_eq!(page.status.eyes, Eyes::Dim);
        assert!(page.status.stop);
    }

    #[test]
    fn a_running_agent_without_sessions_shows_an_empty_table() {
        let page = page(&AgentState::Running(Vec::new()), None, 1_000, false);
        assert_eq!(page.status.title, "Idle");
        assert_eq!(
            page.status.subtitle,
            "Agent running on loopback only · 0 sessions · 0 active"
        );
        assert_eq!(page.rows, Some(Vec::new()));
    }

    #[test]
    fn a_stopped_agent_has_no_table_eyes_or_stop_button() {
        assert_eq!(
            page(&AgentState::Stopped, None, 0, false),
            Page {
                status: Status {
                    title: "Stopped",
                    subtitle: "The agent is not running".to_owned(),
                    eyes: Eyes::Closed,
                    stop: false,
                    launch: Launch::Hidden,
                },
                rows: None,
            }
        );
    }

    #[test]
    fn an_unreachable_agent_shows_the_error() {
        let state = AgentState::Unreachable("the agent did not answer".to_owned());
        assert_eq!(
            page(&state, None, 0, false),
            Page {
                status: Status {
                    title: "Agent unreachable",
                    subtitle: "the agent did not answer".to_owned(),
                    eyes: Eyes::Dim,
                    stop: false,
                    launch: Launch::Hidden,
                },
                rows: None,
            }
        );
    }

    #[test]
    fn a_failed_command_replaces_the_subtitle() {
        let state = AgentState::Running(vec![session(1, 1)]);
        let page = page(&state, Some("no session 9"), 1_000, false);
        assert_eq!(page.status.title, "Relaying");
        assert_eq!(page.status.subtitle, "no session 9");
        assert_eq!(page.rows.unwrap().len(), 1);
    }

    #[test]
    fn a_row_describes_its_session() {
        assert_eq!(
            row(&session(7, 2), 1_000 + 3 * 60),
            Row {
                id: 7,
                kind: Kind::Browser,
                title: "Edge",
                number: " #7".to_owned(),
                auth: "OS user",
                gateway: "office".to_owned(),
                route: "All",
                address: "proxy.example.com".to_owned(),
                uptime: "3 min".to_owned(),
                active: true,
            }
        );
        assert!(!row(&session(7, 0), 1_000).active);
    }

    #[test]
    fn titles_follow_the_session_and_browser_kind() {
        let titled = |kind, browser| {
            let mut s = session(1, 0);
            s.kind = kind;
            s.browser = browser;
            let r = row(&s, 0);
            (r.title, r.kind)
        };
        use BrowserKind as B;
        use SessionKind as S;
        assert_eq!(
            titled(S::Browser, Some(B::Chrome)),
            ("Chrome", Kind::Browser)
        );
        assert_eq!(titled(S::Browser, Some(B::Edge)), ("Edge", Kind::Browser));
        assert_eq!(
            titled(S::Browser, Some(B::Chromium)),
            ("Chromium", Kind::Browser)
        );
        assert_eq!(
            titled(S::Browser, Some(B::Unknown)),
            ("Browser", Kind::Browser)
        );
        assert_eq!(titled(S::Browser, None), ("Browser", Kind::Browser));
        assert_eq!(titled(S::Device, None), ("Device proxy", Kind::Device));
        assert_eq!(titled(S::Unknown, None), ("Session", Kind::Device));
    }

    #[test]
    fn auth_and_route_have_readable_names() {
        let named = |auth, route| {
            let mut s = session(1, 0);
            s.auth = auth;
            s.route = route;
            let r = row(&s, 0);
            (r.auth, r.route)
        };
        assert_eq!(
            named(SessionAuth::OsUser, SessionRoute::All),
            ("OS user", "All")
        );
        assert_eq!(
            named(SessionAuth::Password, SessionRoute::Mixed),
            ("Password", "Mixed")
        );
        assert_eq!(
            named(SessionAuth::None, SessionRoute::Unknown),
            ("No authentication", "Unknown")
        );
        assert_eq!(named(SessionAuth::Unknown, SessionRoute::All).0, "Unknown");
    }

    #[test]
    fn uptime_rounds_down_to_the_largest_unit() {
        assert_eq!(uptime(100, 100), "<1 min");
        assert_eq!(uptime(100, 159), "<1 min");
        assert_eq!(uptime(100, 160), "1 min");
        assert_eq!(uptime(0, 3_599), "59 min");
        assert_eq!(uptime(0, 3_600), "1 h");
        assert_eq!(uptime(0, 86_399), "23 h");
        assert_eq!(uptime(0, 86_400), "1 d");
        assert_eq!(uptime(0, 10 * 86_400 + 5), "10 d");
    }

    #[test]
    fn a_start_in_the_future_is_less_than_a_minute_ago() {
        assert_eq!(uptime(5_000, 1_000), "<1 min");
    }

    #[test]
    fn profile_names_are_replaced_by_the_upstream_host() {
        assert_eq!(
            gateway_label(PROFILE, "proxy.example.com:8443"),
            "proxy.example.com"
        );
        assert_eq!(
            gateway_label(PROFILE, "proxy.example.com"),
            "proxy.example.com"
        );
        assert_eq!(gateway_label(PROFILE, "[2001:db8::1]:443"), "[2001:db8::1]");
        assert_eq!(gateway_label("office", "proxy.example.com:443"), "office");
    }

    #[test]
    fn only_exact_profile_names_are_replaced() {
        let upper = PROFILE.to_uppercase().replacen("G-", "g-", 1);
        let short = &PROFILE[..PROFILE.len() - 1];
        let long = format!("{PROFILE}0");
        let other = PROFILE.replacen('0', "x", 1);
        for name in [upper.as_str(), short, long.as_str(), other.as_str()] {
            assert_eq!(gateway_label(name, "h:443"), name);
        }
    }

    #[test]
    fn addresses_drop_only_the_default_port() {
        assert_eq!(address("proxy.example.com:443"), "proxy.example.com");
        assert_eq!(address("proxy.example.com:8443"), "proxy.example.com:8443");
        assert_eq!(address("[2001:db8::1]:443"), "[2001:db8::1]");
        assert_eq!(address("[2001:db8::1]:4443"), "[2001:db8::1]:4443");
        assert_eq!(address("10.0.0.1:443"), "10.0.0.1");
        assert_eq!(address("proxy.example.com"), "proxy.example.com");
        assert_eq!(address("proxy.example.com:1443"), "proxy.example.com:1443");
    }
}
