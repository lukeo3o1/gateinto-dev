use gateinto::ipc::SessionInfo;
use gateinto::link::Known;

use crate::agent::AgentState;
use crate::gateways;
use crate::layout::Rect;
use crate::sessions::Eyes;

pub const TIP_UNITS: usize = 127;
pub const LABEL: &str = "Start a browser session";
pub const NO_GATEWAYS: &str = "No gateways yet.";
pub const STARTING: &str = "Starting a browser session…";
pub const STARTED: &str = "Browser session started";
pub const OPEN: &str = "Open Gateinto";
pub const ADD: &str = "Add gateway…";
pub const STOP: &str = "Stop agent";
pub const EXIT: &str = "Exit";
const GRACE_MS: u64 = 500;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub title: &'static str,
    pub subtitle: String,
    pub eyes: Eyes,
    pub stop: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub name: String,
    pub address: String,
    pub open: String,
    pub lit: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Flyout {
    pub title: &'static str,
    pub subtitle: String,
    pub eyes: Eyes,
    pub stop: bool,
    pub launch: bool,
    pub rows: Vec<Row>,
    pub empty: Option<String>,
    pub notice: Option<String>,
}

pub fn status(state: &AgentState) -> Status {
    match state {
        AgentState::Running(sessions) => {
            let traffic = sessions.iter().filter(|s| s.tunnels > 0).count();
            let subtitle = match sessions.len() {
                0 => "No sessions".to_owned(),
                1 => format!("1 session · {traffic} with traffic"),
                n => format!("{n} sessions · {traffic} with traffic"),
            };
            Status {
                title: if traffic > 0 { "Relaying" } else { "Idle" },
                subtitle,
                eyes: if traffic > 0 { Eyes::Lit } else { Eyes::Dim },
                stop: true,
            }
        }
        AgentState::Stopped => Status {
            title: "Stopped",
            subtitle: "The agent is not running".to_owned(),
            eyes: Eyes::Closed,
            stop: false,
        },
        AgentState::Unreachable(error) => Status {
            title: "Agent unreachable",
            subtitle: error.clone(),
            eyes: Eyes::Dim,
            stop: false,
        },
    }
}

pub fn pending() -> Status {
    Status {
        title: "Checking",
        subtitle: "Waiting for the agent status".to_owned(),
        eyes: Eyes::Dim,
        stop: false,
    }
}

pub fn waiting() -> Flyout {
    let Status {
        title,
        subtitle,
        eyes,
        stop,
    } = pending();
    Flyout {
        title,
        subtitle,
        eyes,
        stop,
        launch: false,
        rows: Vec::new(),
        empty: None,
        notice: None,
    }
}

pub fn tooltip(status: &Status) -> String {
    let full = format!("Gateinto: {}\n{}", status.title, status.subtitle);
    let mut units = 0;
    full.chars()
        .take_while(|c| {
            units += c.len_utf16();
            units <= TIP_UNITS
        })
        .collect()
}

pub fn flyout(
    listing: &Result<Known, String>,
    state: &AgentState,
    busy: bool,
    notice: Option<&str>,
) -> Flyout {
    let page = gateways::page(listing, state, None, busy);
    let sessions: &[SessionInfo] = match state {
        AgentState::Running(sessions) => sessions,
        AgentState::Stopped | AgentState::Unreachable(_) => &[],
    };
    let rows = gateways::names(listing)
        .iter()
        .zip(page.rows)
        .map(|(name, row)| {
            let open = sessions
                .iter()
                .filter(|s| s.gateway == name.as_str())
                .count();
            Row {
                name: row.label,
                address: row.address,
                open: if open == 0 {
                    String::new()
                } else {
                    format!("{open} open")
                },
                lit: row.lit,
            }
        })
        .collect();
    let empty = match listing {
        Err(error) => Some(error.clone()),
        Ok(_) if page.empty => Some(NO_GATEWAYS.to_owned()),
        Ok(_) => None,
    };
    let Status {
        title,
        subtitle,
        eyes,
        stop,
    } = status(state);
    Flyout {
        title,
        subtitle,
        eyes,
        stop,
        launch: page.launch,
        rows,
        empty,
        notice: notice.map(str::to_owned),
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
enum Stage {
    #[default]
    Quiet,
    Waiting,
    Settled {
        text: String,
        seen: bool,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Notice(Stage);

impl Notice {
    pub fn text(&self) -> Option<&str> {
        match &self.0 {
            Stage::Quiet => None,
            Stage::Waiting => Some(STARTING),
            Stage::Settled { text, .. } => Some(text),
        }
    }

    pub fn wait(&mut self) {
        self.0 = Stage::Waiting;
    }

    pub fn settle(&mut self, failure: Option<&str>, visible: bool) {
        if self.0 == Stage::Waiting {
            self.0 = Stage::Settled {
                text: failure.unwrap_or(STARTED).to_owned(),
                seen: visible,
            };
        }
    }

    pub fn shown(&mut self) {
        if let Stage::Settled { seen, .. } = &mut self.0 {
            *seen = true;
        }
    }

    pub fn hidden(&mut self) {
        if matches!(self.0, Stage::Settled { seen: true, .. }) {
            self.0 = Stage::Quiet;
        }
    }
}

pub fn place(work: Rect, monitor: Rect, cursor: (i32, i32), size: (i32, i32), margin: i32) -> Rect {
    let w = size.0.min(work.w - 2 * margin).max(0);
    let h = size.1.min(work.h - 2 * margin).max(0);
    let (left, top) = (work.x + margin, work.y + margin);
    let (right, bottom) = (work.right() - margin - w, work.bottom() - margin - h);
    let (x, y) = if work.bottom() < monitor.bottom() {
        (right, bottom)
    } else if work.y > monitor.y {
        (right, top)
    } else if work.x > monitor.x {
        (left, bottom)
    } else if work.right() < monitor.right() {
        (right, bottom)
    } else {
        (
            if cursor.0 >= work.x + work.w / 2 {
                right
            } else {
                left
            },
            if cursor.1 >= work.y + work.h / 2 {
                bottom
            } else {
                top
            },
        )
    };
    Rect::new(x, y, w, h)
}

pub fn reopens(now_ms: u64, hidden_at: Option<u64>) -> bool {
    hidden_at.is_none_or(|at| now_ms < at || now_ms - at >= GRACE_MS)
}

#[cfg(test)]
mod tests {
    use gateinto::config::GatewayName;
    use gateinto::ipc::{SessionAuth, SessionInfo, SessionKind, SessionRoute};
    use gateinto::link::{Known, KnownGateway, Source};

    use super::*;

    fn gateway(name: &str, host: &str) -> KnownGateway {
        KnownGateway {
            name: name.parse::<GatewayName>().unwrap(),
            host: Some(host.to_owned()),
            port: None,
            portal_url: None,
            source: Source::Config,
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

    fn running(sessions: Vec<SessionInfo>) -> AgentState {
        AgentState::Running(sessions)
    }

    #[test]
    fn traffic_makes_the_agent_relay() {
        let state = running(vec![session(1, "office", 2), session(2, "office", 0)]);
        assert_eq!(
            status(&state),
            Status {
                title: "Relaying",
                subtitle: "2 sessions · 1 with traffic".to_owned(),
                eyes: Eyes::Lit,
                stop: true,
            }
        );
    }

    #[test]
    fn a_running_agent_without_traffic_is_idle() {
        let one = status(&running(vec![session(1, "office", 0)]));
        assert_eq!(
            (one.title, one.subtitle.as_str()),
            ("Idle", "1 session · 0 with traffic")
        );
        assert_eq!(one.eyes, Eyes::Dim);
        let none = status(&running(Vec::new()));
        assert_eq!(
            (none.title, none.subtitle.as_str()),
            ("Idle", "No sessions")
        );
    }

    #[test]
    fn a_stopped_or_unreachable_agent_cannot_be_stopped() {
        let stopped = status(&AgentState::Stopped);
        assert_eq!(
            stopped,
            Status {
                title: "Stopped",
                subtitle: "The agent is not running".to_owned(),
                eyes: Eyes::Closed,
                stop: false,
            }
        );
        let lost = status(&AgentState::Unreachable("pipe busy".to_owned()));
        assert_eq!(
            (lost.title, lost.subtitle.as_str()),
            ("Agent unreachable", "pipe busy")
        );
        assert_eq!((lost.eyes, lost.stop), (Eyes::Dim, false));
    }

    #[test]
    fn the_tooltip_names_the_app_and_the_status() {
        let tip = tooltip(&status(&running(vec![session(1, "office", 1)])));
        assert_eq!(tip, "Gateinto: Relaying\n1 session · 1 with traffic");
    }

    #[test]
    fn the_tooltip_fits_the_notify_icon_buffer() {
        let long = "é".repeat(300);
        let tip = tooltip(&status(&AgentState::Unreachable(long)));
        assert!(tip.encode_utf16().count() <= TIP_UNITS);
        assert!(tip.starts_with("Gateinto: Agent unreachable\né"));
        let wide = "😀".repeat(100);
        let tip = tooltip(&status(&AgentState::Unreachable(wide)));
        assert!(tip.encode_utf16().count() <= TIP_UNITS);
    }

    #[test]
    fn gateway_rows_count_their_open_sessions() {
        let listing = known(vec![
            gateway("office", "proxy.example.com"),
            gateway("lab", "lab.example"),
        ]);
        let state = running(vec![session(1, "office", 1), session(2, "office", 0)]);
        let flyout = flyout(&listing, &state, false, None);
        assert_eq!(
            flyout.rows,
            [
                Row {
                    name: "office".to_owned(),
                    address: "proxy.example.com".to_owned(),
                    open: "2 open".to_owned(),
                    lit: true,
                },
                Row {
                    name: "lab".to_owned(),
                    address: "lab.example".to_owned(),
                    open: String::new(),
                    lit: false,
                },
            ]
        );
        assert!(flyout.launch);
        assert!(flyout.stop);
        assert_eq!(flyout.empty, None);
    }

    #[test]
    fn rows_launch_only_like_the_gateways_page() {
        let listing = known(vec![gateway("office", "proxy.example.com")]);
        assert!(!flyout(&listing, &running(Vec::new()), true, None).launch);
        assert!(!flyout(&listing, &AgentState::Stopped, false, None).launch);
        let stopped = flyout(&listing, &AgentState::Stopped, false, None);
        assert!(!stopped.stop);
        assert_eq!(stopped.rows.len(), 1);
    }

    #[test]
    fn an_empty_or_unreadable_list_says_so() {
        let empty = flyout(&known(Vec::new()), &AgentState::Stopped, false, None);
        assert_eq!(empty.empty.as_deref(), Some(NO_GATEWAYS));
        let broken = Err("config is broken".to_owned());
        let broken = flyout(&broken, &AgentState::Stopped, false, None);
        assert_eq!(broken.empty.as_deref(), Some("config is broken"));
    }

    #[test]
    fn the_flyout_carries_the_notice() {
        let listing = known(Vec::new());
        let shown = flyout(&listing, &AgentState::Stopped, false, Some("Busy"));
        assert_eq!(shown.notice.as_deref(), Some("Busy"));
        assert_eq!(shown.title, "Stopped");
    }

    #[test]
    fn a_launch_waits_then_shows_a_fixed_line_or_the_failure() {
        let mut notice = Notice::default();
        assert_eq!(notice.text(), None);
        notice.wait();
        assert_eq!(notice.text(), Some(STARTING));
        notice.settle(None, true);
        assert_eq!(notice.text(), Some(STARTED));
        notice.wait();
        notice.settle(Some("Gateway refused"), true);
        assert_eq!(notice.text(), Some("Gateway refused"));
    }

    #[test]
    fn settling_only_ends_a_wait() {
        let mut notice = Notice::default();
        notice.settle(Some("Stop failed"), true);
        assert_eq!(notice.text(), None);
    }

    #[test]
    fn a_seen_result_clears_when_the_flyout_hides() {
        let mut notice = Notice::default();
        notice.wait();
        notice.settle(None, true);
        notice.hidden();
        assert_eq!(notice.text(), None);
    }

    #[test]
    fn a_result_settled_while_hidden_waits_to_be_seen() {
        let mut notice = Notice::default();
        notice.wait();
        notice.hidden();
        assert_eq!(notice.text(), Some(STARTING));
        notice.settle(None, false);
        notice.hidden();
        assert_eq!(notice.text(), Some(STARTED));
        notice.shown();
        assert_eq!(notice.text(), Some(STARTED));
        notice.hidden();
        assert_eq!(notice.text(), None);
    }

    const WORK: Rect = Rect::new(0, 0, 1920, 1040);
    const SCREEN: Rect = Rect::new(0, 0, 1920, 1080);

    #[test]
    fn the_flyout_sits_above_a_bottom_taskbar_at_the_right() {
        let r = place(WORK, SCREEN, (1800, 1060), (360, 520), 12);
        assert_eq!(r, Rect::new(1548, 508, 360, 520));
    }

    #[test]
    fn the_flyout_follows_the_taskbar_edge() {
        let top = place(
            Rect::new(0, 40, 1920, 1040),
            SCREEN,
            (1800, 10),
            (360, 520),
            12,
        );
        assert_eq!(top, Rect::new(1548, 52, 360, 520));
        let left = place(
            Rect::new(60, 0, 1860, 1080),
            SCREEN,
            (10, 1000),
            (360, 520),
            12,
        );
        assert_eq!(left, Rect::new(72, 548, 360, 520));
        let right = place(
            Rect::new(0, 0, 1860, 1080),
            SCREEN,
            (1900, 1000),
            (360, 520),
            12,
        );
        assert_eq!(right, Rect::new(1488, 548, 360, 520));
    }

    #[test]
    fn a_hidden_taskbar_uses_the_corner_nearest_the_cursor() {
        let near = |cursor| place(SCREEN, SCREEN, cursor, (360, 520), 12);
        assert_eq!(near((1900, 1070)), Rect::new(1548, 548, 360, 520));
        assert_eq!(near((5, 3)), Rect::new(12, 12, 360, 520));
    }

    #[test]
    fn the_flyout_shrinks_to_a_small_work_area() {
        let small = Rect::new(100, 50, 300, 400);
        let r = place(
            small,
            Rect::new(100, 50, 300, 440),
            (390, 470),
            (360, 520),
            12,
        );
        assert_eq!(r, Rect::new(112, 62, 276, 376));
    }

    #[test]
    fn a_tray_click_right_after_a_focus_loss_does_not_reopen() {
        assert!(reopens(10_000, None));
        assert!(!reopens(10_000, Some(9_700)));
        assert!(reopens(10_000, Some(9_000)));
        assert!(reopens(10_000, Some(10_900)));
    }

    #[test]
    fn before_the_first_update_the_tray_is_checking() {
        let status = pending();
        assert_eq!(status.title, "Checking");
        assert_eq!(status.subtitle, "Waiting for the agent status");
        assert_eq!(status.eyes, Eyes::Dim);
        assert!(!status.stop);
        assert_eq!(
            tooltip(&status),
            "Gateinto: Checking\nWaiting for the agent status"
        );
        let f = waiting();
        assert_eq!(
            (f.title, f.subtitle.as_str()),
            (status.title, "Waiting for the agent status")
        );
        assert!(!f.stop && !f.launch && f.rows.is_empty());
        assert_eq!((f.empty, f.notice), (None, None));
    }
}
