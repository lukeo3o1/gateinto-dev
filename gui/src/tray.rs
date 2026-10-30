use gateinto::ipc::SessionInfo;
use gateinto::link::Known;

use crate::agent::AgentState;
use crate::gateways;
use crate::i18n::{Note, Text, fill, tr};
use crate::layout::Rect;
use crate::logo::State;
use crate::sessions::Launch;

pub const TIP_UNITS: usize = 127;
pub const LABEL: Text = Text::StartSession;
pub const NO_GATEWAYS: Text = Text::NoGatewaysYet;
pub const STARTING: Text = Text::StartingSession;
pub const STARTED: Text = Text::SessionStarted;
pub const OPEN: Text = Text::OpenApp;
pub const ADD: Text = Text::AddGatewayMenu;
pub const STOP: Text = Text::StopAgent;
pub const START_AGENT: Text = Text::StartAgent;
pub const EXIT: Text = Text::Exit;
pub const FLYOUT_TITLE: Text = Text::FlyoutTitle;
const GRACE_MS: u64 = 500;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub title: &'static str,
    pub subtitle: String,
    pub logo: State,
    pub stop: bool,
    pub start: bool,
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
    pub logo: State,
    pub stop: bool,
    pub start: Launch,
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
                0 => tr(Text::NoSessions).to_owned(),
                1 => fill(Text::OneSessionTraffic, &[&traffic]),
                n => fill(Text::SessionsTraffic, &[&n, &traffic]),
            };
            Status {
                title: tr(if traffic > 0 {
                    Text::Relaying
                } else {
                    Text::Idle
                }),
                subtitle,
                logo: if traffic > 0 {
                    State::Relaying
                } else {
                    State::Idle
                },
                stop: true,
                start: false,
            }
        }
        AgentState::Stopped => Status {
            title: tr(Text::Stopped),
            subtitle: tr(Text::AgentStopped).to_owned(),
            logo: State::Stopped,
            stop: false,
            start: true,
        },
        AgentState::Unreachable(error) => Status {
            title: tr(Text::AgentUnreachable),
            subtitle: error.shown().to_owned(),
            logo: State::Attention,
            stop: false,
            start: false,
        },
    }
}

pub fn pending() -> Status {
    Status {
        title: tr(Text::Checking),
        subtitle: tr(Text::WaitingStatus).to_owned(),
        logo: State::Idle,
        stop: false,
        start: false,
    }
}

pub fn logo(state: Option<&AgentState>) -> State {
    state.map_or_else(pending, status).logo
}

pub fn waiting() -> Flyout {
    let Status {
        title,
        subtitle,
        logo,
        stop,
        ..
    } = pending();
    Flyout {
        title,
        subtitle,
        logo,
        stop,
        start: Launch::Hidden,
        launch: false,
        rows: Vec::new(),
        empty: None,
        notice: None,
    }
}

pub fn flyout_title(demo: bool) -> &'static str {
    tr(if demo {
        Text::DemoFlyoutTitle
    } else {
        FLYOUT_TITLE
    })
}

pub fn tooltip(status: &Status, demo: bool) -> String {
    let tip = if demo {
        Text::DemoTrayTip
    } else {
        Text::TrayTip
    };
    let full = fill(tip, &[&status.title, &status.subtitle]);
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
    starting: bool,
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
                    fill(Text::OpenCount, &[&open])
                },
                lit: row.lit,
            }
        })
        .collect();
    let empty = match listing {
        Err(error) => Some(error.clone()),
        Ok(_) if page.empty => Some(tr(NO_GATEWAYS).to_owned()),
        Ok(_) => None,
    };
    let Status {
        title,
        subtitle,
        logo,
        stop,
        start,
    } = status(state);
    let (subtitle, start) = match (start, starting) {
        (false, _) => (subtitle, Launch::Hidden),
        (true, false) => (subtitle, Launch::Ready),
        (true, true) => (tr(Text::StartingAgent).to_owned(), Launch::Busy),
    };
    Flyout {
        title,
        subtitle,
        logo,
        stop,
        start,
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
        text: Note,
        seen: bool,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Notice(Stage);

impl Notice {
    pub fn text(&self) -> Option<&str> {
        match &self.0 {
            Stage::Quiet => None,
            Stage::Waiting => Some(tr(STARTING)),
            Stage::Settled { text, .. } => Some(text.shown()),
        }
    }

    pub fn wait(&mut self) {
        self.0 = Stage::Waiting;
    }

    pub fn settle(&mut self, failure: Option<&Note>, visible: bool) {
        if self.0 == Stage::Waiting {
            self.0 = Stage::Settled {
                text: failure.cloned().unwrap_or(STARTED.into()),
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

const NIN_SELECT: u32 = 0x400;
const NIN_KEYSELECT: u32 = 0x401;
const WM_CONTEXTMENU: u32 = 0x7b;
const WM_LBUTTONUP: u32 = 0x202;
const WM_RBUTTONUP: u32 = 0x205;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Click,
    Select((i32, i32)),
    KeySelect((i32, i32)),
    Menu(Option<(i32, i32)>),
}

pub fn event(version4: bool, wp: usize, lp: isize) -> Option<Event> {
    let anchor = (
        i32::from(wp as u16 as i16),
        i32::from((wp >> 16) as u16 as i16),
    );
    match ((lp & 0xffff) as u32, version4) {
        (NIN_SELECT, true) => Some(Event::Select(anchor)),
        (NIN_KEYSELECT, true) => Some(Event::KeySelect(anchor)),
        (WM_CONTEXTMENU, true) => Some(Event::Menu(Some(anchor))),
        (WM_LBUTTONUP, false) => Some(Event::Click),
        (WM_RBUTTONUP, false) => Some(Event::Menu(None)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use gateinto::config::GatewayName;
    use gateinto::ipc::{SessionAuth, SessionInfo, SessionKind, SessionRoute};
    use gateinto::link::{Known, KnownGateway, Source};

    use super::*;

    #[test]
    fn the_window_logo_waits_idle_and_flags_an_unreachable_agent() {
        assert_eq!(logo(None), State::Idle);
        assert_eq!(logo(Some(&AgentState::Stopped)), State::Stopped);
        let lost = AgentState::Unreachable(crate::i18n::Note::Agent("pipe busy".to_owned()));
        assert_eq!(logo(Some(&lost)), State::Attention);
        assert_eq!(logo(Some(&AgentState::Running(Vec::new()))), State::Idle);
    }

    #[test]
    fn version_four_events_carry_their_anchor_in_wparam() {
        let anchor = (0xfffe_usize << 16) | 0x0280;
        let lp = |event: u32| ((1 << 16) | event) as isize;
        assert_eq!(
            event(true, anchor, lp(0x400)),
            Some(Event::Select((640, -2)))
        );
        assert_eq!(
            event(true, anchor, lp(0x401)),
            Some(Event::KeySelect((640, -2)))
        );
        assert_eq!(
            event(true, anchor, lp(0x7b)),
            Some(Event::Menu(Some((640, -2))))
        );
        assert_eq!(event(true, anchor, lp(0x202)), None);
        assert_eq!(event(true, anchor, lp(0x205)), None);
    }

    #[test]
    fn legacy_events_use_the_cursor() {
        assert_eq!(event(false, 0, 0x202), Some(Event::Click));
        assert_eq!(event(false, 0, 0x205), Some(Event::Menu(None)));
        assert_eq!(event(false, 0, 0x400), None);
        assert_eq!(event(false, 0, 0x7b), None);
    }

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
                logo: State::Relaying,
                stop: true,
                start: false,
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
        assert_eq!(one.logo, State::Idle);
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
                logo: State::Stopped,
                stop: false,
                start: true,
            }
        );
        let lost = status(&AgentState::Unreachable(crate::i18n::Note::Agent(
            "pipe busy".to_owned(),
        )));
        assert_eq!(
            (lost.title, lost.subtitle.as_str()),
            ("Agent unreachable", "pipe busy")
        );
        assert_eq!(
            (lost.logo, lost.stop, lost.start),
            (State::Attention, false, false)
        );
    }

    #[test]
    fn the_tooltip_names_the_app_and_the_status() {
        let tip = tooltip(&status(&running(vec![session(1, "office", 1)])), false);
        assert_eq!(tip, "Gateinto: Relaying\n1 session · 1 with traffic");
    }

    #[test]
    fn the_demo_labels_its_tray_tooltip_and_flyout_in_each_language() {
        assert_eq!(
            tooltip(&pending(), true),
            "Gateinto Demo: Checking\nWaiting for the agent status"
        );
        assert_eq!(flyout_title(true), "Gateinto Demo status");
        assert_eq!(flyout_title(false), "Gateinto status");
        let _zh = crate::i18n::speaking(crate::i18n::Language::Chinese);
        assert_eq!(
            tooltip(&pending(), true),
            "Gateinto 示範：檢查中\n正在等候代理程式狀態"
        );
        assert_eq!(flyout_title(true), "Gateinto 示範狀態");
        assert_eq!(flyout_title(false), "Gateinto 狀態");
    }

    #[test]
    fn the_tooltip_fits_the_notify_icon_buffer() {
        let long = "é".repeat(300);
        let tip = tooltip(
            &status(&AgentState::Unreachable(crate::i18n::Note::Agent(long))),
            false,
        );
        assert!(tip.encode_utf16().count() <= TIP_UNITS);
        assert!(tip.starts_with("Gateinto: Agent unreachable\né"));
        let wide = "😀".repeat(100);
        let tip = tooltip(
            &status(&AgentState::Unreachable(crate::i18n::Note::Agent(wide))),
            false,
        );
        assert!(tip.encode_utf16().count() <= TIP_UNITS);
    }

    #[test]
    fn gateway_rows_count_their_open_sessions() {
        let listing = known(vec![
            gateway("office", "proxy.example.com"),
            gateway("lab", "lab.example"),
        ]);
        let state = running(vec![session(1, "office", 1), session(2, "office", 0)]);
        let flyout = flyout(&listing, &state, false, false, None);
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
        assert!(!flyout(&listing, &running(Vec::new()), true, false, None).launch);
        assert!(!flyout(&listing, &AgentState::Stopped, false, false, None).launch);
        let stopped = flyout(&listing, &AgentState::Stopped, false, false, None);
        assert!(!stopped.stop);
        assert_eq!(stopped.rows.len(), 1);
    }

    #[test]
    fn only_a_stopped_agent_offers_to_start_and_waits_for_a_start_in_flight() {
        let listing = known(Vec::new());
        let stopped = flyout(&listing, &AgentState::Stopped, false, false, None);
        assert_eq!(stopped.start, Launch::Ready);
        assert_eq!(stopped.subtitle, "The agent is not running");
        let starting = flyout(&listing, &AgentState::Stopped, false, true, None);
        assert_eq!(starting.start, Launch::Busy);
        assert_eq!(starting.subtitle, "Starting the agent…");
        let relaying = flyout(&listing, &running(Vec::new()), false, true, None);
        assert_eq!(relaying.start, Launch::Hidden);
        let lost = AgentState::Unreachable(crate::i18n::Note::Agent("x".to_owned()));
        assert_eq!(
            flyout(&listing, &lost, false, true, None).start,
            Launch::Hidden
        );
    }

    #[test]
    fn an_empty_or_unreadable_list_says_so() {
        let empty = flyout(&known(Vec::new()), &AgentState::Stopped, false, false, None);
        assert_eq!(empty.empty.as_deref(), Some(NO_GATEWAYS.english()));
        let broken = Err("config is broken".to_owned());
        let broken = flyout(&broken, &AgentState::Stopped, false, false, None);
        assert_eq!(broken.empty.as_deref(), Some("config is broken"));
    }

    #[test]
    fn the_flyout_carries_the_notice() {
        let listing = known(Vec::new());
        let shown = flyout(&listing, &AgentState::Stopped, false, false, Some("Busy"));
        assert_eq!(shown.notice.as_deref(), Some("Busy"));
        assert_eq!(shown.title, "Stopped");
    }

    #[test]
    fn a_launch_waits_then_shows_a_fixed_line_or_the_failure() {
        let mut notice = Notice::default();
        assert_eq!(notice.text(), None);
        notice.wait();
        {
            let _zh = crate::i18n::speaking(crate::i18n::Language::Chinese);
            assert_eq!(notice.text(), Some(tr(STARTING)));
        }
        assert_eq!(notice.text(), Some(STARTING.english()));
        notice.settle(None, true);
        assert_eq!(notice.text(), Some(STARTED.english()));
        notice.wait();
        notice.settle(Some(&Note::Agent(STARTED.english().to_owned())), true);
        let _zh = crate::i18n::speaking(crate::i18n::Language::Chinese);
        assert_eq!(notice.text(), Some(STARTED.english()));
    }

    #[test]
    fn settling_only_ends_a_wait() {
        let mut notice = Notice::default();
        notice.settle(Some(&Note::Agent("Stop failed".to_owned())), true);
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
        assert_eq!(notice.text(), Some(STARTING.english()));
        notice.settle(None, false);
        notice.hidden();
        assert_eq!(notice.text(), Some(STARTED.english()));
        notice.shown();
        assert_eq!(notice.text(), Some(STARTED.english()));
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
        assert_eq!(status.logo, State::Idle);
        assert!(!status.stop);
        assert_eq!(
            tooltip(&status, false),
            "Gateinto: Checking\nWaiting for the agent status"
        );
        let f = waiting();
        assert_eq!(
            (f.title, f.subtitle.as_str()),
            (status.title, "Waiting for the agent status")
        );
        assert!(!status.start);
        assert!(!f.stop && !f.launch && f.rows.is_empty());
        assert_eq!(f.start, Launch::Hidden);
        assert_eq!((f.empty, f.notice), (None, None));
    }

    #[test]
    fn the_tray_speaks_chinese_but_agent_errors_stay_as_worded() {
        let _zh = crate::i18n::speaking(crate::i18n::Language::Chinese);
        let state = running(vec![session(1, "office", 2), session(2, "office", 0)]);
        let busy = status(&state);
        assert_eq!(busy.title, "轉送中");
        assert_eq!(busy.subtitle, "2 個工作階段 · 1 個有流量");
        assert_eq!(
            tooltip(&busy, false),
            "Gateinto：轉送中\n2 個工作階段 · 1 個有流量"
        );
        let one = status(&running(vec![session(1, "office", 0)]));
        assert_eq!(
            (one.title, one.subtitle.as_str()),
            ("閒置", "1 個工作階段 · 0 個有流量")
        );
        let stopped = status(&AgentState::Stopped);
        assert_eq!(
            (stopped.title, stopped.subtitle.as_str()),
            ("已停止", "代理程式未執行")
        );
        let lost = status(&AgentState::Unreachable(crate::i18n::Note::Agent(
            "pipe busy".to_owned(),
        )));
        assert_eq!(
            (lost.title, lost.subtitle.as_str()),
            ("無法連線到代理程式", "pipe busy")
        );
        let checking = pending();
        assert_eq!(
            (checking.title, checking.subtitle.as_str()),
            ("檢查中", "正在等候代理程式狀態")
        );

        let listing = known(vec![gateway("office", "proxy.example.com")]);
        let mut started = Notice::default();
        started.wait();
        started.settle(None, true);
        let shown = flyout(&listing, &state, false, false, started.text());
        assert_eq!(shown.rows[0].open, "2 個已開啟");
        assert_eq!(shown.notice.as_deref(), Some("已啟動瀏覽器工作階段"));
        let mut refused = Notice::default();
        refused.wait();
        refused.settle(Some(&Note::Agent(STARTED.english().to_owned())), true);
        let refused = flyout(&listing, &state, false, false, refused.text());
        assert_eq!(refused.notice.as_deref(), Some(STARTED.english()));
        let empty = flyout(&known(Vec::new()), &AgentState::Stopped, false, false, None);
        assert_eq!(empty.empty.as_deref(), Some("尚無閘道。"));

        let mut notice = Notice::default();
        notice.wait();
        let waiting = flyout(&listing, &state, false, false, notice.text());
        assert_eq!(waiting.notice.as_deref(), Some("正在啟動瀏覽器工作階段…"));
        assert_eq!(
            (tr(OPEN), tr(EXIT), tr(FLYOUT_TITLE)),
            ("開啟 Gateinto", "結束", "Gateinto 狀態")
        );
    }
}
