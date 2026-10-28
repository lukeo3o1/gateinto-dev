use std::net::SocketAddr;

use gateinto::ipc::{self, RequestError, Response, SessionAuth, SessionInfo};
use gateinto::proxy::SessionCredentials;
use zeroize::Zeroize;

use crate::agent::AgentState;
use crate::i18n::{Text, fill, tr};
use crate::sessions;

pub const MASK: &str = "\u{2022}\u{2022}\u{2022}\u{2022}-\u{2022}\u{2022}\u{2022}\u{2022}-\u{2022}\u{2022}\u{2022}\u{2022}";
pub const WAITING: Text = Text::AskingCredentials;
pub const UNAVAILABLE: Text = Text::CredentialsUnavailable;
pub const SUBTITLE: Text = Text::CredentialsSubtitle;
pub const COPY_FAILED: Text = Text::ClipboardFailed;
pub const HINT: Text = Text::HyphenHint;

#[derive(Debug)]
pub struct Reveal {
    pub id: u64,
    pub ticket: u64,
    pub credentials: Option<Issued>,
}

#[derive(Debug)]
pub enum Issued {
    Agent(SessionCredentials),
    Demo,
}

impl Issued {
    pub fn username(&self) -> &str {
        match self {
            Self::Agent(credentials) => credentials.username(),
            Self::Demo => "demo-user",
        }
    }

    pub fn password(&self) -> &str {
        match self {
            Self::Agent(credentials) => credentials.password(),
            Self::Demo => "demo-password",
        }
    }
}

pub fn reveal(id: u64, ticket: u64, reply: Result<Response, RequestError>) -> Reveal {
    let credentials = match reply {
        Ok(Response::Ok(mut lines)) => {
            let credentials = ipc::issued_credentials(&lines);
            lines.zeroize();
            credentials.map(Issued::Agent)
        }
        Ok(Response::Error(mut message)) => {
            message.zeroize();
            None
        }
        Err(_) => None,
    };
    Reveal {
        id,
        ticket,
        credentials,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Username,
    Password,
}

#[derive(Debug)]
enum Secret {
    Waiting,
    Shown(Issued),
    Failed,
}

#[derive(Debug)]
pub struct Dialog {
    id: u64,
    ticket: u64,
    started: u64,
    listen: SocketAddr,
    secret: Secret,
    revealed: bool,
    copied: Option<Field>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Page<'a> {
    pub session: String,
    pub detail: String,
    pub username: &'a str,
    pub password: &'a str,
    pub revealed: bool,
    pub ready: bool,
    pub copied: Option<Field>,
    pub note: Option<&'static str>,
    pub warning: String,
}

fn find(state: &AgentState, id: u64) -> Option<&SessionInfo> {
    match state {
        AgentState::Running(sessions) => sessions.iter().find(|session| session.id == id),
        AgentState::Stopped | AgentState::Unreachable(_) => None,
    }
}

pub fn offers(state: &AgentState, id: u64) -> bool {
    find(state, id).is_some_and(|session| session.auth == SessionAuth::Password)
}

pub fn clears_clipboard(copied: Option<u32>, sequence: u32) -> bool {
    copied == Some(sequence)
}

pub fn deliver(dialog: Option<&mut Dialog>, reveal: Reveal) -> bool {
    let Some(dialog) = dialog else {
        return false;
    };
    dialog.receive(reveal);
    matches!(dialog.secret, Secret::Shown(_))
}

impl Dialog {
    pub fn open(state: &AgentState, id: u64, ticket: u64) -> Option<Self> {
        let session = find(state, id).filter(|session| session.auth == SessionAuth::Password)?;
        Some(Self {
            id,
            ticket,
            started: session.started,
            listen: session.listen,
            secret: Secret::Waiting,
            revealed: false,
            copied: None,
        })
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn receive(&mut self, reveal: Reveal) {
        let asked = reveal.id == self.id && reveal.ticket == self.ticket;
        if asked && matches!(self.secret, Secret::Waiting) {
            self.secret = reveal.credentials.map_or(Secret::Failed, Secret::Shown);
        }
    }

    pub fn lasts(&self, state: &AgentState) -> bool {
        find(state, self.id).is_some_and(|session| {
            session.started == self.started
                && session.listen == self.listen
                && session.auth == SessionAuth::Password
        })
    }

    pub fn toggle(&mut self) {
        if matches!(self.secret, Secret::Shown(_)) {
            self.revealed = !self.revealed;
        }
    }

    pub fn secret(&self, field: Field) -> Option<&str> {
        match (&self.secret, field) {
            (Secret::Shown(credentials), Field::Username) => Some(credentials.username()),
            (Secret::Shown(credentials), Field::Password) => Some(credentials.password()),
            (Secret::Waiting | Secret::Failed, _) => None,
        }
    }

    pub fn copied(&mut self, field: Field) {
        self.copied = Some(field);
    }

    pub fn uncopy(&mut self) {
        self.copied = None;
    }

    pub fn page(&self, state: &AgentState) -> Page<'_> {
        let listen = self.listen.to_string();
        let mut detail = Vec::new();
        let mut session = String::new();
        if let Some(info) = find(state, self.id) {
            let row = sessions::row(info, info.started);
            session = format!("{}{}", row.title, row.number);
            if row.gateway != row.address {
                detail.push(row.gateway);
            }
            detail.push(row.address);
        }
        detail.push(fill(Text::DialogNames, &[&listen]));
        let (username, password, note) = match &self.secret {
            Secret::Shown(credentials) => (
                credentials.username(),
                if self.revealed {
                    credentials.password()
                } else {
                    MASK
                },
                None,
            ),
            Secret::Waiting => ("", "", Some(tr(WAITING))),
            Secret::Failed => ("", "", Some(tr(UNAVAILABLE))),
        };
        Page {
            session,
            detail: detail.join(" \u{b7} "),
            username,
            password,
            revealed: self.revealed,
            ready: note.is_none(),
            copied: self.copied,
            note,
            warning: fill(Text::CredentialsWarning, &[&listen]),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use gateinto::ipc::{BrowserKind, SessionAuth, SessionInfo, SessionKind, SessionRoute};

    use super::*;
    use crate::agent::AgentState;

    const PASSWORD: &str = "abcd-efgh-jkmn";

    fn issued() -> Response {
        Response::Ok(vec![
            "listen: 127.0.0.1:49210".to_owned(),
            "username: gateinto".to_owned(),
            format!("password: {PASSWORD}"),
        ])
    }

    fn session(id: u64, auth: SessionAuth) -> SessionInfo {
        SessionInfo {
            id,
            kind: SessionKind::Browser,
            gateway: "office".to_owned(),
            upstream: "proxy.example.com:443".to_owned(),
            listen: "127.0.0.1:49210".parse().unwrap(),
            route: SessionRoute::All,
            auth,
            started: 1_000,
            tunnels: 0,
            browser: Some(BrowserKind::Chrome),
        }
    }

    fn running() -> AgentState {
        AgentState::Running(vec![
            session(2, SessionAuth::OsUser),
            session(3, SessionAuth::Password),
        ])
    }

    fn shown() -> Dialog {
        let mut dialog = Dialog::open(&running(), 3, 1).unwrap();
        dialog.receive(reveal(3, 1, Ok(issued())));
        dialog
    }

    #[test]
    fn a_reveal_keeps_only_well_formed_credentials() {
        let revealed = reveal(3, 1, Ok(issued()));
        assert_eq!((revealed.id, revealed.ticket), (3, 1));
        let credentials = revealed.credentials.unwrap();
        assert_eq!(credentials.username(), "gateinto");
        assert_eq!(credentials.password(), PASSWORD);
        let malformed = Response::Ok(vec![
            "username: gateinto".to_owned(),
            "password: abcd".to_owned(),
        ]);
        for reply in [
            Ok(malformed),
            Ok(Response::Ok(Vec::new())),
            Ok(Response::Error(format!("password: {PASSWORD}"))),
            Err(RequestError::NotRunning),
            Err(RequestError::Io(io::Error::other(PASSWORD))),
        ] {
            assert!(reveal(3, 1, reply).credentials.is_none());
        }
    }

    #[test]
    fn demo_credentials_show_their_placeholder_values() {
        let mut dialog = Dialog::open(&running(), 3, 1).unwrap();
        dialog.receive(Reveal {
            id: 3,
            ticket: 1,
            credentials: Some(Issued::Demo),
        });
        dialog.toggle();
        let page = dialog.page(&running());
        assert_eq!(
            (page.username, page.password),
            ("demo-user", "demo-password")
        );
        assert_eq!(dialog.secret(Field::Password), Some("demo-password"));
    }

    #[test]
    fn only_sessions_signed_in_with_session_credentials_offer_them() {
        assert!(offers(&running(), 3));
        assert!(!offers(&running(), 2));
        assert!(!offers(&running(), 9));
        assert!(!offers(&AgentState::Stopped, 3));
        assert!(Dialog::open(&running(), 2, 1).is_none());
        assert!(Dialog::open(&AgentState::Stopped, 3, 1).is_none());
        assert_eq!(Dialog::open(&running(), 3, 1).unwrap().id(), 3);
    }

    #[test]
    fn a_waiting_dialog_shows_nothing_secret_and_cannot_copy() {
        let mut dialog = Dialog::open(&running(), 3, 1).unwrap();
        let page = dialog.page(&running());
        assert_eq!(page.session, "Chrome #3");
        assert_eq!(
            page.detail,
            "office · proxy.example.com · sign-in dialog names 127.0.0.1:49210"
        );
        assert_eq!(page.note, Some(WAITING.english()));
        assert!(!page.ready);
        assert_eq!(page.username, "");
        assert_eq!(page.password, "");
        assert_eq!(
            page.warning,
            "Enter these only in the browser's proxy sign-in dialog that names \
             127.0.0.1:49210. Never enter them in a website's sign-in page or dialog."
        );
        assert_eq!(dialog.secret(Field::Password), None);
        dialog.toggle();
        assert!(!dialog.page(&running()).revealed);
    }

    #[test]
    fn the_credentials_page_speaks_chinese() {
        let _zh = crate::i18n::speaking(crate::i18n::Language::Chinese);
        let dialog = Dialog::open(&running(), 3, 1).unwrap();
        let page = dialog.page(&running());
        assert_eq!(
            page.detail,
            "office · proxy.example.com · 登入對話框會顯示 127.0.0.1:49210"
        );
        assert_eq!(
            page.note,
            Some("正在向代理程式索取此工作階段的憑證\u{2026}")
        );
        assert_eq!(
            page.warning,
            "只能在顯示 127.0.0.1:49210 的瀏覽器 Proxy 登入對話框中輸入。\
             切勿在網站的登入頁面或對話框中輸入。"
        );
    }

    #[test]
    fn the_password_stays_masked_until_shown() {
        let mut dialog = shown();
        let page = dialog.page(&running());
        assert!(page.ready);
        assert_eq!(page.note, None);
        assert_eq!(page.username, "gateinto");
        assert_eq!(page.password, MASK);
        assert!(!page.revealed);
        dialog.toggle();
        let page = dialog.page(&running());
        assert_eq!(page.password, PASSWORD);
        assert!(page.revealed);
        dialog.toggle();
        assert_eq!(dialog.page(&running()).password, MASK);
    }

    #[test]
    fn copies_hand_out_the_value_and_mark_their_field() {
        let mut dialog = shown();
        assert_eq!(dialog.secret(Field::Username), Some("gateinto"));
        assert_eq!(dialog.secret(Field::Password), Some(PASSWORD));
        dialog.copied(Field::Password);
        assert_eq!(dialog.page(&running()).copied, Some(Field::Password));
        dialog.uncopy();
        assert_eq!(dialog.page(&running()).copied, None);
    }

    #[test]
    fn a_reveal_for_another_session_or_a_second_reveal_is_dropped() {
        let mut dialog = Dialog::open(&running(), 3, 1).unwrap();
        dialog.receive(reveal(2, 1, Ok(issued())));
        assert_eq!(dialog.secret(Field::Password), None);
        assert_eq!(dialog.page(&running()).note, Some(WAITING.english()));
        dialog.receive(reveal(3, 1, Err(RequestError::NotRunning)));
        dialog.receive(reveal(3, 1, Ok(issued())));
        assert_eq!(dialog.secret(Field::Password), None);
        assert_eq!(dialog.page(&running()).note, Some(UNAVAILABLE.english()));
    }

    #[test]
    fn a_reveal_asked_by_an_earlier_dialog_is_dropped() {
        let mut dialog = Dialog::open(&running(), 3, 2).unwrap();
        assert!(!deliver(Some(&mut dialog), reveal(3, 1, Ok(issued()))));
        assert_eq!(dialog.secret(Field::Password), None);
        assert_eq!(dialog.page(&running()).note, Some(WAITING.english()));
        assert!(deliver(Some(&mut dialog), reveal(3, 2, Ok(issued()))));
        assert_eq!(dialog.secret(Field::Password), Some(PASSWORD));
    }

    #[test]
    fn a_reveal_arriving_after_the_dialog_closed_is_dropped() {
        assert!(!deliver(None, reveal(3, 1, Ok(issued()))));
    }

    #[test]
    fn the_failure_note_is_fixed_whatever_the_agent_said() {
        let mut dialog = Dialog::open(&running(), 3, 1).unwrap();
        dialog.receive(reveal(
            3,
            1,
            Ok(Response::Error(format!("bad password: {PASSWORD}"))),
        ));
        let page = dialog.page(&running());
        assert_eq!(page.note, Some(UNAVAILABLE.english()));
        assert!(!page.ready);
        assert!(!UNAVAILABLE.english().contains(PASSWORD));
    }

    #[test]
    fn a_dialog_lasts_only_while_its_session_does() {
        let dialog = shown();
        assert!(dialog.lasts(&running()));
        assert!(!dialog.lasts(&AgentState::Stopped));
        assert!(
            !dialog.lasts(&AgentState::Unreachable(crate::i18n::Note::Agent(
                "gone".to_owned()
            )))
        );
        assert!(!dialog.lasts(&AgentState::Running(vec![session(2, SessionAuth::OsUser)])));
        let mut restarted = session(3, SessionAuth::Password);
        restarted.started = 2_000;
        assert!(!dialog.lasts(&AgentState::Running(vec![restarted])));
        let mut moved = session(3, SessionAuth::Password);
        moved.listen = "127.0.0.1:49211".parse().unwrap();
        assert!(!dialog.lasts(&AgentState::Running(vec![moved])));
    }

    #[test]
    fn a_profile_gateway_is_named_once_by_its_host() {
        let mut profile = session(3, SessionAuth::Password);
        profile.gateway = format!("g-{}", "a".repeat(62));
        let state = AgentState::Running(vec![profile]);
        let dialog = Dialog::open(&state, 3, 1).unwrap();
        assert_eq!(
            dialog.page(&state).detail,
            "proxy.example.com · sign-in dialog names 127.0.0.1:49210"
        );
    }

    #[test]
    fn the_clipboard_is_cleared_only_while_it_still_holds_the_copied_secret() {
        assert!(clears_clipboard(Some(5), 5));
        assert!(!clears_clipboard(Some(5), 6));
        assert!(!clears_clipboard(None, 5));
    }
}
