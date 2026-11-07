use std::net::SocketAddr;
use std::time::{Duration, Instant};

use gateinto::config::GatewayName;
use gateinto::ipc::{self, RequestError, Response, SessionAuth, SessionInfo};
use gateinto::link::Known;
use gateinto::proxy::{Verification, VerificationOrigin};
use qrcodegen_no_heap::{QrCode, QrCodeEcc, Version};
use zeroize::{DefaultIsZeroes, Zeroize, Zeroizing};

use crate::agent::AgentState;
use crate::i18n::{Text, fill, tr};
use crate::sessions;
use crate::worker::Command;

pub const WAITING: Text = Text::AskingVerification;
pub const UNAVAILABLE: Text = Text::VerificationUnavailable;
pub const NOT_OPENED: Text = Text::BrowserNotOpened;
pub const NO_QR: Text = Text::NoQrCode;
pub const COPY_FAILED: Text = Text::ClipboardFailed;
pub const RETRY: Text = Text::VerificationRetry;
pub const QUIET: usize = 4;

const MAX_URL: usize = 2048;

#[derive(Debug)]
pub struct Check {
    pub id: u64,
    pub ticket: u64,
    pub reply: Reply,
}

#[derive(Debug)]
pub enum Reply {
    Pending(GatewayName, Verification),
    Settled,
    Unreached,
}

pub fn check(id: u64, ticket: u64, reply: Result<Response, RequestError>) -> Check {
    let reply = match reply {
        Ok(Response::Ok(mut lines)) => {
            let pending = ipc::verification_from_lines(&lines);
            lines.zeroize();
            pending.map_or(Reply::Settled, |(gateway, verification)| {
                Reply::Pending(gateway, verification)
            })
        }
        Ok(Response::Error(mut message)) => {
            message.zeroize();
            Reply::Settled
        }
        Err(_) => Reply::Unreached,
    };
    Check { id, ticket, reply }
}

pub fn launchable(url: &str) -> bool {
    url.len() <= MAX_URL
        && crate::menu::https(url)
        && url
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~:/?[]@!$&'()*+,=%".contains(&byte))
}

pub fn ends(command: &Command, id: u64) -> bool {
    match command {
        Command::Stop => true,
        Command::Close(closed) | Command::Dismiss(closed, _) => *closed == id,
        _ => false,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Medium,
    Low,
}

#[derive(Debug)]
pub struct Qr {
    size: usize,
    level: Level,
    modules: Zeroizing<Vec<bool>>,
}

impl Qr {
    #[cfg(test)]
    pub fn size(&self) -> usize {
        self.size
    }

    #[cfg(test)]
    pub fn level(&self) -> Level {
        self.level
    }

    pub fn dark(&self, x: usize, y: usize) -> bool {
        self.modules[y * self.size + x]
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Run {
    pub x: usize,
    pub y: usize,
    pub len: usize,
}

impl DefaultIsZeroes for Run {}

pub fn span(qr: &Qr) -> usize {
    qr.size + 2 * QUIET
}

pub fn runs(qr: &Qr) -> Zeroizing<Vec<Run>> {
    let mut runs = Zeroizing::new(Vec::new());
    for y in 0..qr.size {
        let mut x = 0;
        while x < qr.size {
            if !qr.dark(x, y) {
                x += 1;
                continue;
            }
            let start = x;
            while x < qr.size && qr.dark(x, y) {
                x += 1;
            }
            runs.push(Run {
                x: start + QUIET,
                y: y + QUIET,
                len: x - start,
            });
        }
    }
    runs
}

pub struct Encoder {
    temp: Zeroizing<Vec<u8>>,
    out: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Encoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Encoder(<redacted>)")
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self {
            temp: Zeroizing::new(vec![0; Version::MAX.buffer_len()]),
            out: Zeroizing::new(vec![0; Version::MAX.buffer_len()]),
        }
    }
}

impl Encoder {
    pub fn encode(&mut self, text: &str) -> Option<Qr> {
        let qr = [Level::Medium, Level::Low]
            .into_iter()
            .find_map(|level| self.at(text, level));
        self.wipe();
        qr
    }

    fn at(&mut self, text: &str, level: Level) -> Option<Qr> {
        let ecl = match level {
            Level::Medium => QrCodeEcc::Medium,
            Level::Low => QrCodeEcc::Low,
        };
        let code = QrCode::encode_text(
            text,
            &mut self.temp,
            &mut self.out,
            ecl,
            Version::MIN,
            Version::MAX,
            None,
            false,
        )
        .ok()?;
        let size = usize::try_from(code.size()).ok()?;
        let mut modules = Zeroizing::new(Vec::with_capacity(size * size));
        for y in 0..code.size() {
            for x in 0..code.size() {
                modules.push(code.get_module(x, y));
            }
        }
        Some(Qr {
            size,
            level,
            modules,
        })
    }

    fn wipe(&mut self) {
        self.temp.as_mut_slice().zeroize();
        self.out.as_mut_slice().zeroize();
    }

    #[cfg(test)]
    fn clean(&self) -> bool {
        self.temp
            .iter()
            .chain(self.out.iter())
            .all(|byte| *byte == 0)
    }
}

#[derive(Debug)]
struct Shown {
    verification: Verification,
    deadline: Instant,
    qr: Option<Qr>,
}

#[derive(Debug)]
enum State {
    Waiting,
    Shown(Box<Shown>),
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Received {
    Lasts,
    Fails,
    Ends,
}

#[derive(Debug)]
pub struct Dialog {
    id: u64,
    ticket: u64,
    started: u64,
    listen: SocketAddr,
    auth: SessionAuth,
    gateway: String,
    state: State,
    encoder: Encoder,
    copied: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Page<'a> {
    pub origin: &'a str,
    pub note: Option<&'static str>,
    pub gateway: String,
    pub targets: String,
    pub url: &'a str,
    pub code: &'a str,
    pub countdown: String,
    pub qr: Option<&'a Qr>,
    pub status: Option<&'static str>,
    pub ready: bool,
    pub copied: bool,
}

impl PartialEq for Qr {
    fn eq(&self, other: &Self) -> bool {
        self.size == other.size && self.level == other.level && *self.modules == *other.modules
    }
}

impl Eq for Qr {}

fn find(state: &AgentState, id: u64) -> Option<&SessionInfo> {
    match state {
        AgentState::Running(sessions) => sessions.iter().find(|session| session.id == id),
        AgentState::Stopped | AgentState::Unreachable(_) => None,
    }
}

pub fn offers(state: &AgentState, id: u64) -> bool {
    find(state, id).is_some_and(|session| session.verification)
}

pub fn countdown(remaining: Duration) -> String {
    let seconds = remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0);
    format!("{}:{:02}", seconds / 60, seconds % 60)
}

pub fn same_origin(portal: &str, origin: &str) -> bool {
    const SCHEME: &str = "https://";
    portal
        .get(..SCHEME.len())
        .filter(|scheme| scheme.eq_ignore_ascii_case(SCHEME))
        .and_then(|_| portal[SCHEME.len()..].split(['/', '?', '#']).next())
        .and_then(|authority| {
            format!("{SCHEME}{authority}")
                .parse::<VerificationOrigin>()
                .ok()
        })
        .is_some_and(|parsed| parsed.as_str() == origin)
}

fn portal<'a>(listing: &'a Result<Known, String>, gateway: &str) -> Option<&'a str> {
    listing
        .as_ref()
        .ok()?
        .gateways
        .iter()
        .find(|known| known.name.as_str() == gateway)?
        .portal_url
        .as_ref()
        .map(|url| url.as_str())
}

impl Dialog {
    pub fn open(state: &AgentState, id: u64, ticket: u64) -> Option<Self> {
        let session = find(state, id).filter(|session| session.verification)?;
        Some(Self {
            id,
            ticket,
            started: session.started,
            listen: session.listen,
            auth: session.auth,
            gateway: session.gateway.clone(),
            state: State::Waiting,
            encoder: Encoder::default(),
            copied: false,
        })
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    #[cfg(test)]
    pub fn ticket(&self) -> u64 {
        self.ticket
    }

    pub fn receive(&mut self, check: Check, now: Instant) -> Received {
        if check.id != self.id || check.ticket != self.ticket {
            return Received::Lasts;
        }
        match (&self.state, check.reply) {
            (State::Waiting, Reply::Pending(gateway, mut verification))
                if gateway.as_str() == self.gateway && launchable(&verification.auth_uri) =>
            {
                verification.origin.make_ascii_lowercase();
                let qr = self.encoder.encode(&verification.auth_uri);
                self.state = State::Shown(Box::new(Shown {
                    deadline: now + Duration::from_secs(verification.expires_in),
                    verification,
                    qr,
                }));
                Received::Lasts
            }
            (State::Waiting, _) => {
                self.state = State::Failed;
                Received::Fails
            }
            (State::Shown(shown), Reply::Pending(_, verification))
                if shown.verification.serial == verification.serial =>
            {
                Received::Lasts
            }
            (State::Shown(_), Reply::Pending(..) | Reply::Settled) => Received::Ends,
            (State::Shown(_), Reply::Unreached) | (State::Failed, _) => Received::Lasts,
        }
    }

    pub fn lasts(&self, state: &AgentState, now: Instant) -> bool {
        let unexpired = match &self.state {
            State::Shown(shown) => now < shown.deadline,
            State::Waiting | State::Failed => true,
        };
        unexpired
            && find(state, self.id).is_some_and(|session| {
                session.verification
                    && session.started == self.started
                    && session.listen == self.listen
                    && session.auth == self.auth
            })
    }

    pub fn serial(&self) -> Option<u64> {
        match &self.state {
            State::Shown(shown) => Some(shown.verification.serial),
            State::Waiting | State::Failed => None,
        }
    }

    pub fn url(&self) -> Option<&str> {
        match &self.state {
            State::Shown(shown) => Some(shown.verification.auth_uri.as_str()),
            State::Waiting | State::Failed => None,
        }
    }

    pub fn copied(&mut self) {
        self.copied = true;
    }

    pub fn uncopy(&mut self) {
        self.copied = false;
    }

    pub fn page(
        &self,
        state: &AgentState,
        listing: &Result<Known, String>,
        names: &sessions::Names,
        now: Instant,
    ) -> Page<'_> {
        let gateway = find(state, self.id)
            .map(|session| names.label(&session.gateway, &session.upstream))
            .unwrap_or_default();
        let State::Shown(shown) = &self.state else {
            return Page {
                origin: "",
                note: None,
                gateway,
                targets: String::new(),
                url: "",
                code: "",
                countdown: String::new(),
                qr: None,
                status: Some(tr(match self.state {
                    State::Waiting => WAITING,
                    State::Shown(_) | State::Failed => UNAVAILABLE,
                })),
                ready: false,
                copied: false,
            };
        };
        let verification = &shown.verification;
        let note = portal(listing, &self.gateway).map(|portal| {
            tr(if same_origin(portal, &verification.origin) {
                Text::SameOrigin
            } else {
                Text::DifferentOrigin
            })
        });
        let mut targets = verification.targets.join(", ");
        if verification.more_targets > 0 {
            targets.push(' ');
            targets.push_str(&fill(Text::MoreTargets, &[&verification.more_targets]));
        }
        Page {
            origin: &verification.origin,
            note,
            gateway,
            targets,
            url: &verification.auth_uri,
            code: &verification.user_code,
            countdown: fill(
                Text::ExpiresIn,
                &[&countdown(shown.deadline.saturating_duration_since(now))],
            ),
            qr: shown.qr.as_ref(),
            status: None,
            ready: true,
            copied: self.copied,
        }
    }

    pub fn wipe(&mut self) {
        self.state = State::Failed;
        self.encoder.wipe();
        self.copied = false;
    }

    #[cfg(test)]
    fn wiped(&self) -> bool {
        matches!(self.state, State::Failed) && self.encoder.clean()
    }
}

impl Drop for Dialog {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use gateinto::ipc::{BrowserKind, SessionKind, SessionRoute};
    use gateinto::link::{KnownGateway, Source};
    use zeroize::Zeroizing;

    use super::*;
    use crate::credentials;

    const URL: &str = "https://verify.example.test/device?code=WDJB-MJHT";
    const CODE: &str = "WDJB-MJHT";

    fn verification(serial: u64, expires_in: u64) -> Verification {
        Verification {
            serial,
            origin: Zeroizing::new("https://verify.example.test".to_owned()),
            auth_uri: Zeroizing::new(URL.to_owned()),
            user_code: Zeroizing::new(CODE.to_owned()),
            expires_in,
            targets: vec!["intranet.example.test:443".to_owned()],
            more_targets: 0,
            suppressed: 0,
        }
    }

    fn lines(serial: u64) -> Response {
        Response::Ok(ipc::verification_lines(
            &"office".parse().unwrap(),
            &verification(serial, 600),
        ))
    }

    fn session(id: u64, flagged: bool) -> SessionInfo {
        SessionInfo {
            id,
            kind: SessionKind::Browser,
            gateway: "office".to_owned(),
            upstream: "proxy.example.com:443".to_owned(),
            listen: "127.0.0.1:49210".parse().unwrap(),
            route: SessionRoute::All,
            auth: SessionAuth::OsUser,
            started: 1_000,
            tunnels: 0,
            browser: Some(BrowserKind::Chrome),
            shell: None,
            verification: flagged,
        }
    }

    fn running() -> AgentState {
        AgentState::Running(vec![session(2, false), session(3, true)])
    }

    fn listing(portal: Option<&str>) -> Result<Known, String> {
        Ok(Known {
            gateways: vec![KnownGateway {
                name: "office".parse().unwrap(),
                display_name: None,
                host: Some("proxy.example.com".to_owned()),
                port: Some(443),
                portal_url: portal.map(|portal| portal.parse().unwrap()),
                route: gateinto::proxy::Route::Gateway,
                source: Source::Config,
            }],
            ..Known::default()
        })
    }

    fn shown(now: Instant) -> Dialog {
        let mut dialog = Dialog::open(&running(), 3, 1).unwrap();
        assert_eq!(
            dialog.receive(check(3, 1, Ok(lines(7))), now),
            Received::Lasts
        );
        dialog
    }

    #[test]
    fn a_check_keeps_only_a_well_formed_pending_verification() {
        let pending = check(3, 1, Ok(lines(7)));
        assert_eq!((pending.id, pending.ticket), (3, 1));
        let Reply::Pending(gateway, verification) = pending.reply else {
            panic!("not pending");
        };
        assert_eq!(gateway.as_str(), "office");
        assert_eq!(
            (verification.serial, verification.auth_uri.as_str()),
            (7, URL)
        );
        for reply in [
            Ok(Response::Ok(vec![format!("auth_uri: {URL}")])),
            Ok(Response::Ok(Vec::new())),
            Ok(Response::Error(format!("user_code: {CODE}"))),
        ] {
            assert!(matches!(check(3, 1, reply).reply, Reply::Settled));
        }
        for reply in [
            Err(RequestError::NotRunning),
            Err(RequestError::Io(io::Error::other(URL))),
        ] {
            assert!(matches!(check(3, 1, reply).reply, Reply::Unreached));
        }
    }

    #[test]
    fn only_flagged_sessions_offer_a_verification() {
        assert!(offers(&running(), 3));
        assert!(!offers(&running(), 2));
        assert!(!offers(&running(), 9));
        assert!(!offers(&AgentState::Stopped, 3));
        assert!(Dialog::open(&running(), 2, 1).is_none());
    }

    #[test]
    fn the_dialog_accepts_only_the_reply_for_its_id_and_ticket() {
        let now = Instant::now();
        let mut dialog = Dialog::open(&running(), 3, 2).unwrap();
        assert_eq!(
            dialog.receive(check(3, 1, Ok(lines(7))), now),
            Received::Lasts
        );
        assert_eq!(
            dialog.receive(check(4, 2, Ok(lines(7))), now),
            Received::Lasts
        );
        assert_eq!(dialog.url(), None);
        assert_eq!(
            dialog.receive(check(3, 2, Ok(lines(7))), now),
            Received::Lasts
        );
        assert_eq!((dialog.url(), dialog.serial()), (Some(URL), Some(7)));
    }

    #[test]
    fn a_first_reply_without_a_matching_verification_fails_the_dialog_once() {
        let now = Instant::now();
        let other = Response::Ok(ipc::verification_lines(
            &"home".parse().unwrap(),
            &verification(7, 600),
        ));
        let mut unsafe_url = verification(7, 600);
        unsafe_url.auth_uri = Zeroizing::new("https://verify.example.test/a\"b".to_owned());
        let unsafe_url = Response::Ok(ipc::verification_lines(
            &"office".parse().unwrap(),
            &unsafe_url,
        ));
        for reply in [
            Ok(other),
            Ok(unsafe_url),
            Ok(Response::Error("no verification is pending".to_owned())),
            Err(RequestError::NotRunning),
        ] {
            let mut dialog = Dialog::open(&running(), 3, 1).unwrap();
            assert_eq!(dialog.receive(check(3, 1, reply), now), Received::Fails);
            assert_eq!(
                dialog.receive(check(3, 1, Ok(lines(7))), now),
                Received::Lasts
            );
            assert_eq!(dialog.url(), None);
            let page = dialog.page(&running(), &listing(None), &sessions::Names::default(), now);
            assert_eq!(page.status, Some(tr(UNAVAILABLE)));
            assert!(!page.ready);
        }
    }

    #[test]
    fn the_re_check_keeps_the_dialog_only_while_the_same_serial_is_pending() {
        let now = Instant::now();
        let mut dialog = shown(now);
        assert_eq!(
            dialog.receive(check(3, 1, Ok(lines(7))), now),
            Received::Lasts
        );
        assert_eq!(
            dialog.receive(check(3, 1, Err(RequestError::NotRunning)), now),
            Received::Lasts
        );
        assert_eq!(dialog.url(), Some(URL));
        assert_eq!(
            shown(now).receive(check(3, 1, Ok(lines(8))), now),
            Received::Ends
        );
        assert_eq!(
            shown(now).receive(
                check(
                    3,
                    1,
                    Ok(Response::Error("no verification is pending".to_owned()))
                ),
                now
            ),
            Received::Ends
        );
        assert_eq!(
            shown(now).receive(check(3, 1, Ok(Response::Ok(Vec::new()))), now),
            Received::Ends
        );
    }

    #[test]
    fn the_dialog_ends_when_its_session_changes_or_the_verification_expires() {
        let now = Instant::now();
        let dialog = shown(now);
        assert!(dialog.lasts(&running(), now));
        assert!(dialog.lasts(&running(), now + Duration::from_secs(599)));
        assert!(!dialog.lasts(&running(), now + Duration::from_secs(600)));
        let changed = |change: fn(&mut SessionInfo)| {
            let mut session = session(3, true);
            change(&mut session);
            AgentState::Running(vec![session])
        };
        for state in [
            changed(|session| session.started += 1),
            changed(|session| session.listen = "127.0.0.1:49211".parse().unwrap()),
            changed(|session| session.auth = SessionAuth::Password),
            changed(|session| session.verification = false),
            AgentState::Running(vec![session(2, false)]),
            AgentState::Stopped,
            AgentState::Unreachable(crate::i18n::Note::Agent("gone".to_owned())),
        ] {
            assert!(!dialog.lasts(&state, now));
        }
        let waiting = Dialog::open(&running(), 3, 1).unwrap();
        assert!(waiting.lasts(&running(), now + Duration::from_secs(86_400)));
        assert!(!waiting.lasts(&changed(|session| session.verification = false), now));
    }

    #[test]
    fn stopping_closing_or_dismissing_the_session_ends_the_dialog() {
        assert!(ends(&Command::Stop, 3));
        assert!(ends(&Command::Close(3), 3));
        assert!(ends(&Command::Dismiss(3, 7), 3));
        assert!(!ends(&Command::Close(4), 3));
        assert!(!ends(&Command::Dismiss(4, 7), 3));
        assert!(!ends(&Command::Probe, 3));
    }

    #[test]
    fn the_link_is_cleared_only_while_the_clipboard_still_holds_it() {
        assert!(credentials::clears_clipboard(Some(41), 41));
        assert!(!credentials::clears_clipboard(Some(41), 42));
        assert!(!credentials::clears_clipboard(None, 41));
    }

    #[test]
    fn the_countdown_runs_on_the_monotonic_clock() {
        let now = Instant::now();
        let dialog = shown(now);
        let at = |seconds: f64| {
            dialog
                .page(
                    &running(),
                    &listing(None),
                    &sessions::Names::default(),
                    now + Duration::from_secs_f64(seconds),
                )
                .countdown
        };
        assert_eq!(at(0.0), "Expires in 10:00");
        assert_eq!(at(0.5), "Expires in 10:00");
        assert_eq!(at(1.0), "Expires in 9:59");
        assert_eq!(at(599.5), "Expires in 0:01");
        assert_eq!(at(700.0), "Expires in 0:00");
        assert_eq!(countdown(Duration::from_secs(65)), "1:05");
    }

    #[test]
    fn the_page_shows_the_challenge_and_notes_the_portal_origin() {
        let now = Instant::now();
        let dialog = shown(now);
        let names = sessions::Names::default();
        let page = dialog.page(&running(), &listing(None), &names, now);
        assert_eq!(page.origin, "https://verify.example.test");
        assert_eq!((page.url, page.code), (URL, CODE));
        assert_eq!(page.targets, "intranet.example.test:443");
        assert_eq!(page.note, None);
        assert!(page.ready && page.qr.is_some() && page.status.is_none());
        for (portal, note) in [
            ("https://verify.example.test/start", Text::SameOrigin),
            ("HTTPS://Verify.Example.Test:443?x", Text::SameOrigin),
            ("https://portal.example.test/", Text::DifferentOrigin),
            ("https://verify.example.test:8443/", Text::DifferentOrigin),
        ] {
            let page = dialog.page(&running(), &listing(Some(portal)), &names, now);
            assert_eq!(page.note, Some(tr(note)), "{portal}");
        }
    }

    #[test]
    fn more_targets_are_counted_after_the_listed_ones() {
        let now = Instant::now();
        let mut many = verification(7, 600);
        many.targets.push("wiki.example.test:443".to_owned());
        many.more_targets = 3;
        let mut dialog = Dialog::open(&running(), 3, 1).unwrap();
        dialog.receive(
            check(
                3,
                1,
                Ok(Response::Ok(ipc::verification_lines(
                    &"office".parse().unwrap(),
                    &many,
                ))),
            ),
            now,
        );
        let page = dialog.page(&running(), &listing(None), &sessions::Names::default(), now);
        assert_eq!(
            page.targets,
            "intranet.example.test:443, wiki.example.test:443 and 3 more"
        );
    }

    #[test]
    fn the_origin_is_shown_with_its_host_lowercased() {
        let now = Instant::now();
        let mut upper = verification(7, 600);
        upper.origin = Zeroizing::new("https://VERIFY.example.test".to_owned());
        let mut dialog = Dialog::open(&running(), 3, 1).unwrap();
        dialog.receive(
            check(
                3,
                1,
                Ok(Response::Ok(ipc::verification_lines(
                    &"office".parse().unwrap(),
                    &upper,
                ))),
            ),
            now,
        );
        let page = dialog.page(&running(), &listing(None), &sessions::Names::default(), now);
        assert_eq!(page.origin, "https://verify.example.test");
    }

    #[test]
    fn only_short_https_urls_of_safe_characters_are_launched() {
        assert!(launchable(URL));
        assert!(launchable(&format!(
            "https://a.test/{}",
            "x".repeat(2048 - 15)
        )));
        for url in [
            "http://verify.example.test/",
            "https://",
            "https://a.test/a b",
            "https://a.test/a\"b",
            "https://a.test/a\\b",
            "https://a.test/<b>",
            "https://a.test/a\u{e9}",
            "https://a.test/a\nb",
            &format!("https://a.test/{}", "x".repeat(2048 - 14)),
        ] {
            assert!(!launchable(url), "{url:?}");
        }
    }

    fn bits(qr: &Qr) -> String {
        let mut hex = String::new();
        let dark: Vec<bool> = (0..qr.size())
            .flat_map(|y| (0..qr.size()).map(move |x| (x, y)))
            .map(|(x, y)| qr.dark(x, y))
            .collect();
        for chunk in dark.chunks(8) {
            let byte = chunk
                .iter()
                .enumerate()
                .fold(0u8, |byte, (i, on)| byte | (u8::from(*on) << (7 - i)));
            hex.push_str(&format!("{byte:02x}"));
        }
        hex
    }

    #[test]
    fn a_known_url_encodes_to_its_matrix_at_level_m() {
        let qr = Encoder::default().encode(URL).unwrap();
        assert_eq!((qr.size(), qr.level()), (33, Level::Medium));
        for (x, y) in [(0, 0), (6, 0), (0, 6), (6, 6), (32, 0), (0, 32), (26, 26)] {
            assert!(qr.dark(x, y), "{x},{y}");
        }
        assert!(!qr.dark(7, 7));
        assert_eq!(bits(&qr), MATRIX);
    }

    const MATRIX: &str = concat!(
        "fe58bb3fc12493506ea4e3cbb75e26d5dba9389aec1650a507faaaaafe01953f",
        "00be3670be747f7c9b53b3f192db929cd9f773a8f9c30b6b033c6fa72bdd92f6",
        "4bc47eed4bdce8fd0cbb46b0ca3ed605f1bbe12ad36dce0a8c62269b385b3562",
        "497c5eb3d2d2f800777dc57f93736ad0534cb1dbaed86fd5d6f91e5eebce16d1",
        "0472199cfeb9c3f100",
    );

    #[test]
    fn a_text_too_long_for_level_m_falls_back_to_level_l() {
        let qr = Encoder::default().encode(&"a".repeat(2400)).unwrap();
        assert_eq!((qr.size(), qr.level()), (161, Level::Low));
    }

    #[test]
    fn a_text_too_long_for_any_level_shows_the_fixed_text() {
        let mut encoder = Encoder::default();
        assert!(encoder.encode(&"a".repeat(3000)).is_none());
        assert!(encoder.clean());
        let now = Instant::now();
        let mut dialog = Dialog::open(&running(), 3, 1).unwrap();
        dialog.encoder = Encoder {
            temp: Zeroizing::new(vec![0; 8]),
            out: Zeroizing::new(vec![0; 8]),
        };
        dialog.receive(check(3, 1, Ok(lines(7))), now);
        let page = dialog.page(&running(), &listing(None), &sessions::Names::default(), now);
        assert!(page.qr.is_none());
        assert_eq!(page.url, URL);
        assert_eq!(tr(NO_QR), "No QR code for this link.");
    }

    #[test]
    fn dark_modules_become_runs_inside_the_quiet_zone() {
        let qr = Qr {
            size: 3,
            level: Level::Medium,
            modules: Zeroizing::new(vec![
                true, true, false, //
                false, false, false, //
                true, false, true,
            ]),
        };
        assert_eq!(span(&qr), 11);
        assert_eq!(
            *runs(&qr),
            vec![
                Run { x: 4, y: 4, len: 2 },
                Run { x: 4, y: 6, len: 1 },
                Run { x: 6, y: 6, len: 1 },
            ]
        );
    }

    #[test]
    fn the_buffers_are_zeroized_after_encoding_and_when_the_dialog_ends() {
        let mut encoder = Encoder::default();
        encoder.encode(URL).unwrap();
        assert!(encoder.clean());
        let now = Instant::now();
        let mut dialog = shown(now);
        assert!(!dialog.wiped());
        dialog.copied();
        dialog.wipe();
        assert!(dialog.wiped());
        assert_eq!(dialog.url(), None);
        assert!(
            !dialog
                .page(&running(), &listing(None), &sessions::Names::default(), now)
                .copied
        );
    }

    #[test]
    fn error_texts_never_carry_the_link_or_code() {
        for text in [WAITING, UNAVAILABLE, NOT_OPENED, NO_QR, COPY_FAILED, RETRY] {
            assert!(!text.english().contains('{'), "{text:?}");
            assert!(!text.chinese().contains('{'), "{text:?}");
        }
    }
}
