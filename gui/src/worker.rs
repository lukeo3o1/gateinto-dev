use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use gateinto::config::{GatewayName, Gateways};
use gateinto::ipc::{self, Request, RequestError, Response};
use gateinto::link::Known;
use gateinto::sessions::SessionId;
use gateinto::uri::{LaunchAuth, LaunchRequest};
use tokio::sync::mpsc::UnboundedReceiver;

use crate::agent::AgentState;
use crate::credentials::{self, Reveal};
use crate::device::{KeyState, Probe, System};
use crate::i18n::{Note, Text};
use crate::log::Journal;
use crate::settings::Agent;

pub const POLL: Duration = Duration::from_secs(2);
const LOG_PAGES: usize = 16;
pub const CONFIRMATION: Text = Text::Confirmation;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Close(u64),
    Stop,
    Launch(GatewayName),
    Probe,
    Watch(bool),
    Credentials(u64, u64),
}

impl Command {
    fn request(&self) -> Result<Request, String> {
        Ok(match self {
            Command::Close(id) => Request::Close(SessionId::from(*id)),
            Command::Stop => Request::Stop,
            Command::Launch(name) => Request::Launch(
                LaunchRequest::new(name.as_str(), LaunchAuth::SessionCredentials.as_str())
                    .map_err(|error| error.to_string())?,
            ),
            Command::Probe => return Err("probing the device is not an agent request".to_owned()),
            Command::Watch(_) => {
                return Err("watching the log is not an agent request".to_owned());
            }
            Command::Credentials(..) => {
                return Err("credentials are revealed apart from commands".to_owned());
            }
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Loaded {
    pub gateways: Result<Known, String>,
    pub sections: Gateways,
    pub agent: Result<Agent, String>,
    pub listen: Result<SocketAddr, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Update {
    pub state: AgentState,
    pub gateways: Result<Known, String>,
    pub sections: Gateways,
    pub agent: Result<Agent, String>,
    pub listen: Result<SocketAddr, String>,
    pub failure: Option<Note>,
    pub launched: u64,
    pub device: Option<Probe>,
    pub log: Journal,
}

#[derive(Debug)]
pub struct Mailbox {
    open: bool,
    update: Option<Update>,
    reveal: Option<Reveal>,
}

impl Default for Mailbox {
    fn default() -> Self {
        Self {
            open: true,
            update: None,
            reveal: None,
        }
    }
}

impl Mailbox {
    pub fn put(&mut self, update: Update) -> bool {
        self.open && self.update.replace(update).is_none() && self.reveal.is_none()
    }

    pub fn put_reveal(&mut self, reveal: Reveal) -> bool {
        self.open && self.reveal.replace(reveal).is_none() && self.update.is_none()
    }

    pub fn take(&mut self) -> Option<Update> {
        self.update.take()
    }

    pub fn take_reveal(&mut self) -> Option<Reveal> {
        self.reveal.take()
    }

    pub fn close(&mut self) {
        self.open = false;
        self.update = None;
        self.reveal = None;
    }
}

pub fn stalled(error: String, loaded: Loaded) -> Update {
    Update {
        state: AgentState::Unreachable(Note::Agent(error.clone())),
        gateways: loaded.gateways,
        sections: loaded.sections,
        agent: loaded.agent,
        listen: loaded.listen,
        failure: None,
        launched: 0,
        device: Some(Probe {
            key: KeyState::Failed(error),
            system: System::default(),
        }),
        log: Journal::default(),
    }
}

pub fn failure(command: Command, reply: Result<Response, RequestError>) -> Option<Note> {
    match reply {
        Ok(Response::Ok(_)) => None,
        Ok(Response::Error(message)) => Some(Note::Agent(message)),
        Err(RequestError::NotRunning) if matches!(command, Command::Stop) => None,
        Err(error) => Some(crate::agent::note(error)),
    }
}

async fn run<F, R>(command: Command, send: &F) -> Option<Note>
where
    F: Fn(Request) -> R,
    R: Future<Output = Result<Response, RequestError>>,
{
    let request = match command.request() {
        Ok(request) => request,
        Err(error) => return Some(Note::Agent(error)),
    };
    let reply = send(request).await;
    if let Ok(Response::Ok(lines)) = &reply
        && let Some(token) = ipc::confirm_token(lines)
    {
        let _ = send(Request::Deny(token)).await;
        return Some(CONFIRMATION.into());
    }
    failure(command, reply)
}

pub async fn serve<F, R>(
    commands: UnboundedReceiver<Command>,
    send: F,
    load: impl FnMut() -> Loaded,
    probe: impl FnMut() -> Probe,
    deliver: impl FnMut(Update),
    reveal: impl FnMut(Reveal),
) where
    F: Fn(Request) -> R,
    R: Future<Output = Result<Response, RequestError>>,
{
    serve_with(|_| None, commands, send, load, probe, deliver, reveal).await;
}

pub async fn serve_with<F, R>(
    refuse: impl Fn(&Command) -> Option<Text>,
    mut commands: UnboundedReceiver<Command>,
    send: F,
    mut load: impl FnMut() -> Loaded,
    mut probe: impl FnMut() -> Probe,
    mut deliver: impl FnMut(Update),
    mut reveal: impl FnMut(Reveal),
) where
    F: Fn(Request) -> R,
    R: Future<Output = Result<Response, RequestError>>,
{
    let mut failure = None;
    let mut launched = 0;
    let mut device = None;
    let mut watching = false;
    let mut journal = Journal::default();
    loop {
        let state = AgentState::from_list(send(Request::List).await);
        match state {
            AgentState::Stopped => journal.stopped(),
            AgentState::Running(_) if watching => {
                for _ in 0..LOG_PAGES {
                    let Some(request) = journal.request() else {
                        break;
                    };
                    if !journal.absorb(send(request).await) {
                        break;
                    }
                }
            }
            AgentState::Running(_) | AgentState::Unreachable(_) => {}
        }
        let Loaded {
            gateways,
            sections,
            agent,
            listen,
        } = load();
        deliver(Update {
            state,
            gateways,
            sections,
            agent,
            listen,
            failure: failure.take(),
            launched,
            device: device.clone(),
            log: journal.clone(),
        });
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else { return };
                match command {
                    Command::Probe => {
                        device = Some(probe());
                        continue;
                    }
                    Command::Watch(on) => {
                        if on && !watching {
                            journal.reopen();
                        }
                        watching = on;
                        continue;
                    }
                    Command::Credentials(id, ticket) => {
                        let reply = send(Request::Credentials(SessionId::from(id))).await;
                        reveal(credentials::reveal(id, ticket, reply));
                        continue;
                    }
                    Command::Close(_) | Command::Stop | Command::Launch(_) => {}
                }
                let launch = matches!(command, Command::Launch(_));
                failure = match refuse(&command) {
                    Some(text) => Some(text.into()),
                    None => run(command, &send).await,
                };
                launched += u64::from(launch);
            }
            () = tokio::time::sleep(POLL) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use tokio::sync::mpsc::unbounded_channel;
    use tokio::time::timeout;

    use gateinto::config::ConfigFile;
    use gateinto::uri::{LaunchAuth, LaunchRequest};

    use gateinto::ipc::{LogEvent, LogLevel, LogPage};
    use gateinto::proxy::{DEFAULT_LISTEN, SessionCredentials};

    use super::*;
    use crate::credentials::Issued;

    fn agent(
        log: &RefCell<Vec<Request>>,
    ) -> impl Fn(Request) -> std::future::Ready<Result<Response, RequestError>> {
        move |request| {
            log.borrow_mut().push(request.clone());
            std::future::ready(Ok(match request {
                Request::Close(_) => Response::Error("no session 5".to_owned()),
                _ => Response::Ok(Vec::new()),
            }))
        }
    }

    fn said(message: &str) -> Option<Note> {
        Some(Note::Agent(message.to_owned()))
    }

    fn polled(failure: Option<Note>) -> Update {
        Update {
            state: AgentState::Running(Vec::new()),
            gateways: Ok(Known::default()),
            sections: Gateways::default(),
            agent: Ok(Agent::default()),
            listen: Ok(DEFAULT_LISTEN),
            failure,
            launched: 0,
            device: None,
            log: Journal::default(),
        }
    }

    fn loaded() -> Loaded {
        Loaded {
            gateways: Ok(Known::default()),
            sections: Gateways::default(),
            agent: Ok(Agent::default()),
            listen: Ok(DEFAULT_LISTEN),
        }
    }

    fn unprobed() -> Probe {
        panic!("probed the device without being asked")
    }

    fn unrevealed(_: Reveal) {
        panic!("revealed credentials without being asked")
    }

    const PASSWORD: &str = "abcd-efgh-jkmn";

    fn revealer(
        log: &RefCell<Vec<Request>>,
    ) -> impl Fn(Request) -> std::future::Ready<Result<Response, RequestError>> {
        move |request| {
            log.borrow_mut().push(request.clone());
            std::future::ready(Ok(match request {
                Request::Credentials(_) => Response::Ok(vec![
                    "listen: 127.0.0.1:8080".to_owned(),
                    "username: gateinto".to_owned(),
                    format!("password: {PASSWORD}"),
                ]),
                _ => Response::Ok(Vec::new()),
            }))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn credentials_are_asked_once_for_the_chosen_session_and_never_by_polls() {
        let log = RefCell::new(Vec::new());
        let (tx, rx) = unbounded_channel();
        tx.send(Command::Credentials(7, 4)).unwrap();
        let reveals = RefCell::new(Vec::new());
        let updates = RefCell::new(Vec::new());
        let run = serve(
            rx,
            revealer(&log),
            loaded,
            unprobed,
            |u| updates.borrow_mut().push(u),
            |r| reveals.borrow_mut().push(r),
        );
        assert!(timeout(Duration::from_millis(4_500), run).await.is_err());
        assert_eq!(
            *log.borrow(),
            [
                Request::List,
                Request::Credentials(SessionId::from(7)),
                Request::List,
                Request::List,
                Request::List
            ]
        );
        let reveals = reveals.borrow();
        assert_eq!(reveals.len(), 1);
        assert_eq!((reveals[0].id, reveals[0].ticket), (7, 4));
        let credentials = reveals[0].credentials.as_ref().unwrap();
        assert_eq!(
            (credentials.username(), credentials.password()),
            ("gateinto", PASSWORD)
        );
        assert!(updates.borrow().iter().all(|u| *u == polled(None)));
    }

    fn probe(n: u32) -> Probe {
        Probe {
            key: KeyState::Failed(format!("probe {n}")),
            system: System::default(),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_probe_reads_the_device_once_and_later_polls_keep_it() {
        let log = RefCell::new(Vec::new());
        let (tx, rx) = unbounded_channel();
        tx.send(Command::Probe).unwrap();
        let probes = RefCell::new(0);
        let read = || {
            *probes.borrow_mut() += 1;
            probe(*probes.borrow())
        };
        let mut updates = Vec::new();
        let run = serve(
            rx,
            agent(&log),
            loaded,
            read,
            |u| updates.push(u.device),
            unrevealed,
        );
        assert!(timeout(Duration::from_millis(4_500), run).await.is_err());
        assert_eq!(
            updates,
            [None, Some(probe(1)), Some(probe(1)), Some(probe(1))]
        );
        assert_eq!(*probes.borrow(), 1);
        assert_eq!(log.borrow().len(), 4);
        assert!(log.borrow().iter().all(|r| *r == Request::List));
    }

    fn launched(update: Update) -> Update {
        Update {
            launched: 1,
            ..update
        }
    }

    #[tokio::test(start_paused = true)]
    async fn polls_at_once_and_then_every_two_seconds() {
        let log = RefCell::new(Vec::new());
        let (_tx, rx) = unbounded_channel();
        let mut updates = Vec::new();
        let run = serve(
            rx,
            agent(&log),
            loaded,
            unprobed,
            |u| updates.push(u),
            unrevealed,
        );
        assert!(timeout(Duration::from_millis(4_500), run).await.is_err());
        assert_eq!(updates, [polled(None), polled(None), polled(None)]);
        assert_eq!(*log.borrow(), [Request::List, Request::List, Request::List]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_command_is_followed_by_a_poll_that_carries_its_failure_once() {
        let log = RefCell::new(Vec::new());
        let (tx, rx) = unbounded_channel();
        tx.send(Command::Close(5)).unwrap();
        let mut updates = Vec::new();
        let run = serve(
            rx,
            agent(&log),
            loaded,
            unprobed,
            |u| updates.push(u),
            unrevealed,
        );
        assert!(timeout(Duration::from_millis(2_500), run).await.is_err());
        assert_eq!(
            updates,
            [polled(None), polled(said("no session 5")), polled(None)]
        );
        assert_eq!(
            *log.borrow(),
            [
                Request::List,
                Request::Close(SessionId::from(5)),
                Request::List,
                Request::List
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stops_when_the_window_drops_its_sender() {
        let log = RefCell::new(Vec::new());
        let (tx, rx) = unbounded_channel::<Command>();
        drop(tx);
        let mut updates = Vec::new();
        let run = serve(
            rx,
            agent(&log),
            loaded,
            unprobed,
            |u| updates.push(u),
            unrevealed,
        );
        assert!(timeout(Duration::from_secs(10), run).await.is_ok());
        assert_eq!(updates, [polled(None)]);
    }

    #[tokio::test(start_paused = true)]
    async fn every_poll_rereads_the_gateways_agent_and_listen_settings() {
        let log = RefCell::new(Vec::new());
        let (_tx, rx) = unbounded_channel();
        let reads = RefCell::new(0);
        let read = |n: u32| Loaded {
            gateways: Err(format!("gateways {n}")),
            sections: ConfigFile::parse(&format!("[gateways.g{n}]\nhost = \"h{n}\"\n"))
                .unwrap()
                .gateways,
            agent: Err(format!("agent {n}")),
            listen: Err(format!("listen {n}")),
        };
        let load = || {
            *reads.borrow_mut() += 1;
            read(*reads.borrow())
        };
        let mut updates = Vec::new();
        let run = serve(
            rx,
            agent(&log),
            load,
            unprobed,
            |u| {
                updates.push(Loaded {
                    gateways: u.gateways,
                    sections: u.sections,
                    agent: u.agent,
                    listen: u.listen,
                })
            },
            unrevealed,
        );
        assert!(timeout(Duration::from_millis(2_500), run).await.is_err());
        assert_eq!(updates, [read(1), read(2)]);
    }

    fn launcher(
        log: &RefCell<Vec<Request>>,
        lines: Vec<String>,
    ) -> impl Fn(Request) -> std::future::Ready<Result<Response, RequestError>> {
        move |request| {
            log.borrow_mut().push(request.clone());
            std::future::ready(Ok(match request {
                Request::Launch(_) => Response::Ok(lines.clone()),
                _ => Response::Ok(Vec::new()),
            }))
        }
    }

    fn launch(name: &str) -> Request {
        Request::Launch(LaunchRequest::new(name, LaunchAuth::SessionCredentials.as_str()).unwrap())
    }

    #[tokio::test(start_paused = true)]
    async fn launching_a_known_gateway_asks_for_a_browser_session() {
        let log = RefCell::new(Vec::new());
        let (tx, rx) = unbounded_channel();
        tx.send(Command::Launch("office".parse().unwrap())).unwrap();
        let lines = vec!["session 3".to_owned(), "password: secret".to_owned()];
        let mut updates = Vec::new();
        let run = serve(
            rx,
            launcher(&log, lines),
            loaded,
            unprobed,
            |u| updates.push(u),
            unrevealed,
        );
        assert!(timeout(Duration::from_millis(500), run).await.is_err());
        assert_eq!(updates, [polled(None), launched(polled(None))]);
        assert_eq!(
            *log.borrow(),
            [Request::List, launch("office"), Request::List]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_launch_that_asks_for_confirmation_is_denied_and_fails() {
        let log = RefCell::new(Vec::new());
        let (tx, rx) = unbounded_channel();
        tx.send(Command::Launch("office".parse().unwrap())).unwrap();
        let token = "0123456789abcdef0123456789abcdef";
        let lines = vec![format!("confirm: {token}")];
        let mut updates = Vec::new();
        let run = serve(
            rx,
            launcher(&log, lines),
            loaded,
            unprobed,
            |u| updates.push(u),
            unrevealed,
        );
        assert!(timeout(Duration::from_millis(500), run).await.is_err());
        assert_eq!(
            updates,
            [polled(None), launched(polled(Some(CONFIRMATION.into())))]
        );
        assert_eq!(
            *log.borrow(),
            [
                Request::List,
                launch("office"),
                Request::Deny(token.parse().unwrap()),
                Request::List
            ]
        );
    }

    fn logger(
        log: &RefCell<Vec<Request>>,
        answer: impl Fn(u64) -> Response,
    ) -> impl Fn(Request) -> std::future::Ready<Result<Response, RequestError>> {
        move |request| {
            log.borrow_mut().push(request.clone());
            std::future::ready(Ok(match request {
                Request::Log { after } => answer(after),
                _ => Response::Ok(Vec::new()),
            }))
        }
    }

    fn log_page(last: u64, seqs: std::ops::RangeInclusive<u64>) -> Response {
        let page = LogPage {
            last,
            events: seqs
                .map(|seq| LogEvent {
                    seq,
                    time: 0,
                    level: LogLevel::Info,
                    scope: "agent".to_owned(),
                    message: format!("event {seq}"),
                })
                .collect(),
        };
        let mut lines = vec!["agent-pid: 9".to_owned()];
        lines.extend(page.to_lines());
        Response::Ok(lines)
    }

    fn logged(update: &Update) -> Vec<u64> {
        update.log.events().iter().map(|event| event.seq).collect()
    }

    #[tokio::test(start_paused = true)]
    async fn the_log_is_read_only_while_its_page_is_watched() {
        let log = RefCell::new(Vec::new());
        let (tx, rx) = unbounded_channel();
        tx.send(Command::Watch(true)).unwrap();
        let answer = |after: u64| log_page(2, after + 1..=2);
        let mut updates = Vec::new();
        let run = serve(
            rx,
            logger(&log, answer),
            loaded,
            unprobed,
            |u| updates.push(u),
            unrevealed,
        );
        assert!(timeout(Duration::from_millis(2_500), run).await.is_err());
        assert_eq!(
            *log.borrow(),
            [
                Request::List,
                Request::List,
                Request::Log { after: 0 },
                Request::List,
                Request::Log { after: 2 },
            ]
        );
        let seen: Vec<Vec<u64>> = updates.iter().map(logged).collect();
        assert_eq!(seen, [vec![], vec![1, 2], vec![1, 2]]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_page_left_stops_the_log_requests_and_keeps_what_was_read() {
        let log = RefCell::new(Vec::new());
        let (tx, rx) = unbounded_channel();
        tx.send(Command::Watch(true)).unwrap();
        tx.send(Command::Watch(false)).unwrap();
        let answer = |after: u64| log_page(1, after + 1..=1);
        let mut updates = Vec::new();
        let run = serve(
            rx,
            logger(&log, answer),
            loaded,
            unprobed,
            |u| updates.push(u),
            unrevealed,
        );
        assert!(timeout(Duration::from_millis(2_500), run).await.is_err());
        assert_eq!(
            *log.borrow(),
            [
                Request::List,
                Request::List,
                Request::Log { after: 0 },
                Request::List,
                Request::List,
            ]
        );
        assert_eq!(logged(updates.last().unwrap()), [1]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_long_log_is_read_page_by_page_within_one_poll() {
        let log = RefCell::new(Vec::new());
        let (tx, rx) = unbounded_channel();
        tx.send(Command::Watch(true)).unwrap();
        let answer = |after: u64| log_page(5, after + 1..=(after + 2).min(5));
        let mut updates = Vec::new();
        let run = serve(
            rx,
            logger(&log, answer),
            loaded,
            unprobed,
            |u| updates.push(u),
            unrevealed,
        );
        assert!(timeout(Duration::from_millis(500), run).await.is_err());
        let asked: Vec<Request> = log.borrow()[2..].to_vec();
        assert_eq!(
            asked,
            [
                Request::Log { after: 0 },
                Request::Log { after: 2 },
                Request::Log { after: 4 },
            ]
        );
        assert_eq!(logged(&updates[1]), [1, 2, 3, 4, 5]);
    }

    #[tokio::test(start_paused = true)]
    async fn an_older_agent_is_asked_for_its_log_once_per_visit() {
        let log = RefCell::new(Vec::new());
        let (tx, rx) = unbounded_channel();
        tx.send(Command::Watch(true)).unwrap();
        let answer = |_| Response::Error(ipc::INVALID_REQUEST.to_owned());
        let mut updates = Vec::new();
        let run = serve(
            rx,
            logger(&log, answer),
            loaded,
            unprobed,
            |u| updates.push(u),
            unrevealed,
        );
        assert!(timeout(Duration::from_millis(4_500), run).await.is_err());
        let asked = log
            .borrow()
            .iter()
            .filter(|request| matches!(request, Request::Log { .. }))
            .count();
        assert_eq!(asked, 1);
        assert_eq!(
            updates.last().unwrap().log.problem(),
            Some(crate::log::OLDER.english())
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_stopped_agent_is_not_asked_for_its_log() {
        let log = RefCell::new(Vec::new());
        let (tx, rx) = unbounded_channel();
        tx.send(Command::Watch(true)).unwrap();
        let send = |request: Request| {
            log.borrow_mut().push(request);
            std::future::ready(Err(RequestError::NotRunning))
        };
        let mut updates = Vec::new();
        let run = serve(rx, send, loaded, unprobed, |u| updates.push(u), unrevealed);
        assert!(timeout(Duration::from_millis(2_500), run).await.is_err());
        assert!(log.borrow().iter().all(|request| *request == Request::List));
        assert!(
            updates
                .iter()
                .all(|update| update.log == Journal::default())
        );
    }

    #[test]
    fn a_worker_that_cannot_start_shows_why_instead_of_waiting_for_the_device() {
        let update = stalled("no timer".to_owned(), loaded());
        assert_eq!(
            update,
            Update {
                state: AgentState::Unreachable(crate::i18n::Note::Agent("no timer".to_owned())),
                device: Some(Probe {
                    key: KeyState::Failed("no timer".to_owned()),
                    system: System::default(),
                }),
                ..polled(None)
            }
        );
    }

    #[test]
    fn a_mailbox_asks_for_a_notice_only_when_it_was_empty() {
        let mut mailbox = Mailbox::default();
        assert!(mailbox.put(polled(None)));
        assert!(!mailbox.put(polled(said("busy"))));
        assert_eq!(mailbox.take(), Some(polled(said("busy"))));
        assert_eq!(mailbox.take(), None);
        assert!(mailbox.put(polled(None)));
    }

    #[test]
    fn a_closed_mailbox_drops_what_it_holds_and_what_arrives() {
        let mut mailbox = Mailbox::default();
        mailbox.put(polled(None));
        mailbox.close();
        assert_eq!(mailbox.take(), None);
        assert!(!mailbox.put(polled(None)));
        assert_eq!(mailbox.take(), None);
    }

    fn revealed(id: u64) -> Reveal {
        Reveal {
            id,
            ticket: 1,
            credentials: SessionCredentials::parse("gateinto", PASSWORD).map(Issued::Agent),
        }
    }

    #[test]
    fn a_mailbox_holds_one_reveal_apart_from_updates_and_shares_one_notice() {
        let mut mailbox = Mailbox::default();
        assert!(mailbox.put_reveal(revealed(3)));
        assert!(!mailbox.put(polled(None)));
        assert!(!mailbox.put_reveal(revealed(4)));
        assert_eq!(mailbox.take_reveal().map(|reveal| reveal.id), Some(4));
        assert_eq!(mailbox.take_reveal().map(|reveal| reveal.id), None);
        assert_eq!(mailbox.take(), Some(polled(None)));
        assert!(mailbox.put(polled(None)));
        assert!(!mailbox.put_reveal(revealed(5)));
    }

    #[test]
    fn a_closed_mailbox_drops_a_reveal_and_refuses_new_ones() {
        let mut mailbox = Mailbox::default();
        mailbox.put_reveal(revealed(3));
        mailbox.close();
        assert!(mailbox.take_reveal().is_none());
        assert!(!mailbox.put_reveal(revealed(3)));
        assert!(mailbox.take_reveal().is_none());
    }

    #[test]
    fn commands_fail_with_the_agent_error_or_the_request_error() {
        assert_eq!(
            failure(Command::Close(1), Ok(Response::Ok(Vec::new()))),
            None
        );
        assert_eq!(
            failure(
                Command::Close(1),
                Ok(Response::Error("no session 1".to_owned()))
            ),
            said("no session 1")
        );
        assert_eq!(
            failure(Command::Close(1), Err(RequestError::NotRunning)),
            Some(Text::AgentNotRunning.into())
        );
        assert_eq!(
            failure(Command::Stop, Err(RequestError::Closed)),
            Some(Text::AgentClosed.into())
        );
    }

    #[test]
    fn stopping_an_agent_that_is_not_running_is_not_a_failure() {
        assert_eq!(failure(Command::Stop, Err(RequestError::NotRunning)), None);
        let office = || Command::Launch("office".parse().unwrap());
        assert_eq!(
            failure(office(), Err(RequestError::NotRunning)),
            Some(Text::AgentNotRunning.into())
        );
    }

    #[test]
    fn the_confirmation_notice_is_worded_by_the_gui() {
        let _zh = crate::i18n::speaking(crate::i18n::Language::Chinese);
        assert_eq!(
            Note::from(CONFIRMATION).shown(),
            "代理程式要求確認此閘道；請開啟其 gateinto:// 連結以確認"
        );
    }
}
