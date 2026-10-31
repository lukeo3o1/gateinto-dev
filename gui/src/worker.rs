use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use gateinto::config::{GatewayName, Gateways};
use gateinto::ipc::{self, Request, RequestError, Response};
use gateinto::link::approval::{ApprovalError, settle};
use gateinto::link::{Confirmation, Known};
use gateinto::sessions::SessionId;
use gateinto::uri::{LaunchAuth, LaunchRequest};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::oneshot;

use crate::agent::{AgentState, Config};
use crate::approval::{self, Answer, Desk};
use crate::credentials::{self, Reveal};
use crate::device::{KeyState, Probe, System};
use crate::i18n::{Note, Text};
use crate::log::Journal;
use crate::settings::Agent;
use crate::start::Starting;

pub const POLL: Duration = Duration::from_secs(2);
const LOG_PAGES: usize = 16;
pub const CONFIRMATION: Text = Text::Confirmation;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Close(u64),
    Stop,
    Start,
    Launch(GatewayName),
    Probe,
    Watch(bool),
    Credentials(u64, u64),
    Link(LaunchRequest),
    Answer(u64, Answer),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Prompt {
    Ask(u64, Confirmation),
    Dismiss(u64),
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
            Command::Start => return Err("starting the agent is not an agent request".to_owned()),
            Command::Probe => return Err("probing the device is not an agent request".to_owned()),
            Command::Watch(_) => {
                return Err("watching the log is not an agent request".to_owned());
            }
            Command::Credentials(..) => {
                return Err("credentials are revealed apart from commands".to_owned());
            }
            Command::Link(_) | Command::Answer(..) => {
                return Err("links are settled apart from commands".to_owned());
            }
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Loaded {
    pub gateways: Result<Known, String>,
    pub sections: Gateways,
    pub agent: Result<Agent, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Update {
    pub state: AgentState,
    pub gateways: Result<Known, String>,
    pub sections: Gateways,
    pub agent: Result<Agent, String>,
    pub failure: Option<Note>,
    pub launched: u64,
    pub device: Option<Probe>,
    pub log: Journal,
    pub starting: Starting,
    pub config: Config,
}

#[derive(Debug, Default)]
pub struct Mail {
    pub update: Option<Update>,
    pub reveal: Option<Reveal>,
    pub prompt: Option<Prompt>,
}

#[derive(Debug)]
pub struct Mailbox {
    open: bool,
    mail: Mail,
}

impl Default for Mailbox {
    fn default() -> Self {
        Self {
            open: true,
            mail: Mail::default(),
        }
    }
}

impl Mailbox {
    fn deliver(&mut self, put: impl FnOnce(&mut Mail)) -> bool {
        if !self.open {
            return false;
        }
        let m = &self.mail;
        let empty = m.update.is_none() && m.reveal.is_none() && m.prompt.is_none();
        put(&mut self.mail);
        empty
    }

    pub fn put(&mut self, update: Update) -> bool {
        self.deliver(|mail| mail.update = Some(update))
    }

    pub fn put_reveal(&mut self, reveal: Reveal) -> bool {
        self.deliver(|mail| mail.reveal = Some(reveal))
    }

    pub fn put_prompt(&mut self, prompt: Prompt) -> bool {
        self.deliver(|mail| mail.prompt = Some(prompt))
    }

    pub fn take_all(&mut self) -> Mail {
        std::mem::take(&mut self.mail)
    }

    pub fn close(&mut self) {
        self.open = false;
        self.mail = Mail::default();
    }
}

pub fn stalled(error: String, loaded: Loaded) -> Update {
    Update {
        state: AgentState::Unreachable(Note::Agent(error.clone())),
        gateways: loaded.gateways,
        sections: loaded.sections,
        agent: loaded.agent,
        failure: None,
        launched: 0,
        device: Some(Probe {
            key: KeyState::Failed(error),
            system: System::default(),
        }),
        log: Journal::default(),
        starting: Starting::Idle,
        config: Config::Unreported,
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

type Answers = RefCell<Desk<oneshot::Sender<Answer>>>;
type Linking<'a> = Pin<Box<dyn Future<Output = Option<Note>> + 'a>>;

fn unlinked(error: RequestError) -> Note {
    match error {
        RequestError::NotRunning => Text::LinkAgentNotRunning.into(),
        error => crate::agent::note(error),
    }
}

async fn link<F, R>(
    launch: LaunchRequest,
    send: &F,
    ticket: u64,
    answered: oneshot::Receiver<Answer>,
    answers: &Answers,
    prompt: &impl Fn(Prompt),
) -> Option<Note>
where
    F: Fn(Request) -> R,
    R: Future<Output = Result<Response, RequestError>>,
{
    let reply = match send(Request::Launch(launch.clone())).await {
        Ok(reply) => reply,
        Err(error) => return Some(unlinked(error)),
    };
    let ask = move |confirmation| async move {
        if !answers.borrow().holds(ticket) {
            return Ok(false);
        }
        prompt(Prompt::Ask(ticket, confirmation));
        let answer = tokio::time::timeout(approval::TIMEOUT, answered).await;
        answers.borrow_mut().take(ticket);
        prompt(Prompt::Dismiss(ticket));
        Ok(answer == Ok(Ok(Answer::Allow)))
    };
    match settle(&launch, reply, send, ask).await {
        Ok(Response::Ok(_)) => None,
        Ok(Response::Error(message)) => Some(Note::Agent(message)),
        Err(error) => refused(error),
    }
}

fn refused(error: ApprovalError) -> Option<Note> {
    match error {
        ApprovalError::Denied(_) => None,
        ApprovalError::Request(error) => Some(unlinked(error)),
        ApprovalError::MissingSelector | ApprovalError::UnnamedGateway => {
            Some(Text::LinkUnnamed.into())
        }
        ApprovalError::NotEchoed => Some(Text::LinkNotEchoed.into()),
        ApprovalError::Unasked(reason) => Some(Note::Agent(reason)),
    }
}

async fn finish<T>(pending: &mut Option<Pin<Box<T>>>) -> Option<Note>
where
    T: Future<Output = Option<Note>> + ?Sized,
{
    match pending {
        Some(pending) => pending.await,
        None => std::future::pending().await,
    }
}

pub async fn serve<F, R>(
    commands: UnboundedReceiver<Command>,
    send: F,
    load: impl FnMut(&Config) -> Loaded,
    probe: impl FnMut(&Config) -> Probe,
    deliver: impl FnMut(Update),
    reveal: impl FnMut(Reveal),
    prompt: impl Fn(Prompt),
) where
    F: Fn(Request) -> R,
    R: Future<Output = Result<Response, RequestError>>,
{
    serve_with(
        |_| None,
        crate::start::agent,
        commands,
        send,
        load,
        probe,
        deliver,
        reveal,
        prompt,
    )
    .await;
}

#[expect(
    clippy::too_many_arguments,
    reason = "each callback reaches a different part of the window"
)]
pub async fn serve_with<F, R, S>(
    refuse: impl Fn(&Command) -> Option<Text>,
    start: impl Fn() -> S,
    mut commands: UnboundedReceiver<Command>,
    send: F,
    mut load: impl FnMut(&Config) -> Loaded,
    mut probe: impl FnMut(&Config) -> Probe,
    mut deliver: impl FnMut(Update),
    mut reveal: impl FnMut(Reveal),
    prompt: impl Fn(Prompt),
) where
    F: Fn(Request) -> R,
    R: Future<Output = Result<Response, RequestError>>,
    S: Future<Output = Option<Note>>,
{
    let mut failure = None;
    let mut launched = 0;
    let mut device = None;
    let mut watching = false;
    let mut journal = Journal::default();
    let answers = Answers::default();
    let mut linking: Option<Linking<'_>> = None;
    let mut starting: Option<Pin<Box<S>>> = None;
    let mut unstarted: Option<Note> = None;
    loop {
        let state = AgentState::from_list(send(Request::List).await);
        let config = match state {
            AgentState::Running(_) => Config::from_reply(send(Request::Config).await),
            AgentState::Stopped | AgentState::Unreachable(_) => Config::Unreported,
        };
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
        let stopped = state == AgentState::Stopped;
        if !stopped {
            unstarted = None;
        }
        let Loaded {
            gateways,
            sections,
            agent,
        } = load(&config);
        deliver(Update {
            state,
            gateways,
            sections,
            agent,
            failure: failure.take(),
            launched,
            device: device.clone(),
            log: journal.clone(),
            starting: match (&starting, &unstarted) {
                (Some(_), _) => Starting::InFlight,
                (None, Some(note)) => Starting::Failed(note.clone()),
                (None, None) => Starting::Idle,
            },
            config: config.clone(),
        });
        tokio::select! {
            biased;
            command = commands.recv() => {
                let Some(command) = command else {
                    answers.borrow_mut().close();
                    if let Some(superseded) = linking.take() {
                        superseded.await;
                    }
                    return;
                };
                let launch = matches!(command, Command::Launch(_));
                if let Some(text) = refuse(&command) {
                    failure = Some(text.into());
                    launched += u64::from(launch);
                    continue;
                }
                match command {
                    Command::Probe => {
                        device = Some(probe(&config));
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
                    Command::Answer(ticket, answer) => {
                        if let Some(answering) = answers.borrow_mut().take(ticket) {
                            let _ = answering.send(answer);
                        }
                        continue;
                    }
                    Command::Link(launch) => {
                        let (answering, answered) = oneshot::channel();
                        let (ticket, _) = answers.borrow_mut().open(answering);
                        if let Some(superseded) = linking.take() {
                            failure = superseded.await;
                        }
                        linking = Some(Box::pin(link(
                            launch, &send, ticket, answered, &answers, &prompt,
                        )));
                        continue;
                    }
                    Command::Start => {
                        if stopped && starting.is_none() {
                            starting = Some(Box::pin(start()));
                            unstarted = None;
                        }
                        continue;
                    }
                    Command::Close(_) | Command::Stop | Command::Launch(_) => {}
                }
                failure = run(command, &send).await;
                launched += u64::from(launch);
            }
            note = finish(&mut linking) => {
                linking = None;
                failure = note;
            }
            note = finish(&mut starting) => {
                starting = None;
                unstarted = note;
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
    use gateinto::proxy::SessionCredentials;

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
            failure,
            launched: 0,
            device: None,
            log: Journal::default(),
            starting: Starting::Idle,
            config: Config::Unreported,
        }
    }

    fn loaded(_: &Config) -> Loaded {
        Loaded {
            gateways: Ok(Known::default()),
            sections: Gateways::default(),
            agent: Ok(Agent::default()),
        }
    }

    fn unprobed(_: &Config) -> Probe {
        panic!("probed the device without being asked")
    }

    fn unrevealed(_: Reveal) {
        panic!("revealed credentials without being asked")
    }

    fn unprompted(_: Prompt) {
        panic!("prompted without a link")
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
            unprompted,
        );
        assert!(timeout(Duration::from_millis(4_500), run).await.is_err());
        assert_eq!(
            *log.borrow(),
            [
                Request::List,
                Request::Config,
                Request::Credentials(SessionId::from(7)),
                Request::List,
                Request::Config,
                Request::List,
                Request::Config,
                Request::List,
                Request::Config
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
        let read = |_: &Config| {
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
            unprompted,
        );
        assert!(timeout(Duration::from_millis(4_500), run).await.is_err());
        assert_eq!(
            updates,
            [None, Some(probe(1)), Some(probe(1)), Some(probe(1))]
        );
        assert_eq!(*probes.borrow(), 1);
        assert_eq!(*log.borrow(), polls(4));
    }

    fn polls(n: usize) -> Vec<Request> {
        (0..n)
            .flat_map(|_| [Request::List, Request::Config])
            .collect()
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
            unprompted,
        );
        assert!(timeout(Duration::from_millis(4_500), run).await.is_err());
        assert_eq!(updates, [polled(None), polled(None), polled(None)]);
        assert_eq!(*log.borrow(), polls(3));
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
            unprompted,
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
                Request::Config,
                Request::Close(SessionId::from(5)),
                Request::List,
                Request::Config,
                Request::List,
                Request::Config
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
            unprompted,
        );
        assert!(timeout(Duration::from_secs(10), run).await.is_ok());
        assert_eq!(updates, [polled(None)]);
    }

    #[tokio::test(start_paused = true)]
    async fn every_poll_rereads_the_gateways_and_agent_settings() {
        let log = RefCell::new(Vec::new());
        let (_tx, rx) = unbounded_channel();
        let reads = RefCell::new(0);
        let read = |n: u32| Loaded {
            gateways: Err(format!("gateways {n}")),
            sections: ConfigFile::parse(&format!("[gateways.g{n}]\nhost = \"h{n}\"\n"))
                .unwrap()
                .gateways,
            agent: Err(format!("agent {n}")),
        };
        let load = |_: &Config| {
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
                })
            },
            unrevealed,
            unprompted,
        );
        assert!(timeout(Duration::from_millis(2_500), run).await.is_err());
        assert_eq!(updates, [read(1), read(2)]);
    }

    fn configured(
        log: &RefCell<Vec<Request>>,
        config: Response,
    ) -> impl Fn(Request) -> std::future::Ready<Result<Response, RequestError>> {
        move |request| {
            log.borrow_mut().push(request.clone());
            std::future::ready(Ok(match request {
                Request::Config => config.clone(),
                _ => Response::Ok(Vec::new()),
            }))
        }
    }

    async fn configs_read(
        send: impl Fn(Request) -> std::future::Ready<Result<Response, RequestError>>,
    ) -> (Vec<Config>, Vec<Config>, Vec<Config>) {
        let (tx, rx) = unbounded_channel();
        tx.send(Command::Probe).unwrap();
        let loads = RefCell::new(Vec::new());
        let probes = RefCell::new(Vec::new());
        let mut delivered = Vec::new();
        let run = serve(
            rx,
            send,
            |config: &Config| {
                loads.borrow_mut().push(config.clone());
                loaded(config)
            },
            |config: &Config| {
                probes.borrow_mut().push(config.clone());
                probe(0)
            },
            |u| delivered.push(u.config),
            unrevealed,
            unprompted,
        );
        assert!(timeout(Duration::from_millis(2_500), run).await.is_err());
        (loads.into_inner(), probes.into_inner(), delivered)
    }

    #[tokio::test(start_paused = true)]
    async fn a_running_agent_is_asked_each_poll_for_the_config_its_gateways_are_read_from() {
        let log = RefCell::new(Vec::new());
        let file = std::env::temp_dir().join("agent.toml");
        let line = ipc::config_line(&ipc::ConfigSource::File(file.clone())).unwrap();
        let (loads, probes, delivered) =
            configs_read(configured(&log, Response::Ok(vec![line]))).await;
        let reported = Config::Reported(ipc::ConfigSource::File(file));
        assert_eq!(loads, vec![reported.clone(); 3]);
        assert_eq!(probes, [reported]);
        assert_eq!(delivered, loads);
        assert_eq!(
            *log.borrow(),
            [
                Request::List,
                Request::Config,
                Request::List,
                Request::Config,
                Request::List,
                Request::Config
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_agent_too_old_to_report_its_config_leaves_the_default_in_use() {
        let log = RefCell::new(Vec::new());
        let older = Response::Error(ipc::INVALID_REQUEST.to_owned());
        let (loads, probes, delivered) = configs_read(configured(&log, older)).await;
        assert_eq!(
            loads,
            [Config::Unreported, Config::Unreported, Config::Unreported]
        );
        assert_eq!(probes, [Config::Unreported]);
        assert_eq!(delivered, loads);
    }

    #[tokio::test(start_paused = true)]
    async fn an_agent_that_is_not_running_is_not_asked_for_its_config() {
        for reply in [stopped as fn() -> _, || Err(RequestError::TimedOut)] {
            let log = RefCell::new(Vec::new());
            let (loads, _, delivered) = configs_read(listing(&log, reply)).await;
            assert_eq!(
                loads,
                [Config::Unreported, Config::Unreported, Config::Unreported]
            );
            assert_eq!(delivered, loads);
            assert!(log.borrow().iter().all(|r| *r == Request::List));
        }
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
            unprompted,
        );
        assert!(timeout(Duration::from_millis(500), run).await.is_err());
        assert_eq!(updates, [polled(None), launched(polled(None))]);
        assert_eq!(
            *log.borrow(),
            [
                Request::List,
                Request::Config,
                launch("office"),
                Request::List,
                Request::Config
            ]
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
            unprompted,
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
                Request::Config,
                launch("office"),
                Request::Deny(token.parse().unwrap()),
                Request::List,
                Request::Config
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
            unprompted,
        );
        assert!(timeout(Duration::from_millis(2_500), run).await.is_err());
        assert_eq!(
            *log.borrow(),
            [
                Request::List,
                Request::Config,
                Request::List,
                Request::Config,
                Request::Log { after: 0 },
                Request::List,
                Request::Config,
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
            unprompted,
        );
        assert!(timeout(Duration::from_millis(2_500), run).await.is_err());
        assert_eq!(
            *log.borrow(),
            [
                Request::List,
                Request::Config,
                Request::List,
                Request::Config,
                Request::Log { after: 0 },
                Request::List,
                Request::Config,
                Request::List,
                Request::Config,
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
            unprompted,
        );
        assert!(timeout(Duration::from_millis(500), run).await.is_err());
        let asked: Vec<Request> = log.borrow()[4..].to_vec();
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
            unprompted,
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
        let run = serve(
            rx,
            send,
            loaded,
            unprobed,
            |u| updates.push(u),
            unrevealed,
            unprompted,
        );
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
        let update = stalled("no timer".to_owned(), loaded(&Config::Unreported));
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
        assert_eq!(mailbox.take_all().update, Some(polled(said("busy"))));
        assert_eq!(mailbox.take_all().update, None);
        assert!(mailbox.put(polled(None)));
    }

    #[test]
    fn a_closed_mailbox_drops_what_it_holds_and_what_arrives() {
        let mut mailbox = Mailbox::default();
        mailbox.put(polled(None));
        mailbox.put_reveal(revealed(3));
        mailbox.put_prompt(Prompt::Ask(1, proposed()));
        mailbox.close();
        assert!(!mailbox.put(polled(None)));
        assert!(!mailbox.put_reveal(revealed(4)));
        assert!(!mailbox.put_prompt(Prompt::Ask(2, proposed())));
        let mail = mailbox.take_all();
        assert_eq!(mail.update, None);
        assert!(mail.reveal.is_none());
        assert_eq!(mail.prompt, None);
    }

    fn revealed(id: u64) -> Reveal {
        Reveal {
            id,
            ticket: 1,
            credentials: SessionCredentials::parse("gateinto", PASSWORD).map(Issued::Agent),
        }
    }

    #[test]
    fn a_mailbox_keeps_the_latest_of_each_kind_and_shares_one_notice() {
        let mut mailbox = Mailbox::default();
        assert!(mailbox.put_reveal(revealed(3)));
        assert!(!mailbox.put(polled(None)));
        assert!(!mailbox.put_reveal(revealed(4)));
        assert!(!mailbox.put_prompt(Prompt::Ask(1, proposed())));
        assert!(!mailbox.put_prompt(Prompt::Dismiss(1)));

        let mail = mailbox.take_all();
        assert_eq!(mail.update, Some(polled(None)));
        assert_eq!(mail.reveal.map(|reveal| reveal.id), Some(4));
        assert_eq!(mail.prompt, Some(Prompt::Dismiss(1)));
    }

    #[test]
    fn whatever_arrives_after_a_drain_asks_for_a_new_notice() {
        let mut mailbox = Mailbox::default();
        assert!(mailbox.put(polled(None)));
        mailbox.take_all();
        assert!(mailbox.put_prompt(Prompt::Ask(1, proposed())));
        assert!(!mailbox.put(polled(None)));

        let mail = mailbox.take_all();
        assert_eq!(mail.prompt, Some(Prompt::Ask(1, proposed())));
        assert_eq!(mail.update, Some(polled(None)));
        assert!(mailbox.put_reveal(revealed(3)));
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

    const LINK: &str = "gateinto://connect?profile=newco&gateway=proxy.newco.example\
                        &portal=https%3A%2F%2Fportal.newco.example%2Fhome";
    const TOKEN: &str = "00112233445566778899aabbccddeeff";

    fn link() -> LaunchRequest {
        LINK.parse().unwrap()
    }

    fn token() -> ipc::ConfirmToken {
        TOKEN.parse().unwrap()
    }

    fn proposed() -> Confirmation {
        let launch = link();
        Confirmation {
            route: launch.route.unwrap_or_default(),
            profile: launch.proposed_profile().unwrap(),
            gateway: launch.gateway.clone().unwrap(),
            portal: launch.portal.clone(),
        }
    }

    fn confirming(
        log: &RefCell<Vec<Request>>,
    ) -> impl Fn(Request) -> std::future::Ready<Result<Response, RequestError>> {
        move |request| {
            log.borrow_mut().push(request.clone());
            std::future::ready(Ok(match request {
                Request::Launch(_) => {
                    let mut lines = proposed().echo();
                    lines.push(ipc::confirm_line(&token()));
                    Response::Ok(lines)
                }
                _ => Response::Ok(Vec::new()),
            }))
        }
    }

    fn settled(log: &RefCell<Vec<Request>>) -> Vec<Request> {
        log.borrow()
            .iter()
            .filter(|request| !matches!(request, Request::List | Request::Config))
            .cloned()
            .collect()
    }

    async fn linked(
        send: impl Fn(Request) -> std::future::Ready<Result<Response, RequestError>>,
        commands: Vec<Command>,
        answer: impl Fn(&Prompt) -> Vec<Command>,
        wait: Duration,
    ) -> (Vec<Prompt>, Vec<Option<Note>>) {
        let (tx, rx) = unbounded_channel();
        for command in commands {
            tx.send(command).unwrap();
        }
        let prompts = RefCell::new(Vec::new());
        let mut failures = Vec::new();
        let prompt = |prompt: Prompt| {
            for command in answer(&prompt) {
                tx.send(command).unwrap();
            }
            prompts.borrow_mut().push(prompt);
        };
        let run = serve(
            rx,
            send,
            loaded,
            unprobed,
            |u| failures.push(u.failure),
            unrevealed,
            prompt,
        );
        assert!(timeout(wait, run).await.is_err());
        (prompts.into_inner(), failures)
    }

    fn reply(answer: Answer) -> impl Fn(&Prompt) -> Vec<Command> {
        move |prompt| match prompt {
            Prompt::Ask(ticket, _) => vec![Command::Answer(*ticket, answer)],
            Prompt::Dismiss(_) => Vec::new(),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_allowed_link_approves_its_token() {
        let log = RefCell::new(Vec::new());
        let (prompts, failures) = linked(
            confirming(&log),
            vec![Command::Link(link())],
            reply(Answer::Allow),
            Duration::from_millis(500),
        )
        .await;
        assert_eq!(
            settled(&log),
            [Request::Launch(link()), Request::Approve(token())]
        );
        assert_eq!(prompts, [Prompt::Ask(1, proposed()), Prompt::Dismiss(1)]);
        assert!(failures.iter().all(Option::is_none));
    }

    #[tokio::test(start_paused = true)]
    async fn a_denied_link_denies_its_token_without_a_failure() {
        let log = RefCell::new(Vec::new());
        let (prompts, failures) = linked(
            confirming(&log),
            vec![Command::Link(link())],
            reply(Answer::Deny),
            Duration::from_millis(500),
        )
        .await;
        assert_eq!(
            settled(&log),
            [Request::Launch(link()), Request::Deny(token())]
        );
        assert_eq!(prompts, [Prompt::Ask(1, proposed()), Prompt::Dismiss(1)]);
        assert!(failures.iter().all(Option::is_none));
    }

    #[tokio::test(start_paused = true)]
    async fn polling_goes_on_while_a_link_waits_for_its_answer() {
        let log = RefCell::new(Vec::new());
        let (prompts, _) = linked(
            confirming(&log),
            vec![Command::Link(link())],
            |_| Vec::new(),
            Duration::from_millis(4_500),
        )
        .await;
        assert_eq!(prompts, [Prompt::Ask(1, proposed())]);
        assert_eq!(settled(&log), [Request::Launch(link())]);
        assert_eq!(log.borrow().len(), 1 + polls(4).len());
    }

    #[tokio::test(start_paused = true)]
    async fn an_unanswered_link_is_denied_when_the_dialog_times_out() {
        let log = RefCell::new(Vec::new());
        let (prompts, _) = linked(
            confirming(&log),
            vec![Command::Link(link())],
            |_| Vec::new(),
            crate::approval::TIMEOUT + Duration::from_secs(1),
        )
        .await;
        assert_eq!(
            settled(&log),
            [Request::Launch(link()), Request::Deny(token())]
        );
        assert_eq!(prompts, [Prompt::Ask(1, proposed()), Prompt::Dismiss(1)]);
    }

    #[tokio::test(start_paused = true)]
    async fn an_answer_for_a_stale_ticket_is_dropped() {
        let log = RefCell::new(Vec::new());
        let stale = |prompt: &Prompt| match prompt {
            Prompt::Ask(ticket, _) => vec![Command::Answer(ticket + 1, Answer::Allow)],
            Prompt::Dismiss(_) => Vec::new(),
        };
        let (prompts, _) = linked(
            confirming(&log),
            vec![Command::Link(link())],
            stale,
            Duration::from_millis(500),
        )
        .await;
        assert_eq!(settled(&log), [Request::Launch(link())]);
        assert_eq!(prompts, [Prompt::Ask(1, proposed())]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_link_denies_the_one_it_supersedes() {
        let log = RefCell::new(Vec::new());
        let supersede = |prompt: &Prompt| match prompt {
            Prompt::Ask(1, _) => vec![Command::Link(link())],
            Prompt::Ask(ticket, _) => vec![Command::Answer(*ticket, Answer::Allow)],
            Prompt::Dismiss(_) => Vec::new(),
        };
        let (prompts, _) = linked(
            confirming(&log),
            vec![Command::Link(link())],
            supersede,
            Duration::from_millis(500),
        )
        .await;
        assert_eq!(
            settled(&log),
            [
                Request::Launch(link()),
                Request::Deny(token()),
                Request::Launch(link()),
                Request::Approve(token())
            ]
        );
        assert_eq!(
            prompts,
            [
                Prompt::Ask(1, proposed()),
                Prompt::Dismiss(1),
                Prompt::Ask(2, proposed()),
                Prompt::Dismiss(2)
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_link_superseded_before_it_asks_is_denied_unasked() {
        let log = RefCell::new(Vec::new());
        let (prompts, _) = linked(
            confirming(&log),
            vec![Command::Link(link()), Command::Link(link())],
            reply(Answer::Allow),
            Duration::from_millis(500),
        )
        .await;
        assert_eq!(
            settled(&log),
            [
                Request::Launch(link()),
                Request::Deny(token()),
                Request::Launch(link()),
                Request::Approve(token())
            ]
        );
        assert_eq!(prompts, [Prompt::Ask(2, proposed()), Prompt::Dismiss(2)]);
    }

    #[tokio::test(start_paused = true)]
    async fn closing_the_gui_denies_an_open_link() {
        let log = RefCell::new(Vec::new());
        let (tx, rx) = unbounded_channel();
        tx.send(Command::Link(link())).unwrap();
        let tx = RefCell::new(Some(tx));
        let run = serve(
            rx,
            confirming(&log),
            loaded,
            unprobed,
            |_| {},
            unrevealed,
            |_| drop(tx.borrow_mut().take()),
        );
        timeout(Duration::from_millis(500), run).await.unwrap();
        assert_eq!(
            settled(&log),
            [Request::Launch(link()), Request::Deny(token())]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_link_never_starts_a_missing_agent() {
        let log = RefCell::new(Vec::new());
        let missing = |request: Request| {
            log.borrow_mut().push(request);
            std::future::ready(Err(RequestError::NotRunning))
        };
        let (prompts, failures) = linked(
            missing,
            vec![Command::Link(link())],
            reply(Answer::Allow),
            Duration::from_millis(500),
        )
        .await;
        assert_eq!(settled(&log), [Request::Launch(link())]);
        assert!(prompts.is_empty());
        assert_eq!(
            failures.last(),
            Some(&Some(Text::LinkAgentNotRunning.into()))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_link_without_a_confirmation_reports_the_agent_reply() {
        let log = RefCell::new(Vec::new());
        let refused = |request: Request| {
            log.borrow_mut().push(request.clone());
            std::future::ready(Ok(match request {
                Request::Launch(_) => Response::Error("no such gateway".to_owned()),
                _ => Response::Ok(Vec::new()),
            }))
        };
        let (prompts, failures) = linked(
            refused,
            vec![Command::Link(link())],
            reply(Answer::Allow),
            Duration::from_millis(500),
        )
        .await;
        assert_eq!(settled(&log), [Request::Launch(link())]);
        assert!(prompts.is_empty());
        assert_eq!(failures.last(), Some(&said("no such gateway")));
    }

    #[tokio::test(start_paused = true)]
    async fn a_confirmation_for_another_gateway_is_denied_with_a_fixed_note() {
        let log = RefCell::new(Vec::new());
        let other = |request: Request| {
            log.borrow_mut().push(request.clone());
            std::future::ready(Ok(match request {
                Request::Launch(_) => {
                    let mut elsewhere = proposed();
                    elsewhere.gateway = "proxy.elsewhere.example".parse().unwrap();
                    let mut lines = elsewhere.echo();
                    lines.push(ipc::confirm_line(&token()));
                    Response::Ok(lines)
                }
                _ => Response::Ok(Vec::new()),
            }))
        };
        let (prompts, failures) = linked(
            other,
            vec![Command::Link(link())],
            reply(Answer::Allow),
            Duration::from_millis(500),
        )
        .await;
        assert_eq!(
            settled(&log),
            [Request::Launch(link()), Request::Deny(token())]
        );
        assert!(prompts.is_empty());
        assert_eq!(failures.last(), Some(&Some(Text::LinkNotEchoed.into())));
    }

    #[test]
    fn links_naming_no_gateway_get_a_fixed_note() {
        for error in [
            ApprovalError::MissingSelector,
            ApprovalError::UnnamedGateway,
        ] {
            assert_eq!(refused(error), Some(Text::LinkUnnamed.into()));
        }
        assert_eq!(
            refused(ApprovalError::Request(RequestError::NotRunning)),
            Some(Text::LinkAgentNotRunning.into())
        );
        assert_eq!(
            refused(ApprovalError::Denied("newco".parse().unwrap())),
            None
        );
    }

    fn listing(
        log: &RefCell<Vec<Request>>,
        reply: fn() -> Result<Response, RequestError>,
    ) -> impl Fn(Request) -> std::future::Ready<Result<Response, RequestError>> {
        move |request| {
            log.borrow_mut().push(request);
            std::future::ready(reply())
        }
    }

    type Seen = (u64, Starting, Option<Note>);

    async fn starts(
        send: impl Fn(Request) -> std::future::Ready<Result<Response, RequestError>>,
        commands: Vec<(u64, Command)>,
        took: Duration,
        note: Option<Note>,
        wait: Duration,
    ) -> (u32, Vec<Seen>) {
        let (tx, rx) = unbounded_channel();
        let calls = RefCell::new(0);
        let start = || {
            *calls.borrow_mut() += 1;
            let note = note.clone();
            async move {
                tokio::time::sleep(took).await;
                note
            }
        };
        let begun = tokio::time::Instant::now();
        let mut seen = Vec::new();
        let run = serve_with(
            |_| None,
            start,
            rx,
            send,
            loaded,
            unprobed,
            |u| {
                let at = begun.elapsed().as_millis() as u64;
                seen.push((at, u.starting, u.failure));
            },
            unrevealed,
            unprompted,
        );
        let feed = async {
            for (at, command) in commands {
                tokio::time::sleep_until(begun + Duration::from_millis(at)).await;
                tx.send(command).unwrap();
            }
            std::future::pending::<()>().await;
        };
        assert!(
            timeout(wait, async { tokio::join!(run, feed) })
                .await
                .is_err()
        );
        (calls.into_inner(), seen)
    }

    fn stopped() -> Result<Response, RequestError> {
        Err(RequestError::NotRunning)
    }

    #[tokio::test(start_paused = true)]
    async fn a_stopped_agent_is_started_once_and_refreshed_as_soon_as_it_runs() {
        let log = RefCell::new(Vec::new());
        let (calls, seen) = starts(
            listing(&log, stopped),
            vec![(0, Command::Start), (0, Command::Start)],
            Duration::from_secs(9),
            None,
            Duration::from_millis(12_500),
        )
        .await;
        assert_eq!(calls, 1);
        let (idle, busy) = (Starting::Idle, Starting::InFlight);
        assert_eq!(
            seen,
            [
                (0, idle.clone(), None),
                (0, busy.clone(), None),
                (0, busy.clone(), None),
                (2_000, busy.clone(), None),
                (4_000, busy.clone(), None),
                (6_000, busy.clone(), None),
                (8_000, busy, None),
                (9_000, idle.clone(), None),
                (11_000, idle, None),
            ]
        );
        assert!(log.borrow().iter().all(|r| *r == Request::List));
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_start_stays_shown_while_the_agent_stays_stopped() {
        let log = RefCell::new(Vec::new());
        let failed = Starting::Failed(crate::start::FAILED.into());
        let (calls, seen) = starts(
            listing(&log, stopped),
            vec![(0, Command::Start)],
            Duration::from_secs(1),
            Some(crate::start::FAILED.into()),
            Duration::from_millis(5_500),
        )
        .await;
        assert_eq!(calls, 1);
        assert_eq!(
            seen,
            [
                (0, Starting::Idle, None),
                (0, Starting::InFlight, None),
                (1_000, failed.clone(), None),
                (3_000, failed.clone(), None),
                (5_000, failed, None),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_next_start_replaces_a_failed_one() {
        let log = RefCell::new(Vec::new());
        let failed = Starting::Failed(crate::start::MISSING.into());
        let (calls, seen) = starts(
            listing(&log, stopped),
            vec![(0, Command::Start), (2_500, Command::Start)],
            Duration::from_secs(1),
            Some(crate::start::MISSING.into()),
            Duration::from_millis(4_500),
        )
        .await;
        assert_eq!(calls, 2);
        assert_eq!(
            seen,
            [
                (0, Starting::Idle, None),
                (0, Starting::InFlight, None),
                (1_000, failed.clone(), None),
                (2_500, Starting::InFlight, None),
                (3_500, failed, None),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_start_is_forgotten_once_the_agent_is_no_longer_stopped() {
        let begun = tokio::time::Instant::now();
        let send = move |_| {
            std::future::ready(if begun.elapsed() < Duration::from_millis(2_500) {
                stopped()
            } else {
                Ok(Response::Ok(Vec::new()))
            })
        };
        let (calls, seen) = starts(
            send,
            vec![(0, Command::Start)],
            Duration::from_secs(1),
            Some(crate::start::FAILED.into()),
            Duration::from_millis(5_500),
        )
        .await;
        assert_eq!(calls, 1);
        assert_eq!(
            seen,
            [
                (0, Starting::Idle, None),
                (0, Starting::InFlight, None),
                (1_000, Starting::Failed(crate::start::FAILED.into()), None),
                (3_000, Starting::Idle, None),
                (5_000, Starting::Idle, None),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn only_a_stopped_agent_is_started() {
        let running = || Ok(Response::Ok(Vec::new()));
        let unreachable = || Err(RequestError::TimedOut);
        for reply in [running as fn() -> _, unreachable] {
            let log = RefCell::new(Vec::new());
            let (calls, seen) = starts(
                listing(&log, reply),
                vec![(0, Command::Start)],
                Duration::from_secs(1),
                None,
                Duration::from_millis(500),
            )
            .await;
            assert_eq!(calls, 0);
            assert!(
                seen.iter()
                    .all(|(_, starting, failure)| *starting == Starting::Idle && failure.is_none())
            );
        }
    }

    #[test]
    fn starting_is_not_an_agent_request() {
        assert!(Command::Start.request().is_err());
    }
}
