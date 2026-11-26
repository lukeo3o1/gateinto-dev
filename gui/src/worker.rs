use std::cell::RefCell;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use gateinto::config::{GatewayName, Gateways};
use gateinto::ipc::{self, Mode, Request, RequestError, Response, TerminalRequest};
use gateinto::link::approval::{ApprovalError, settle};
use gateinto::link::{Ask, Known};
use gateinto::sessions::SessionId;
use gateinto::uri::{LaunchAuth, LaunchRequest};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::oneshot;
use zeroize::Zeroize;

use crate::agent::{AgentState, Config, Origin, Transparent};
use crate::approval::{self, Answer, Desk};
use crate::credentials::{self, Reveal};
use crate::device::{KeyState, Probe, System};
use crate::i18n::{Note, Text};
use crate::log::Journal;
use crate::settings::Agent;
use crate::start::Starting;
use crate::verification::{self, Check, Reply};

pub const POLL: Duration = Duration::from_secs(2);
const LOG_PAGES: usize = 16;
pub const CONFIRMATION: Text = Text::Confirmation;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Close(u64),
    Stop,
    Start,
    Launch(GatewayName, Mode),
    Terminal(GatewayName, Mode),
    Probe,
    Watch(bool),
    Credentials(u64, u64),
    Verification(u64, u64),
    Unverify,
    Dismiss(u64, u64),
    Link(LaunchRequest),
    Answer(u64, Answer),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Prompt {
    Ask(u64, Ask),
    Dismiss(u64),
}

impl Command {
    fn request(&self) -> Result<Request, String> {
        Ok(match self {
            Command::Close(id) => Request::Close(SessionId::from(*id)),
            Command::Dismiss(id, serial) => Request::Dismiss(SessionId::from(*id), *serial),
            Command::Stop => Request::Stop,
            Command::Launch(name, mode) => Request::Launch(
                LaunchRequest::new(name.as_str(), LaunchAuth::SessionCredentials.as_str())
                    .map_err(|error| error.to_string())?,
                *mode,
            ),
            Command::Terminal(gateway, mode) => Request::Terminal(TerminalRequest {
                gateway: gateway.clone(),
                route: None,
                mode: *mode,
            }),
            Command::Start => return Err("starting the agent is not an agent request".to_owned()),
            Command::Probe => return Err("probing the device is not an agent request".to_owned()),
            Command::Watch(_) => {
                return Err("watching the log is not an agent request".to_owned());
            }
            Command::Credentials(..) => {
                return Err("credentials are revealed apart from commands".to_owned());
            }
            Command::Verification(..) | Command::Unverify => {
                return Err("verifications are shown apart from commands".to_owned());
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
    pub unlisted: u64,
    pub device: Option<Probe>,
    pub log: Journal,
    pub starting: Starting,
    pub config: Config,
    pub transparent: Transparent,
}

#[derive(Debug)]
pub enum Secret {
    Credentials(Reveal),
    Verification(Check),
}

#[derive(Debug, Default)]
pub struct Mail {
    pub update: Option<Update>,
    pub reveal: Option<Reveal>,
    pub verification: Option<Check>,
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
        let empty = m.update.is_none()
            && m.reveal.is_none()
            && m.verification.is_none()
            && m.prompt.is_none();
        put(&mut self.mail);
        empty
    }

    pub fn put(&mut self, update: Update) -> bool {
        self.deliver(|mail| mail.update = Some(update))
    }

    pub fn put_secret(&mut self, secret: Secret) -> bool {
        self.deliver(|mail| match secret {
            Secret::Credentials(reveal) => mail.reveal = Some(reveal),
            Secret::Verification(check) => mail.verification = Some(check),
        })
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
        unlisted: 0,
        device: Some(Probe {
            key: KeyState::Failed(error),
            system: System::default(),
        }),
        log: Journal::default(),
        starting: Starting::Idle,
        config: Config::Unreported,
        transparent: Transparent::Unreported,
    }
}

fn wiped<E>(mut reply: Result<Response, E>) -> Result<Response, E> {
    if let Ok(Response::Ok(lines)) = &mut reply {
        lines.zeroize();
    }
    reply
}

pub fn failure(command: Command, reply: Result<Response, RequestError>) -> Option<Note> {
    let answered = match (&command, &reply) {
        (Command::Terminal(..), Ok(Response::Ok(lines))) => Note::warnings(lines),
        (Command::Stop, Ok(Response::Ok(lines))) => match ipc::closed_terminals(lines) {
            None | Some(0) => None,
            Some(1) => Some(Text::ClosedTerminal.into()),
            Some(count) => Some(Note::filled(Text::ClosedTerminals, &[&count])),
        },
        _ => None,
    };
    match wiped(reply) {
        Ok(Response::Ok(_)) => answered,
        Ok(Response::Error(message))
            if command
                .request()
                .is_ok_and(|request| ipc::agent_too_old_for_transparent(&request, &message)) =>
        {
            Some(Text::TransparentTooOld.into())
        }
        Ok(Response::Error(message))
            if matches!(command, Command::Terminal(..)) && message == ipc::INVALID_REQUEST =>
        {
            Some(Text::TerminalTooOld.into())
        }
        Ok(Response::Error(message)) => Some(Note::Agent(message)),
        Err(RequestError::NotRunning) if matches!(command, Command::Stop) => None,
        Err(error) => Some(crate::agent::note(error)),
    }
}

async fn run<F, R>(command: Command, send: &F) -> (Option<Note>, Option<u64>)
where
    F: Fn(Request) -> R,
    R: Future<Output = Result<Response, RequestError>>,
{
    let request = match command.request() {
        Ok(request) => request,
        Err(error) => return (Some(Note::Agent(error)), None),
    };
    let reply = send(request).await;
    if let Ok(Response::Ok(lines)) = &reply
        && let Some(token) = ipc::confirm_token(lines)
    {
        drop(wiped(reply));
        let _ = send(Request::Deny(token)).await;
        return (Some(CONFIRMATION.into()), None);
    }
    let terminal = match (&command, &reply) {
        (Command::Terminal(..), Ok(Response::Ok(lines))) => lines.iter().find_map(|line| {
            line.strip_prefix("session: ")
                .and_then(|id| id.parse().ok())
        }),
        _ => None,
    };
    (failure(command, reply), terminal)
}

type Answers = RefCell<Desk<oneshot::Sender<Answer>>>;
type Linking<'a> = Pin<Box<dyn Future<Output = Option<Note>> + 'a>>;
type Opening<'a> = Pin<Box<dyn Future<Output = (Option<Note>, Option<u64>)> + 'a>>;

fn open<'a, F, R>(command: Command, send: &'a F) -> Opening<'a>
where
    F: Fn(Request) -> R,
    R: Future<Output = Result<Response, RequestError>> + 'a,
{
    Box::pin(run(command, send))
}

fn unlinked(error: RequestError) -> Note {
    match error {
        RequestError::NotRunning => Text::LinkAgentNotRunning.into(),
        error => crate::agent::note(error),
    }
}

async fn link<F, R>(
    launch: LaunchRequest,
    mode: Mode,
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
    let reply = match send(Request::Launch(launch.clone(), mode)).await {
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
    match wiped(settle(&launch, reply, send, ask).await) {
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

async fn finish<T>(pending: &mut Option<Pin<Box<T>>>) -> T::Output
where
    T: Future + ?Sized,
{
    match pending {
        Some(pending) => pending.await,
        None => std::future::pending().await,
    }
}

async fn poll<F, R>(
    send: &F,
    load: &mut impl FnMut(&Config) -> Loaded,
    watching: bool,
    journal: &mut Journal,
) -> (AgentState, Config, Transparent, Loaded)
where
    F: Fn(Request) -> R,
    R: Future<Output = Result<Response, RequestError>>,
{
    let state = AgentState::from_list(send(Request::List).await);
    let (config, transparent) = match state {
        AgentState::Running(_) => (
            Config::from_reply(send(Request::Config).await),
            Transparent::from_reply(send(Request::Transparent).await),
        ),
        AgentState::Stopped | AgentState::Unreachable(_) => {
            (Config::Unreported, Transparent::Unreported)
        }
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
    let loaded = load(&config);
    (state, config, transparent, loaded)
}

async fn recheck<F, R>(
    checking: Option<(u64, u64)>,
    send: &F,
    reveal: &mut impl FnMut(Secret),
) -> Option<(u64, u64)>
where
    F: Fn(Request) -> R,
    R: Future<Output = Result<Response, RequestError>>,
{
    let (id, ticket) = checking?;
    let reply = send(Request::Verification(SessionId::from(id))).await;
    let check = verification::check(id, ticket, reply);
    let settled = matches!(check.reply, Reply::Settled);
    reveal(Secret::Verification(check));
    (!settled).then_some((id, ticket))
}

pub async fn serve<F, R>(
    commands: UnboundedReceiver<Command>,
    send: F,
    load: impl FnMut(&Config) -> Loaded,
    probe: impl FnMut(&Config) -> Probe,
    deliver: impl FnMut(Update),
    reveal: impl FnMut(Secret),
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
    mut reveal: impl FnMut(Secret),
    prompt: impl Fn(Prompt),
) where
    F: Fn(Request) -> R,
    R: Future<Output = Result<Response, RequestError>>,
    S: Future<Output = Option<Note>>,
{
    let mut failure = None;
    let mut launched = 0;
    let mut unlisted = 0;
    let mut device = None;
    let mut watching = false;
    let mut journal = Journal::default();
    let answers = Answers::default();
    let mut linking: Option<Linking<'_>> = None;
    let mut opening: Option<Opening<'_>> = None;
    let mut queued = VecDeque::new();
    let mut starting: Option<Pin<Box<S>>> = None;
    let mut unstarted: Option<Note> = None;
    let mut checking: Option<(u64, u64)> = None;
    let mut polled = poll(&send, &mut load, watching, &mut journal).await;
    let mut next_poll = tokio::time::Instant::now() + POLL;
    loop {
        if tokio::time::Instant::now() >= next_poll {
            polled = poll(&send, &mut load, watching, &mut journal).await;
            if matches!(polled.0, AgentState::Running(_)) {
                checking = recheck(checking, &send, &mut reveal).await;
            }
            unlisted = 0;
            next_poll = tokio::time::Instant::now() + POLL;
        }
        let (state, config, transparent, loaded) = polled.clone();
        let stopped = state == AgentState::Stopped;
        if !stopped {
            unstarted = None;
        }
        let Loaded {
            gateways,
            sections,
            agent,
        } = loaded;
        deliver(Update {
            state,
            gateways,
            sections,
            agent,
            failure: failure.take(),
            launched,
            unlisted,
            device: device.clone(),
            log: journal.clone(),
            starting: match (&starting, &unstarted) {
                (Some(_), _) => Starting::InFlight,
                (None, Some(note)) => Starting::Failed(note.clone()),
                (None, None) => Starting::Idle,
            },
            config: config.clone(),
            transparent,
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
                let launch = matches!(command, Command::Launch(..) | Command::Terminal(..));
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
                        reveal(Secret::Credentials(credentials::reveal(id, ticket, reply)));
                        continue;
                    }
                    Command::Verification(id, ticket) => {
                        checking = recheck(Some((id, ticket)), &send, &mut reveal).await;
                        continue;
                    }
                    Command::Unverify => {
                        checking = None;
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
                        let mode = polled.2.start(Origin::Link);
                        linking = Some(Box::pin(link(
                            launch, mode, &send, ticket, answered, &answers, &prompt,
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
                    Command::Launch(..) | Command::Terminal(..) => {
                        if opening.is_none() {
                            opening = Some(open(command, &send));
                        } else {
                            queued.push_back(command);
                        }
                        continue;
                    }
                    Command::Close(_) | Command::Dismiss(..) | Command::Stop => {}
                }
                checking = checking.filter(|(id, _)| !verification::ends(&command, *id));
                failure = run(command, &send).await.0;
            }
            (note, terminal) = finish(&mut opening) => {
                opening = queued.pop_front().map(|command| open(command, &send));
                failure = note;
                launched += 1;
                if let Some(id) = terminal
                    && !polled.0.ids().contains(&id)
                {
                    unlisted += 1;
                }
            }
            note = finish(&mut linking) => {
                linking = None;
                failure = note;
            }
            note = finish(&mut starting) => {
                starting = None;
                unstarted = note;
            }
            () = tokio::time::sleep_until(next_poll) => {}
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

    use gateinto::ipc::{
        LogEvent, LogLevel, LogPage, TransparentAvailability, TransparentEngine, TransparentStatus,
    };
    use gateinto::link::LinkError;
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
            unlisted: 0,
            device: None,
            log: Journal::default(),
            starting: Starting::Idle,
            config: Config::Unreported,
            transparent: Transparent::Unreported,
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

    fn unrevealed(_: Secret) {
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
            |r| match r {
                Secret::Credentials(r) => reveals.borrow_mut().push(r),
                Secret::Verification(_) => panic!("checked a verification without being asked"),
            },
            unprompted,
        );
        assert!(timeout(Duration::from_millis(4_500), run).await.is_err());
        assert_eq!(
            *log.borrow(),
            [
                Request::List,
                Request::Config,
                Request::Transparent,
                Request::Credentials(SessionId::from(7)),
                Request::List,
                Request::Config,
                Request::Transparent,
                Request::List,
                Request::Config,
                Request::Transparent
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

    fn verifier(
        log: &RefCell<Vec<Request>>,
        pending: bool,
    ) -> impl Fn(Request) -> std::future::Ready<Result<Response, RequestError>> {
        move |request| {
            log.borrow_mut().push(request.clone());
            std::future::ready(Ok(match request {
                Request::Verification(_) if pending => {
                    let verification = gateinto::proxy::Verification {
                        serial: 7,
                        origin: "https://verify.example.test".to_owned().into(),
                        auth_uri: "https://verify.example.test/device".to_owned().into(),
                        user_code: "WDJB-MJHT".to_owned().into(),
                        expires_in: 600,
                        targets: Vec::new(),
                        more_targets: 0,
                        suppressed: 0,
                    };
                    Response::Ok(ipc::verification_lines(
                        &"office".parse().unwrap(),
                        &verification,
                    ))
                }
                Request::Verification(_) => Response::Error("nothing is pending".to_owned()),
                _ => Response::Ok(Vec::new()),
            }))
        }
    }

    async fn verify(
        commands: &[Command],
        send: impl Fn(Request) -> std::future::Ready<Result<Response, RequestError>>,
    ) -> Vec<Check> {
        let (tx, rx) = unbounded_channel();
        for command in commands {
            tx.send(command.clone()).unwrap();
        }
        let checks = RefCell::new(Vec::new());
        let run = serve(
            rx,
            send,
            loaded,
            unprobed,
            |_| {},
            |r| match r {
                Secret::Verification(check) => checks.borrow_mut().push(check),
                Secret::Credentials(_) => panic!("revealed credentials without being asked"),
            },
            unprompted,
        );
        assert!(timeout(Duration::from_millis(4_500), run).await.is_err());
        checks.into_inner()
    }

    fn verification(id: u64) -> Request {
        Request::Verification(SessionId::from(id))
    }

    #[tokio::test(start_paused = true)]
    async fn an_open_verification_is_re_checked_once_per_poll_with_its_ticket() {
        let log = RefCell::new(Vec::new());
        let checks = verify(&[Command::Verification(3, 5)], verifier(&log, true)).await;
        assert_eq!(
            *log.borrow(),
            [
                Request::List,
                Request::Config,
                Request::Transparent,
                verification(3),
                Request::List,
                Request::Config,
                Request::Transparent,
                verification(3),
                Request::List,
                Request::Config,
                Request::Transparent,
                verification(3),
            ]
        );
        assert_eq!(checks.len(), 3);
        assert!(checks.iter().all(|check| (check.id, check.ticket) == (3, 5)
            && matches!(&check.reply, Reply::Pending(_, pending) if pending.serial == 7)));
    }

    #[tokio::test(start_paused = true)]
    async fn re_checks_stop_when_nothing_is_pending_or_the_dialog_ends() {
        for commands in [
            vec![Command::Verification(3, 5), Command::Unverify],
            vec![Command::Verification(3, 5), Command::Stop],
            vec![Command::Verification(3, 5), Command::Close(3)],
            vec![Command::Verification(3, 5), Command::Dismiss(3, 7)],
        ] {
            let log = RefCell::new(Vec::new());
            verify(&commands, verifier(&log, true)).await;
            let checked = log
                .borrow()
                .iter()
                .filter(|request| matches!(request, Request::Verification(_)))
                .count();
            assert_eq!(checked, 1, "{commands:?}");
        }
        let log = RefCell::new(Vec::new());
        verify(
            &[Command::Verification(3, 5), Command::Close(4)],
            verifier(&log, true),
        )
        .await;
        assert_eq!(
            log.borrow()
                .iter()
                .filter(|r| **r == verification(3))
                .count(),
            3
        );
        let log = RefCell::new(Vec::new());
        let checks = verify(&[Command::Verification(3, 5)], verifier(&log, false)).await;
        assert_eq!(
            log.borrow()
                .iter()
                .filter(|r| **r == verification(3))
                .count(),
            1
        );
        assert!(matches!(
            checks[..],
            [Check {
                reply: Reply::Settled,
                ..
            }]
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn dismissing_sends_the_remembered_serial() {
        let log = RefCell::new(Vec::new());
        verify(&[Command::Dismiss(3, 7)], verifier(&log, true)).await;
        assert!(
            log.borrow()
                .contains(&Request::Dismiss(SessionId::from(3), 7))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn no_re_check_is_sent_while_the_agent_is_not_running() {
        let log = RefCell::new(Vec::new());
        let send = |request: Request| {
            log.borrow_mut().push(request);
            std::future::ready(Err(RequestError::NotRunning))
        };
        let checks = verify(&[Command::Verification(3, 5)], send).await;
        assert_eq!(
            *log.borrow(),
            [Request::List, verification(3), Request::List, Request::List]
        );
        assert!(matches!(
            checks[..],
            [Check {
                reply: Reply::Unreached,
                ..
            }]
        ));
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
        assert_eq!(*log.borrow(), polls(3));
    }

    fn polls(n: usize) -> Vec<Request> {
        (0..n)
            .flat_map(|_| [Request::List, Request::Config, Request::Transparent])
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
    async fn a_command_failure_is_delivered_once_and_refreshed_at_the_earliest_allowed_poll() {
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
                Request::Transparent,
                Request::Close(SessionId::from(5)),
                Request::List,
                Request::Config,
                Request::Transparent
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn commands_that_change_nothing_deliver_the_cached_state_without_polling() {
        let log = RefCell::new(Vec::new());
        let (tx, rx) = unbounded_channel();
        for command in [
            Command::Watch(true),
            Command::Watch(false),
            Command::Answer(9, Answer::Deny),
            Command::Start,
            Command::Watch(true),
        ] {
            tx.send(command).unwrap();
        }
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
        assert!(timeout(Duration::from_millis(1_900), run).await.is_err());
        assert_eq!(updates, vec![polled(None); 6]);
        assert_eq!(*log.borrow(), polls(1));
    }

    #[tokio::test(start_paused = true)]
    async fn commands_that_change_the_agent_refresh_no_sooner_than_two_seconds_apart() {
        let log = RefCell::new(Vec::new());
        let (tx, rx) = unbounded_channel();
        for _ in 0..3 {
            tx.send(Command::Close(5)).unwrap();
        }
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
        assert!(timeout(Duration::from_millis(1_900), run).await.is_err());
        let closes = || vec![Request::Close(SessionId::from(5)); 3];
        assert_eq!(*log.borrow(), [polls(1), closes()].concat());
        assert_eq!(
            updates,
            [vec![polled(None)], vec![polled(said("no session 5")); 3]].concat()
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
        assert_eq!(loads, vec![reported.clone(); 2]);
        assert_eq!(delivered, vec![reported.clone(); 3]);
        assert_eq!(probes, [reported]);
        assert_eq!(*log.borrow(), polls(2));
    }

    #[tokio::test(start_paused = true)]
    async fn an_agent_too_old_to_report_its_config_leaves_the_default_in_use() {
        let log = RefCell::new(Vec::new());
        let older = Response::Error(ipc::INVALID_REQUEST.to_owned());
        let (loads, probes, delivered) = configs_read(configured(&log, older)).await;
        assert_eq!(loads, vec![Config::Unreported; 2]);
        assert_eq!(delivered, vec![Config::Unreported; 3]);
        assert_eq!(probes, [Config::Unreported]);
    }

    #[tokio::test(start_paused = true)]
    async fn an_agent_that_is_not_running_is_not_asked_for_its_config() {
        for reply in [stopped as fn() -> _, timed_out] {
            let log = RefCell::new(Vec::new());
            let (loads, _, delivered) = configs_read(listing(&log, reply)).await;
            assert_eq!(loads, vec![Config::Unreported; 2]);
            assert_eq!(delivered, vec![Config::Unreported; 3]);
            assert!(log.borrow().iter().all(|r| *r == Request::List));
        }
    }

    fn available() -> TransparentStatus {
        TransparentStatus {
            availability: TransparentAvailability::Available,
            engine: TransparentEngine::Stopped(None),
        }
    }

    fn transparency(
        log: &RefCell<Vec<Request>>,
        reply: fn() -> Result<Response, RequestError>,
    ) -> impl Fn(Request) -> std::future::Ready<Result<Response, RequestError>> {
        move |request| {
            log.borrow_mut().push(request.clone());
            std::future::ready(match request {
                Request::Config => Ok(Response::Ok(vec![
                    ipc::config_line(&ipc::ConfigSource::Defaults).unwrap(),
                ])),
                Request::Transparent => reply(),
                _ => Ok(Response::Ok(Vec::new())),
            })
        }
    }

    async fn transparency_read(
        send: impl Fn(Request) -> std::future::Ready<Result<Response, RequestError>>,
    ) -> Vec<(AgentState, Config, Transparent)> {
        let (_tx, rx) = unbounded_channel();
        let mut delivered = Vec::new();
        let run = serve(
            rx,
            send,
            loaded,
            unprobed,
            |u| delivered.push((u.state, u.config, u.transparent)),
            unrevealed,
            unprompted,
        );
        assert!(timeout(Duration::from_millis(2_500), run).await.is_err());
        delivered
    }

    #[tokio::test(start_paused = true)]
    async fn a_running_agent_is_asked_each_poll_whether_transparent_sessions_are_available() {
        let log = RefCell::new(Vec::new());
        let delivered = transparency_read(transparency(&log, || {
            Ok(Response::Ok(available().to_lines()))
        }))
        .await;
        let reported = (
            AgentState::Running(Vec::new()),
            Config::Reported(ipc::ConfigSource::Defaults),
            Transparent::Reported(available()),
        );
        assert_eq!(delivered, vec![reported; 2]);
        assert_eq!(*log.borrow(), polls(2));
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_transparent_request_leaves_the_rest_of_the_refresh_intact() {
        let replies: [fn() -> Result<Response, RequestError>; 5] = [
            || Ok(Response::Error(ipc::INVALID_REQUEST.to_owned())),
            || Ok(Response::Error("busy".to_owned())),
            || Ok(Response::Ok(vec!["availability: maybe".to_owned()])),
            || Err(RequestError::Closed),
            || Err(RequestError::TimedOut(ipc::REQUEST_TIMEOUT)),
        ];
        for reply in replies {
            let log = RefCell::new(Vec::new());
            let delivered = transparency_read(transparency(&log, reply)).await;
            let unreported = (
                AgentState::Running(Vec::new()),
                Config::Reported(ipc::ConfigSource::Defaults),
                Transparent::Unreported,
            );
            assert_eq!(delivered, vec![unreported; 2]);
            assert_eq!(*log.borrow(), polls(2));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_agent_that_is_not_running_is_not_asked_whether_transparent_sessions_are_available()
    {
        for reply in [stopped as fn() -> _, timed_out] {
            let log = RefCell::new(Vec::new());
            let delivered = transparency_read(listing(&log, reply)).await;
            assert_eq!(delivered.len(), 2);
            assert!(
                delivered
                    .iter()
                    .all(|(_, _, t)| *t == Transparent::Unreported)
            );
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
                Request::Launch(..) => Response::Ok(lines.clone()),
                Request::Terminal(_) => Response::Ok(vec!["session: 1".to_owned()]),
                _ => Response::Ok(Vec::new()),
            }))
        }
    }

    fn launch(name: &str) -> Request {
        Request::Launch(
            LaunchRequest::new(name, LaunchAuth::SessionCredentials.as_str()).unwrap(),
            Mode::Proxy,
        )
    }

    #[tokio::test(start_paused = true)]
    async fn launching_a_known_gateway_asks_for_a_browser_session() {
        let log = RefCell::new(Vec::new());
        let (tx, rx) = unbounded_channel();
        tx.send(Command::Launch("office".parse().unwrap(), Mode::Proxy))
            .unwrap();
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
        assert_eq!(
            updates,
            [polled(None), polled(None), launched(polled(None))]
        );
        assert_eq!(
            *log.borrow(),
            [
                Request::List,
                Request::Config,
                Request::Transparent,
                launch("office")
            ]
        );
    }

    fn terminal(name: &str) -> Request {
        Request::Terminal(gateinto::ipc::TerminalRequest {
            gateway: name.parse().unwrap(),
            route: None,
            mode: Mode::Proxy,
        })
    }

    #[tokio::test(start_paused = true)]
    async fn opening_a_terminal_asks_the_agent_and_counts_as_a_launch() {
        let log = RefCell::new(Vec::new());
        let (tx, rx) = unbounded_channel();
        tx.send(Command::Terminal("office".parse().unwrap(), Mode::Proxy))
            .unwrap();
        let mut updates = Vec::new();
        let run = serve(
            rx,
            launcher(&log, Vec::new()),
            loaded,
            unprobed,
            |u| updates.push(u),
            unrevealed,
            unprompted,
        );
        assert!(timeout(Duration::from_millis(500), run).await.is_err());
        assert_eq!(
            updates,
            [polled(None), polled(None), unlisted(launched(polled(None)))]
        );
        assert_eq!(
            *log.borrow(),
            [
                Request::List,
                Request::Config,
                Request::Transparent,
                terminal("office")
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_transparent_launch_and_terminal_ask_the_agent_in_transparent_mode() {
        let log = RefCell::new(Vec::new());
        let (tx, rx) = unbounded_channel();
        let office = || "office".parse::<GatewayName>().unwrap();
        tx.send(Command::Launch(office(), Mode::Transparent))
            .unwrap();
        tx.send(Command::Terminal(office(), Mode::Transparent))
            .unwrap();
        let mut updates = Vec::new();
        let run = serve(
            rx,
            launcher(&log, Vec::new()),
            loaded,
            unprobed,
            |u| updates.push(u),
            unrevealed,
            unprompted,
        );
        assert!(timeout(Duration::from_millis(500), run).await.is_err());
        let twice = Update {
            launched: 2,
            ..polled(None)
        };
        assert_eq!(
            updates,
            [
                polled(None),
                polled(None),
                polled(None),
                launched(polled(None)),
                unlisted(twice)
            ]
        );
        let launch = Request::Launch(
            LaunchRequest::new("office", LaunchAuth::SessionCredentials.as_str()).unwrap(),
            Mode::Transparent,
        );
        let terminal = Request::Terminal(TerminalRequest {
            gateway: office(),
            route: None,
            mode: Mode::Transparent,
        });
        assert_eq!(
            *log.borrow(),
            [
                Request::List,
                Request::Config,
                Request::Transparent,
                launch,
                terminal
            ]
        );
    }

    fn unlisted(update: Update) -> Update {
        Update {
            unlisted: 1,
            ..update
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_opened_terminal_is_unlisted_until_the_next_list() {
        let log = RefCell::new(Vec::new());
        let (tx, rx) = unbounded_channel();
        tx.send(Command::Terminal("office".parse().unwrap(), Mode::Proxy))
            .unwrap();
        let mut updates = Vec::new();
        let run = serve(
            rx,
            launcher(&log, Vec::new()),
            loaded,
            unprobed,
            |u| updates.push(u),
            unrevealed,
            unprompted,
        );
        assert!(timeout(Duration::from_millis(2_500), run).await.is_err());
        assert_eq!(
            updates,
            [
                polled(None),
                polled(None),
                unlisted(launched(polled(None))),
                launched(polled(None))
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_terminal_already_returned_by_list_is_not_unlisted_when_its_reply_arrives() {
        let (tx, rx) = unbounded_channel();
        tx.send(Command::Terminal(
            "office".parse().unwrap(),
            Mode::Transparent,
        ))
        .unwrap();
        let begun = tokio::time::Instant::now();
        let mut updates = Vec::new();
        let run = serve(
            rx,
            |request| async move {
                let lines = match request {
                    Request::Terminal(_) => {
                        tokio::time::sleep(Duration::from_millis(2100)).await;
                        vec!["session: 1".to_owned()]
                    }
                    Request::List if begun.elapsed() >= POLL => vec![
                        r#"{"id":1,"kind":"terminal","gateway":"office","upstream":"proxy.example:443","listen":"127.0.0.1:8080","route":"all","auth":"os_user","started":1,"tunnels":0}"#.to_owned(),
                    ],
                    _ => Vec::new(),
                };
                Ok(Response::Ok(lines))
            },
            loaded,
            unprobed,
            |update| updates.push(update),
            unrevealed,
            unprompted,
        );
        assert!(timeout(Duration::from_millis(2500), run).await.is_err());
        let latest = updates.last().unwrap();
        assert_eq!(latest.state.ids(), [1]);
        assert_eq!(latest.launched, 1);
        assert_eq!(latest.unlisted, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_terminal_the_agent_refused_is_not_unlisted() {
        let (tx, rx) = unbounded_channel();
        tx.send(Command::Terminal("office".parse().unwrap(), Mode::Proxy))
            .unwrap();
        let mut updates = Vec::new();
        let run = serve(
            rx,
            |request| {
                std::future::ready(Ok(match request {
                    Request::Terminal(_) => Response::Error("no such gateway".to_owned()),
                    _ => Response::Ok(Vec::new()),
                }))
            },
            loaded,
            unprobed,
            |u| updates.push(u),
            unrevealed,
            unprompted,
        );
        assert!(timeout(Duration::from_millis(500), run).await.is_err());
        assert_eq!(
            updates,
            [
                polled(None),
                polled(None),
                launched(polled(said("no such gateway")))
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_refused_terminal_counts_as_a_launch_and_asks_nothing() {
        let log = RefCell::new(Vec::new());
        let (tx, rx) = unbounded_channel();
        tx.send(Command::Terminal("office".parse().unwrap(), Mode::Proxy))
            .unwrap();
        let mut updates = Vec::new();
        let run = serve_with(
            |command| matches!(command, Command::Terminal(..)).then_some(Text::DemoNotStarted),
            || std::future::ready(None),
            rx,
            launcher(&log, Vec::new()),
            loaded,
            unprobed,
            |u| updates.push(u),
            unrevealed,
            unprompted,
        );
        assert!(timeout(Duration::from_millis(500), run).await.is_err());
        assert_eq!(
            updates,
            [
                polled(None),
                launched(polled(Some(Text::DemoNotStarted.into())))
            ]
        );
        assert_eq!(
            *log.borrow(),
            [Request::List, Request::Config, Request::Transparent]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_launch_that_asks_for_confirmation_is_denied_and_fails() {
        let log = RefCell::new(Vec::new());
        let (tx, rx) = unbounded_channel();
        tx.send(Command::Launch("office".parse().unwrap(), Mode::Proxy))
            .unwrap();
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
            [
                polled(None),
                polled(None),
                launched(polled(Some(CONFIRMATION.into())))
            ]
        );
        assert_eq!(
            *log.borrow(),
            [
                Request::List,
                Request::Config,
                Request::Transparent,
                launch("office"),
                Request::Deny(token.parse().unwrap())
            ]
        );
    }

    type Replying = Pin<Box<dyn Future<Output = Result<Response, RequestError>>>>;

    fn since(begun: tokio::time::Instant) -> u64 {
        begun.elapsed().as_millis() as u64
    }

    fn polls_at(at: u64) -> Vec<(u64, Request)> {
        polls(1).into_iter().map(|request| (at, request)).collect()
    }

    fn transparent(name: &str) -> Request {
        Request::Launch(
            LaunchRequest::new(name, LaunchAuth::SessionCredentials.as_str()).unwrap(),
            Mode::Transparent,
        )
    }

    fn holding(
        log: &RefCell<Vec<(u64, Request)>>,
        begun: tokio::time::Instant,
        reply: oneshot::Receiver<Result<Response, RequestError>>,
    ) -> impl Fn(Request) -> Replying {
        let reply = RefCell::new(Some(reply));
        move |request| {
            log.borrow_mut().push((since(begun), request.clone()));
            match request {
                Request::Launch(_, Mode::Transparent) => {
                    let reply = reply.borrow_mut().take().expect("one transparent launch");
                    Box::pin(async move {
                        match reply.await {
                            Ok(reply) => reply,
                            Err(_) => std::future::pending().await,
                        }
                    })
                }
                Request::Launch(launch, Mode::Proxy) if launch == link() => {
                    let mut lines = proposed().echo();
                    lines.push(ipc::confirm_line(&token()));
                    Box::pin(std::future::ready(Ok(Response::Ok(lines))))
                }
                _ => Box::pin(std::future::ready(Ok(Response::Ok(Vec::new())))),
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn polls_links_and_other_commands_go_on_while_a_launch_waits_for_the_agent() {
        let begun = tokio::time::Instant::now();
        let log = RefCell::new(Vec::new());
        let (answer, reply) = oneshot::channel();
        let (tx, rx) = unbounded_channel();
        let office = || "office".parse::<GatewayName>().unwrap();
        tx.send(Command::Launch(office(), Mode::Transparent))
            .unwrap();
        let prompts = RefCell::new(Vec::new());
        let mut updates = Vec::new();
        let run = serve(
            rx,
            holding(&log, begun, reply),
            loaded,
            unprobed,
            |u| updates.push((since(begun), u.launched, u.failure)),
            unrevealed,
            |prompt| prompts.borrow_mut().push((since(begun), prompt)),
        );
        let feed = async {
            for (at, command) in [
                (500, Command::Launch(office(), Mode::Proxy)),
                (1_000, Command::Close(5)),
                (1_500, Command::Link(link())),
            ] {
                tokio::time::sleep_until(begun + Duration::from_millis(at)).await;
                tx.send(command).unwrap();
            }
            tokio::time::sleep_until(begun + Duration::from_secs(5)).await;
            let refused = Response::Error(ipc::INVALID_LAUNCH_REQUEST.to_owned());
            answer.send(Ok(refused)).unwrap();
            std::future::pending::<()>().await;
        };
        assert!(
            timeout(Duration::from_millis(6_500), async {
                tokio::join!(run, feed)
            })
            .await
            .is_err()
        );
        assert_eq!(
            *log.borrow(),
            [
                polls_at(0),
                vec![
                    (0, transparent("office")),
                    (1_000, Request::Close(SessionId::from(5))),
                    (1_500, Request::Launch(link(), Mode::Proxy)),
                ],
                polls_at(2_000),
                polls_at(4_000),
                vec![(5_000, launch("office"))],
                polls_at(6_000),
            ]
            .concat()
        );
        assert_eq!(*prompts.borrow(), [(1_500, Prompt::Ask(1, proposed()))]);
        let too_old = Some(Note::from(Text::TransparentTooOld));
        assert_eq!(
            updates,
            [
                (0, 0, None),
                (0, 0, None),
                (500, 0, None),
                (1_000, 0, None),
                (1_500, 0, None),
                (2_000, 0, None),
                (4_000, 0, None),
                (5_000, 1, too_old),
                (5_000, 2, None),
                (6_000, 2, None),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn quitting_drops_a_pending_launch_and_those_queued_behind_it() {
        let begun = tokio::time::Instant::now();
        let log = RefCell::new(Vec::new());
        let (_answer, reply) = oneshot::channel();
        let (tx, rx) = unbounded_channel();
        let office = || "office".parse::<GatewayName>().unwrap();
        tx.send(Command::Launch(office(), Mode::Transparent))
            .unwrap();
        tx.send(Command::Terminal(office(), Mode::Proxy)).unwrap();
        let run = serve(
            rx,
            holding(&log, begun, reply),
            loaded,
            unprobed,
            |_| {},
            unrevealed,
            unprompted,
        );
        let close = async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            drop(tx);
        };
        timeout(Duration::from_secs(2), async { tokio::join!(run, close) })
            .await
            .unwrap();
        assert_eq!(
            *log.borrow(),
            [polls_at(0), vec![(0, transparent("office"))]].concat()
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
        assert!(timeout(Duration::from_millis(4_500), run).await.is_err());
        assert_eq!(
            *log.borrow(),
            [
                Request::List,
                Request::Config,
                Request::Transparent,
                Request::List,
                Request::Config,
                Request::Transparent,
                Request::Log { after: 0 },
                Request::List,
                Request::Config,
                Request::Transparent,
                Request::Log { after: 2 },
            ]
        );
        let seen: Vec<Vec<u64>> = updates.iter().map(logged).collect();
        assert_eq!(seen, [vec![], vec![], vec![1, 2], vec![1, 2]]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_page_left_stops_the_log_requests_and_keeps_what_was_read() {
        let log = RefCell::new(Vec::new());
        let (tx, rx) = unbounded_channel();
        tx.send(Command::Watch(true)).unwrap();
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
        let leave = async {
            tokio::time::sleep(Duration::from_millis(2_500)).await;
            tx.send(Command::Watch(false)).unwrap();
            std::future::pending::<()>().await;
        };
        let both = async { tokio::join!(run, leave) };
        assert!(timeout(Duration::from_millis(4_500), both).await.is_err());
        assert_eq!(
            *log.borrow(),
            [
                Request::List,
                Request::Config,
                Request::Transparent,
                Request::List,
                Request::Config,
                Request::Transparent,
                Request::Log { after: 0 },
                Request::List,
                Request::Config,
                Request::Transparent,
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
        assert!(timeout(Duration::from_millis(2_500), run).await.is_err());
        let asked: Vec<Request> = log.borrow()[6..].to_vec();
        assert_eq!(
            asked,
            [
                Request::Log { after: 0 },
                Request::Log { after: 2 },
                Request::Log { after: 4 },
            ]
        );
        assert_eq!(logged(&updates[2]), [1, 2, 3, 4, 5]);
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
        mailbox.put_secret(revealed(3));
        mailbox.put_prompt(Prompt::Ask(1, proposed()));
        mailbox.close();
        assert!(!mailbox.put(polled(None)));
        assert!(!mailbox.put_secret(revealed(4)));
        assert!(!mailbox.put_prompt(Prompt::Ask(2, proposed())));
        let mail = mailbox.take_all();
        assert_eq!(mail.update, None);
        assert!(mail.reveal.is_none());
        assert!(mail.verification.is_none());
        assert_eq!(mail.prompt, None);
    }

    fn revealed(id: u64) -> Secret {
        Secret::Credentials(Reveal {
            id,
            ticket: 1,
            listen: None,
            credentials: SessionCredentials::parse("gateinto", PASSWORD).map(Issued::Agent),
        })
    }

    #[test]
    fn a_mailbox_keeps_the_latest_of_each_kind_and_shares_one_notice() {
        let mut mailbox = Mailbox::default();
        assert!(mailbox.put_secret(revealed(3)));
        assert!(!mailbox.put(polled(None)));
        assert!(!mailbox.put_secret(revealed(4)));
        assert!(!mailbox.put_prompt(Prompt::Ask(1, proposed())));
        assert!(!mailbox.put_prompt(Prompt::Dismiss(1)));

        let mail = mailbox.take_all();
        assert_eq!(mail.update, Some(polled(None)));
        assert_eq!(mail.reveal.map(|reveal| reveal.id), Some(4));
        assert_eq!(mail.prompt, Some(Prompt::Dismiss(1)));
    }

    #[test]
    fn a_verification_check_shares_the_notice_and_keeps_its_own_slot() {
        let mut mailbox = Mailbox::default();
        let checked = |ticket| {
            Secret::Verification(verification::check(
                3,
                ticket,
                Err(RequestError::NotRunning),
            ))
        };
        assert!(mailbox.put_secret(checked(1)));
        assert!(!mailbox.put_secret(revealed(4)));
        assert!(!mailbox.put_secret(checked(2)));
        let mail = mailbox.take_all();
        assert_eq!(mail.verification.map(|check| check.ticket), Some(2));
        assert_eq!(mail.reveal.map(|reveal| reveal.id), Some(4));
        assert!(mailbox.put_secret(checked(3)));
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
        assert!(mailbox.put_secret(revealed(3)));
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
    fn a_discarded_reply_is_wiped_but_an_error_is_kept() {
        let issued = || {
            Ok::<_, ()>(Response::Ok(vec![
                "username: gi-1".to_owned(),
                "password: secret".to_owned(),
            ]))
        };
        assert_eq!(wiped(issued()), Ok(Response::Ok(Vec::new())));
        let error = || Ok::<_, ()>(Response::Error("no session".to_owned()));
        assert_eq!(wiped(error()), error());
        assert_eq!(wiped(Err::<Response, _>(())), Err(()));
    }

    #[test]
    fn stopping_an_agent_that_is_not_running_is_not_a_failure() {
        assert_eq!(failure(Command::Stop, Err(RequestError::NotRunning)), None);
        let office = || Command::Launch("office".parse().unwrap(), Mode::Proxy);
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
            "代理程式要求確認此閘道；請重新開啟該閘道的連結以確認"
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

    fn proposed() -> Ask {
        let launch = link();
        Ask::Add(gateinto::link::Confirmation {
            route: launch.route.unwrap_or_default(),
            profile: launch.proposed_profile().unwrap(),
            gateway: launch.gateway.clone().unwrap(),
            portal: launch.portal.clone(),
        })
    }

    fn loosening_link() -> LaunchRequest {
        "gateinto://connect?profile=corp&route=mixed"
            .parse()
            .unwrap()
    }

    fn loosening() -> Ask {
        Ask::Loosen(gateinto::link::Loosening {
            profile: "corp".parse().unwrap(),
            gateway: None,
        })
    }

    fn loosening_asked(
        log: &RefCell<Vec<Request>>,
    ) -> impl Fn(Request) -> std::future::Ready<Result<Response, RequestError>> {
        move |request| {
            log.borrow_mut().push(request.clone());
            std::future::ready(Ok(match request {
                Request::Launch(..) => {
                    let mut lines = vec![ipc::confirm_line(&token())];
                    lines.extend(loosening().echo());
                    Response::Ok(lines)
                }
                _ => Response::Ok(Vec::new()),
            }))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_link_switching_a_gateway_to_mixed_asks_and_only_allow_approves_it() {
        for (answer, wait, sent) in [
            (
                Some(Answer::Allow),
                Duration::from_millis(500),
                Request::Approve(token()),
            ),
            (
                Some(Answer::Deny),
                Duration::from_millis(500),
                Request::Deny(token()),
            ),
            (
                None,
                crate::approval::TIMEOUT + Duration::from_secs(1),
                Request::Deny(token()),
            ),
        ] {
            let log = RefCell::new(Vec::new());
            let respond = move |prompt: &Prompt| match (prompt, answer) {
                (Prompt::Ask(ticket, _), Some(answer)) => vec![Command::Answer(*ticket, answer)],
                _ => Vec::new(),
            };
            let (prompts, failures) = linked(
                loosening_asked(&log),
                vec![Command::Link(loosening_link())],
                respond,
                wait,
            )
            .await;
            assert_eq!(
                settled(&log),
                [Request::Launch(loosening_link(), Mode::Proxy), sent]
            );
            assert_eq!(prompts, [Prompt::Ask(1, loosening()), Prompt::Dismiss(1)]);
            assert!(failures.iter().all(Option::is_none), "{failures:?}");
        }
    }

    fn confirming(
        log: &RefCell<Vec<Request>>,
    ) -> impl Fn(Request) -> std::future::Ready<Result<Response, RequestError>> {
        move |request| {
            log.borrow_mut().push(request.clone());
            std::future::ready(Ok(match request {
                Request::Launch(..) => {
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
            .filter(|request| {
                !matches!(
                    request,
                    Request::List | Request::Config | Request::Transparent
                )
            })
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
            [
                Request::Launch(link(), Mode::Proxy),
                Request::Approve(token())
            ]
        );
        assert_eq!(prompts, [Prompt::Ask(1, proposed()), Prompt::Dismiss(1)]);
        assert!(failures.iter().all(Option::is_none));
    }

    #[tokio::test(start_paused = true)]
    async fn a_link_asks_for_a_proxy_session_even_when_transparent_ones_are_available() {
        let log = RefCell::new(Vec::new());
        let send = |request: Request| {
            log.borrow_mut().push(request.clone());
            std::future::ready(Ok(match request {
                Request::Transparent => Response::Ok(available().to_lines()),
                _ => Response::Ok(Vec::new()),
            }))
        };
        let (_, failures) = linked(
            send,
            vec![Command::Link(link())],
            reply(Answer::Allow),
            Duration::from_millis(500),
        )
        .await;
        assert_eq!(settled(&log), [Request::Launch(link(), Mode::Proxy)]);
        assert!(failures.iter().all(Option::is_none));
        assert!(log.borrow().iter().all(|request| !request.is_transparent()));
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
            [Request::Launch(link(), Mode::Proxy), Request::Deny(token())]
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
        assert_eq!(settled(&log), [Request::Launch(link(), Mode::Proxy)]);
        assert_eq!(log.borrow().len(), 1 + polls(3).len());
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
            [Request::Launch(link(), Mode::Proxy), Request::Deny(token())]
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
        assert_eq!(settled(&log), [Request::Launch(link(), Mode::Proxy)]);
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
                Request::Launch(link(), Mode::Proxy),
                Request::Deny(token()),
                Request::Launch(link(), Mode::Proxy),
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
                Request::Launch(link(), Mode::Proxy),
                Request::Deny(token()),
                Request::Launch(link(), Mode::Proxy),
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
            [Request::Launch(link(), Mode::Proxy), Request::Deny(token())]
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
        assert_eq!(settled(&log), [Request::Launch(link(), Mode::Proxy)]);
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
                Request::Launch(..) => Response::Error("no such gateway".to_owned()),
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
        assert_eq!(settled(&log), [Request::Launch(link(), Mode::Proxy)]);
        assert!(prompts.is_empty());
        assert_eq!(failures.last(), Some(&said("no such gateway")));
    }

    #[tokio::test(start_paused = true)]
    async fn a_confirmation_for_another_gateway_is_denied_with_a_fixed_note() {
        let log = RefCell::new(Vec::new());
        let other = |request: Request| {
            log.borrow_mut().push(request.clone());
            std::future::ready(Ok(match request {
                Request::Launch(..) => {
                    let Ask::Add(mut elsewhere) = proposed() else {
                        unreachable!()
                    };
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
            [Request::Launch(link(), Mode::Proxy), Request::Deny(token())]
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
            refused(ApprovalError::Denied(LinkError::Denied(
                "newco".parse().unwrap()
            ))),
            None
        );
        assert_eq!(
            refused(ApprovalError::Denied(LinkError::LooseningDenied(
                "corp".parse().unwrap()
            ))),
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

    fn timed_out() -> Result<Response, RequestError> {
        Err(RequestError::TimedOut(ipc::REQUEST_TIMEOUT))
    }

    #[tokio::test(start_paused = true)]
    async fn a_stopped_agent_is_started_once_and_refreshed_at_the_next_allowed_poll() {
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
                (10_000, idle.clone(), None),
                (12_000, idle, None),
            ]
        );
        assert!(log.borrow().iter().all(|r| *r == Request::List));
    }

    #[tokio::test(start_paused = true)]
    async fn a_terminal_for_a_stopped_agent_never_starts_it() {
        let log = RefCell::new(Vec::new());
        let (calls, seen) = starts(
            listing(&log, stopped),
            vec![(0, Command::Terminal("office".parse().unwrap(), Mode::Proxy))],
            Duration::from_secs(1),
            None,
            Duration::from_millis(4_500),
        )
        .await;
        assert_eq!(calls, 0);
        assert!(
            seen.iter()
                .all(|(_, starting, _)| *starting == Starting::Idle)
        );
        assert_eq!(
            log.borrow()
                .iter()
                .filter(|r| **r == terminal("office"))
                .count(),
            1
        );
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
                (2_000, failed.clone(), None),
                (4_000, failed, None),
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
                (2_000, failed.clone(), None),
                (2_500, Starting::InFlight, None),
                (3_500, failed.clone(), None),
                (4_000, failed, None),
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
                (2_000, Starting::Failed(crate::start::FAILED.into()), None),
                (4_000, Starting::Idle, None),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn only_a_stopped_agent_is_started() {
        let running = || Ok(Response::Ok(Vec::new()));
        for reply in [running as fn() -> _, timed_out] {
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

    #[test]
    fn open_terminal_leaves_the_route_and_the_shell_to_the_saved_gateway() {
        let request = Command::Terminal("office".parse().unwrap(), Mode::Proxy)
            .request()
            .unwrap();
        assert_eq!(request.to_string(), "terminal office route=saved");
        assert_eq!(request, terminal("office"));
    }

    fn opened(lines: &[&str]) -> Result<Response, RequestError> {
        Ok(Response::Ok(
            lines.iter().map(|&line| line.to_owned()).collect(),
        ))
    }

    const OPENED: [&str; 6] = [
        "session: 4",
        "gateway: office",
        "listen: 127.0.0.1:50000",
        "route: gateway",
        "auth: os_user",
        "shell: pwsh.exe",
    ];

    #[test]
    fn an_opened_terminal_shows_nothing_of_its_answer_but_the_warnings() {
        let office = || Command::Terminal("office".parse().unwrap(), Mode::Proxy);
        assert_eq!(failure(office(), opened(&OPENED)), None);
        let mut lines = OPENED.to_vec();
        lines.extend([
            "linked-gateways: error: the linked gateways file is unreadable",
            "linked-gateway: error: bad entry",
            gateinto::link::MIXED_WARNING,
        ]);
        let note = failure(office(), opened(&lines)).unwrap();
        let english = "linked-gateways: error: the linked gateways file is unreadable\n\
                       linked-gateway: error: bad entry\n"
            .to_owned()
            + gateinto::link::MIXED_WARNING;
        assert_eq!(note.shown(), english);
        for line in OPENED {
            assert!(!note.shown().contains(line), "{line}");
        }
        let _zh = crate::i18n::speaking(crate::i18n::Language::Chinese);
        assert!(note.shown().starts_with("linked-gateways: error: "));
        assert!(note.shown().ends_with("並繞過閘道的政策。"));
    }

    #[test]
    fn an_agent_without_terminals_is_said_to_be_too_old() {
        let office = || Command::Terminal("office".parse().unwrap(), Mode::Proxy);
        let invalid = || Ok(Response::Error(ipc::INVALID_REQUEST.to_owned()));
        assert_eq!(
            failure(office(), invalid()),
            Some(Text::TerminalTooOld.into())
        );
        assert_eq!(
            failure(office(), Ok(Response::Error("no gateway".to_owned()))),
            said("no gateway")
        );
        assert_eq!(
            failure(Command::Close(1), invalid()),
            said(ipc::INVALID_REQUEST)
        );
        assert_eq!(
            Note::from(Text::TerminalTooOld).shown(),
            "the agent is too old for terminal sessions; restart it"
        );
    }

    #[test]
    fn an_agent_too_old_for_transparent_sessions_is_said_to_be_so_only_for_them() {
        let office = || "office".parse::<GatewayName>().unwrap();
        let refused = |error: &str| Ok(Response::Error(error.to_owned()));
        let too_old = Some(Note::from(Text::TransparentTooOld));
        assert_eq!(
            failure(
                Command::Launch(office(), Mode::Transparent),
                refused(ipc::INVALID_LAUNCH_REQUEST)
            ),
            too_old
        );
        assert_eq!(
            failure(
                Command::Terminal(office(), Mode::Transparent),
                refused(ipc::INVALID_TERMINAL_REQUEST)
            ),
            too_old
        );
        assert_eq!(
            failure(
                Command::Launch(office(), Mode::Proxy),
                refused(ipc::INVALID_LAUNCH_REQUEST)
            ),
            said(ipc::INVALID_LAUNCH_REQUEST)
        );
        assert_eq!(
            failure(
                Command::Terminal(office(), Mode::Proxy),
                refused(ipc::INVALID_TERMINAL_REQUEST)
            ),
            said(ipc::INVALID_TERMINAL_REQUEST)
        );
        assert_eq!(
            failure(
                Command::Launch(office(), Mode::Transparent),
                refused("no gateway office")
            ),
            said("no gateway office")
        );
        assert_eq!(
            failure(
                Command::Terminal(office(), Mode::Proxy),
                refused(ipc::INVALID_REQUEST)
            ),
            Some(Text::TerminalTooOld.into())
        );
        assert_eq!(
            Note::from(Text::TransparentTooOld).shown(),
            "the agent is too old for transparent sessions; restart it"
        );
        let _zh = crate::i18n::speaking(crate::i18n::Language::Chinese);
        assert_eq!(
            Note::from(Text::TransparentTooOld).shown(),
            "代理程式版本過舊，不支援透明工作階段；請重新啟動它"
        );
    }

    #[test]
    fn launches_and_terminals_carry_the_chosen_mode() {
        let office = || "office".parse::<GatewayName>().unwrap();
        for mode in [Mode::Proxy, Mode::Transparent] {
            assert_eq!(
                Command::Launch(office(), mode).request(),
                Ok(Request::Launch(
                    LaunchRequest::new("office", LaunchAuth::SessionCredentials.as_str()).unwrap(),
                    mode
                ))
            );
            assert_eq!(
                Command::Terminal(office(), mode).request(),
                Ok(Request::Terminal(TerminalRequest {
                    gateway: office(),
                    route: None,
                    mode
                }))
            );
        }
        assert_eq!(
            Command::Launch(office(), Mode::Transparent)
                .request()
                .unwrap()
                .to_string(),
            "launch office session_credentials route=saved mode=transparent"
        );
        assert_eq!(
            Command::Terminal(office(), Mode::Transparent)
                .request()
                .unwrap()
                .to_string(),
            "terminal office route=saved mode=transparent"
        );
    }

    #[test]
    fn a_stop_tells_how_many_terminals_it_closed() {
        let stopped = |count: &str| {
            opened(&[
                "agent-pid: 41",
                &format!("{}{count}", ipc::CLOSED_TERMINALS),
            ])
        };
        assert_eq!(failure(Command::Stop, stopped("0")), None);
        assert_eq!(failure(Command::Stop, opened(&["agent-pid: 41"])), None);
        let one = failure(Command::Stop, stopped("1")).unwrap();
        assert_eq!(one.shown(), "Closed 1 terminal session");
        let two = failure(Command::Stop, stopped("2")).unwrap();
        assert_eq!(two.shown(), "Closed 2 terminal sessions");
        let _zh = crate::i18n::speaking(crate::i18n::Language::Chinese);
        assert_eq!(two.shown(), "已關閉 2 個終端機工作階段");
        assert_eq!(failure(Command::Close(1), stopped("2")), None);
    }

    #[test]
    fn start_browser_leaves_the_route_to_the_saved_gateway() {
        let request = Command::Launch("office".parse().unwrap(), Mode::Proxy)
            .request()
            .unwrap();
        assert_eq!(
            request.to_string(),
            "launch office session_credentials route=saved"
        );
        let Request::Launch(launch, _) = request else {
            panic!("expected a launch request");
        };
        assert_eq!(launch.route, None);
    }
}
