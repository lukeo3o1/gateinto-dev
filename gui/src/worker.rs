use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use gateinto::config::GatewayName;
use gateinto::ipc::{self, Request, RequestError, Response};
use gateinto::link::Known;
use gateinto::sessions::SessionId;
use gateinto::uri::{LaunchAuth, LaunchRequest};
use tokio::sync::mpsc::UnboundedReceiver;

use crate::agent::AgentState;
use crate::device::{KeyState, Probe, System};
use crate::settings::Agent;

pub const POLL: Duration = Duration::from_secs(2);
pub const CONFIRMATION: &str =
    "the agent asked to confirm this gateway; open its gateinto:// link to confirm it";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Close(u64),
    Stop,
    Launch(GatewayName),
    Probe,
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
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Loaded {
    pub gateways: Result<Known, String>,
    pub agent: Result<Agent, String>,
    pub listen: Result<SocketAddr, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Update {
    pub state: AgentState,
    pub gateways: Result<Known, String>,
    pub agent: Result<Agent, String>,
    pub listen: Result<SocketAddr, String>,
    pub failure: Option<String>,
    pub launched: u64,
    pub device: Option<Probe>,
}

#[derive(Debug)]
pub struct Mailbox {
    open: bool,
    update: Option<Update>,
}

impl Default for Mailbox {
    fn default() -> Self {
        Self {
            open: true,
            update: None,
        }
    }
}

impl Mailbox {
    pub fn put(&mut self, update: Update) -> bool {
        self.open && self.update.replace(update).is_none()
    }

    pub fn take(&mut self) -> Option<Update> {
        self.update.take()
    }

    pub fn close(&mut self) {
        self.open = false;
        self.update = None;
    }
}

pub fn stalled(error: String, loaded: Loaded) -> Update {
    Update {
        state: AgentState::Unreachable(error.clone()),
        gateways: loaded.gateways,
        agent: loaded.agent,
        listen: loaded.listen,
        failure: None,
        launched: 0,
        device: Some(Probe {
            key: KeyState::Failed(error),
            system: System::default(),
        }),
    }
}

pub fn failure(command: Command, reply: Result<Response, RequestError>) -> Option<String> {
    match reply {
        Ok(Response::Ok(_)) => None,
        Ok(Response::Error(message)) => Some(message),
        Err(RequestError::NotRunning) if matches!(command, Command::Stop) => None,
        Err(error) => Some(error.to_string()),
    }
}

async fn run<F, R>(command: Command, send: &F) -> Option<String>
where
    F: Fn(Request) -> R,
    R: Future<Output = Result<Response, RequestError>>,
{
    let request = match command.request() {
        Ok(request) => request,
        Err(error) => return Some(error),
    };
    let reply = send(request).await;
    if let Ok(Response::Ok(lines)) = &reply
        && let Some(token) = ipc::confirm_token(lines)
    {
        let _ = send(Request::Deny(token)).await;
        return Some(CONFIRMATION.to_owned());
    }
    failure(command, reply)
}

pub async fn serve<F, R>(
    mut commands: UnboundedReceiver<Command>,
    send: F,
    mut load: impl FnMut() -> Loaded,
    mut probe: impl FnMut() -> Probe,
    mut deliver: impl FnMut(Update),
) where
    F: Fn(Request) -> R,
    R: Future<Output = Result<Response, RequestError>>,
{
    let mut failure = None;
    let mut launched = 0;
    let mut device = None;
    loop {
        let state = AgentState::from_list(send(Request::List).await);
        let Loaded {
            gateways,
            agent,
            listen,
        } = load();
        deliver(Update {
            state,
            gateways,
            agent,
            listen,
            failure: failure.take(),
            launched,
            device: device.clone(),
        });
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else { return };
                if command == Command::Probe {
                    device = Some(probe());
                    continue;
                }
                let launch = matches!(command, Command::Launch(_));
                failure = run(command, &send).await;
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

    use gateinto::uri::{LaunchAuth, LaunchRequest};

    use gateinto::proxy::DEFAULT_LISTEN;

    use super::*;

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

    fn polled(failure: Option<&str>) -> Update {
        Update {
            state: AgentState::Running(Vec::new()),
            gateways: Ok(Known::default()),
            agent: Ok(Agent::default()),
            listen: Ok(DEFAULT_LISTEN),
            failure: failure.map(str::to_owned),
            launched: 0,
            device: None,
        }
    }

    fn loaded() -> Loaded {
        Loaded {
            gateways: Ok(Known::default()),
            agent: Ok(Agent::default()),
            listen: Ok(DEFAULT_LISTEN),
        }
    }

    fn unprobed() -> Probe {
        panic!("probed the device without being asked")
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
        let run = serve(rx, agent(&log), loaded, read, |u| updates.push(u.device));
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
        let run = serve(rx, agent(&log), loaded, unprobed, |u| updates.push(u));
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
        let run = serve(rx, agent(&log), loaded, unprobed, |u| updates.push(u));
        assert!(timeout(Duration::from_millis(2_500), run).await.is_err());
        assert_eq!(
            updates,
            [polled(None), polled(Some("no session 5")), polled(None)]
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
        let run = serve(rx, agent(&log), loaded, unprobed, |u| updates.push(u));
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
            agent: Err(format!("agent {n}")),
            listen: Err(format!("listen {n}")),
        };
        let load = || {
            *reads.borrow_mut() += 1;
            read(*reads.borrow())
        };
        let mut updates = Vec::new();
        let run = serve(rx, agent(&log), load, unprobed, |u| {
            updates.push(Loaded {
                gateways: u.gateways,
                agent: u.agent,
                listen: u.listen,
            })
        });
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
        let run = serve(rx, launcher(&log, lines), loaded, unprobed, |u| {
            updates.push(u)
        });
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
        let run = serve(rx, launcher(&log, lines), loaded, unprobed, |u| {
            updates.push(u)
        });
        assert!(timeout(Duration::from_millis(500), run).await.is_err());
        assert_eq!(
            updates,
            [polled(None), launched(polled(Some(CONFIRMATION)))]
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

    #[test]
    fn a_worker_that_cannot_start_shows_why_instead_of_waiting_for_the_device() {
        let update = stalled("no timer".to_owned(), loaded());
        assert_eq!(
            update,
            Update {
                state: AgentState::Unreachable("no timer".to_owned()),
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
        assert!(!mailbox.put(polled(Some("busy"))));
        assert_eq!(mailbox.take(), Some(polled(Some("busy"))));
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
            Some("no session 1".to_owned())
        );
        assert_eq!(
            failure(Command::Close(1), Err(RequestError::NotRunning)),
            Some("no agent is running".to_owned())
        );
        assert_eq!(
            failure(Command::Stop, Err(RequestError::Closed)),
            Some("the agent closed the connection without an answer".to_owned())
        );
    }

    #[test]
    fn stopping_an_agent_that_is_not_running_is_not_a_failure() {
        assert_eq!(failure(Command::Stop, Err(RequestError::NotRunning)), None);
        let office = || Command::Launch("office".parse().unwrap());
        assert_eq!(
            failure(office(), Err(RequestError::NotRunning)),
            Some("no agent is running".to_owned())
        );
    }
}
