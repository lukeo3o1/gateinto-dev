use std::future::Future;
use std::time::Duration;

use gateinto::ipc::{Request, RequestError, Response};
use gateinto::sessions::SessionId;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::agent::AgentState;

pub const POLL: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Close(u64),
    Stop,
}

impl Command {
    fn request(self) -> Request {
        match self {
            Command::Close(id) => Request::Close(SessionId::from(id)),
            Command::Stop => Request::Stop,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Update {
    pub state: AgentState,
    pub failure: Option<String>,
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

pub fn failure(command: Command, reply: Result<Response, RequestError>) -> Option<String> {
    match reply {
        Ok(Response::Ok(_)) => None,
        Ok(Response::Error(message)) => Some(message),
        Err(RequestError::NotRunning) if command == Command::Stop => None,
        Err(error) => Some(error.to_string()),
    }
}

pub async fn serve<F, R>(
    mut commands: UnboundedReceiver<Command>,
    send: F,
    mut deliver: impl FnMut(Update),
) where
    F: Fn(Request) -> R,
    R: Future<Output = Result<Response, RequestError>>,
{
    let mut failure = None;
    loop {
        let state = AgentState::from_list(send(Request::List).await);
        deliver(Update {
            state,
            failure: failure.take(),
        });
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else { return };
                failure = self::failure(command, send(command.request()).await);
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
            failure: failure.map(str::to_owned),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn polls_at_once_and_then_every_two_seconds() {
        let log = RefCell::new(Vec::new());
        let (_tx, rx) = unbounded_channel();
        let mut updates = Vec::new();
        let run = serve(rx, agent(&log), |u| updates.push(u));
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
        let run = serve(rx, agent(&log), |u| updates.push(u));
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
        let run = serve(rx, agent(&log), |u| updates.push(u));
        assert!(timeout(Duration::from_secs(10), run).await.is_ok());
        assert_eq!(updates, [polled(None)]);
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
    }
}
