use std::error::Error;
use std::fmt;
use std::future::Future;
use std::io;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::watch;
use tokio::time::{Instant, sleep_until, timeout, timeout_at};
use tracing::debug;

use crate::divert::helper::{
    EXIT_ENGINE_FAILED, EXIT_NOT_REPORTED, EXIT_REPORTED, ListenerPort, PipeName,
};
use crate::divert::protocol::{
    ErrorCode, Event, MAX_LINE_BYTES, ProtocolError, Snapshot, StatusReader,
};
use crate::divert::{Counters, Dscp};

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::{Elevated, Server, Windows};

pub const PREVIOUS_HELPER_TIMEOUT: Duration = Duration::from_secs(25);
pub const START_TIMEOUT: Duration = Duration::from_secs(60);
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

const ERROR_CANCELLED: i32 = 1223;
const NOT_REPORTED: u32 = EXIT_NOT_REPORTED as u32;
const REPORTED: u32 = EXIT_REPORTED as u32;
const ENGINE_FAILED: u32 = EXIT_ENGINE_FAILED as u32;

pub trait Platform: Send + Sync + 'static {
    type Pipe: Pipe;
    type Process: Process;

    fn create_pipe(&self, name: &PipeName) -> io::Result<Self::Pipe>;
    fn launch(
        &self,
        arguments: Vec<String>,
    ) -> impl Future<Output = io::Result<Self::Process>> + Send;
}

pub trait Pipe: AsyncRead + Unpin + Send + 'static {
    fn connect(&mut self) -> impl Future<Output = io::Result<()>> + Send;
    fn client_pid(&self) -> io::Result<u32>;
}

pub trait Process: Send + 'static {
    fn id(&self) -> u32;
    fn wait(self) -> impl Future<Output = Option<u32>> + Send + 'static;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exit(Option<u32>);

impl Exit {
    pub fn code(self) -> Option<u32> {
        self.0
    }
}

impl fmt::Display for Exit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(NOT_REPORTED) => f.write_str(
                "the transparent engine ended without reporting its status (exit code 3)",
            ),
            Some(REPORTED) => f.write_str(
                "the transparent engine ended after an error report that did not arrive \
                 (exit code 4)",
            ),
            Some(ENGINE_FAILED) => f.write_str("the transparent engine failed (exit code 5)"),
            Some(code) => write!(f, "the transparent engine ended with exit code {code}"),
            None => f.write_str("the transparent engine ended with an unknown exit code"),
        }
    }
}

#[derive(Debug)]
pub enum StartError {
    PreviousRunning,
    Random,
    Pipe(io::Error),
    Declined,
    Launch(io::Error),
    TimedOut,
    UnknownClient,
    Failed(ErrorCode),
    Exited(Exit),
    Protocol(ProtocolError),
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PreviousRunning => f.write_str("the previous transparent engine has not ended"),
            Self::Random => f.write_str("the system random number generator failed"),
            Self::Pipe(error) => {
                write!(
                    f,
                    "creating the pipe of the transparent engine failed: {error}"
                )
            }
            Self::Declined => {
                f.write_str("the administrator approval for the transparent engine was declined")
            }
            Self::Launch(error) => write!(f, "starting the transparent engine failed: {error}"),
            Self::TimedOut => write!(
                f,
                "the transparent engine did not report within {} s",
                START_TIMEOUT.as_secs()
            ),
            Self::UnknownClient => {
                f.write_str("the process on the pipe of the transparent engine is not the engine")
            }
            Self::Failed(code) => f.write_str(match code {
                ErrorCode::InvalidArguments => "the transparent engine refused its arguments",
                ErrorCode::AnotherHelper => {
                    "another transparent engine is running or still ending on this machine; try \
                     again in a few seconds"
                }
                ErrorCode::FirewallRule => "the transparent engine could not add its firewall rule",
                ErrorCode::FilesMissing => "the WinDivert files are missing next to gateinto.exe",
                ErrorCode::DigestMismatch => {
                    "the WinDivert files next to gateinto.exe are not those of the pinned release"
                }
                ErrorCode::DriverLoad(error) => {
                    return write!(
                        f,
                        "the WinDivert driver could not be loaded (Windows error {error})"
                    );
                }
                ErrorCode::DriverVersion => "a WinDivert driver of another version is loaded",
            }),
            Self::Exited(exit) => exit.fmt(f),
            Self::Protocol(error) => {
                write!(
                    f,
                    "the transparent engine broke the status protocol: {error}"
                )
            }
        }
    }
}

impl Error for StartError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Pipe(error) | Self::Launch(error) => Some(error),
            Self::Protocol(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stopped {
    Closed,
    EngineFailed,
    Protocol(ProtocolError),
    Exited(Exit),
}

impl fmt::Display for Stopped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => f.write_str("the pipe of the transparent engine closed"),
            Self::EngineFailed => f.write_str("the transparent engine stopped processing packets"),
            Self::Protocol(error) => {
                write!(
                    f,
                    "the transparent engine broke the status protocol: {error}"
                )
            }
            Self::Exited(exit) => exit.fmt(f),
        }
    }
}

type Ended = watch::Receiver<Option<Exit>>;

pub struct Supervisor<P> {
    platform: P,
    previous: Mutex<Option<Ended>>,
}

impl<P: Platform> Supervisor<P> {
    pub fn new(platform: P) -> Self {
        Self {
            platform,
            previous: Mutex::new(None),
        }
    }

    pub async fn start(
        &self,
        port: ListenerPort,
        dscp: Dscp,
    ) -> Result<Running<P::Pipe>, StartError> {
        let previous = self.previous().clone();
        if let Some(mut previous) = previous {
            timeout(PREVIOUS_HELPER_TIMEOUT, ended(&mut previous))
                .await
                .map_err(|_| StartError::PreviousRunning)?;
        }
        let name = PipeName::from_random(random()?);
        let mut pipe = self.platform.create_pipe(&name).map_err(StartError::Pipe)?;
        let process = self
            .platform
            .launch(arguments(&name, port, dscp))
            .await
            .map_err(launch_error)?;
        let deadline = Instant::now() + START_TIMEOUT;
        let pid = process.id();
        let exited = watch_exit(process);
        *self.previous() = Some(exited.clone());
        let mut reader = StatusReader::new();
        let rest = first_status(&mut pipe, &mut reader, pid, exited.clone(), deadline).await?;
        rest.iter().for_each(log);
        Ok(Running {
            pipe,
            reader,
            exited,
            stopping: rest.contains(&Event::Stopping),
        })
    }

    pub async fn wait_for_exit(&self) {
        let previous = self.previous().clone();
        if let Some(mut previous) = previous {
            ended(&mut previous).await;
        }
    }

    fn previous(&self) -> MutexGuard<'_, Option<Ended>> {
        self.previous.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

pub struct Running<P> {
    pipe: P,
    reader: StatusReader,
    exited: Ended,
    stopping: bool,
}

impl<P: Pipe> Running<P> {
    pub async fn wait_for_stop(&mut self) -> Stopped {
        if self.stopping {
            return Stopped::EngineFailed;
        }
        tokio::select! {
            biased;
            stopped = counters(&mut self.pipe, &mut self.reader) => stopped,
            exit = ended(&mut self.exited) => Stopped::Exited(exit),
        }
    }

    #[cfg(test)]
    async fn stopped(mut self) -> Stopped {
        self.wait_for_stop().await
    }
}

async fn counters<P: Pipe>(pipe: &mut P, reader: &mut StatusReader) -> Stopped {
    loop {
        match events(pipe, reader).await {
            Ok(events) => {
                events.iter().for_each(log);
                if events.contains(&Event::Stopping) {
                    return Stopped::EngineFailed;
                }
            }
            Err(End::Closed) => return Stopped::Closed,
            Err(End::Protocol(error)) => return Stopped::Protocol(error),
        }
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
fn pipe_sddl(user_sid: &str) -> String {
    format!("O:{user_sid}D:P(A;;GA;;;{user_sid})(A;;GA;;;BA)")
}

fn random() -> Result<[u8; 16], StartError> {
    let mut bytes = [0; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| StartError::Random)?;
    Ok(bytes)
}

fn arguments(pipe: &PipeName, port: ListenerPort, dscp: Dscp) -> Vec<String> {
    vec![
        "divert".to_owned(),
        "--pipe".to_owned(),
        pipe.to_string(),
        "--agent-pid".to_owned(),
        std::process::id().to_string(),
        "--port".to_owned(),
        port.to_string(),
        "--dscp".to_owned(),
        dscp.to_string(),
    ]
}

fn launch_error(error: io::Error) -> StartError {
    match error.raw_os_error() {
        Some(ERROR_CANCELLED) => StartError::Declined,
        _ => StartError::Launch(error),
    }
}

fn watch_exit<R: Process>(process: R) -> Ended {
    let (sender, exited) = watch::channel(None);
    tokio::spawn(async move {
        let code = process.wait().await;
        sender.send_replace(Some(Exit(code)));
    });
    exited
}

async fn ended(exited: &mut Ended) -> Exit {
    let exit = exited
        .wait_for(Option::is_some)
        .await
        .ok()
        .and_then(|exit| *exit);
    exit.unwrap_or(Exit(None))
}

enum Status {
    Ready(Vec<Event>),
    Closed,
    Refused(StartError),
}

enum First {
    Status(Status),
    Exited(Exit),
    TimedOut,
}

async fn first_status<P: Pipe>(
    pipe: &mut P,
    reader: &mut StatusReader,
    pid: u32,
    mut exited: Ended,
    deadline: Instant,
) -> Result<Vec<Event>, StartError> {
    let status = status(pipe, reader, pid);
    tokio::pin!(status);
    let first = tokio::select! {
        biased;
        status = &mut status => First::Status(status),
        exit = ended(&mut exited) => First::Exited(exit),
        () = sleep_until(deadline) => First::TimedOut,
    };
    match first {
        First::Status(Status::Ready(rest)) => Ok(rest),
        First::Status(Status::Closed) => match timeout_at(deadline, ended(&mut exited)).await {
            Ok(exit) => Err(StartError::Exited(exit)),
            Err(_) => Err(StartError::TimedOut),
        },
        First::Status(Status::Refused(error)) => Err(error),
        First::Exited(exit) => {
            let drained = timeout_at(deadline.min(Instant::now() + DRAIN_TIMEOUT), status).await;
            match drained {
                Ok(Status::Refused(error)) => Err(error),
                Ok(Status::Ready(_) | Status::Closed) | Err(_) => Err(StartError::Exited(exit)),
            }
        }
        First::TimedOut => Err(StartError::TimedOut),
    }
}

async fn status<P: Pipe>(pipe: &mut P, reader: &mut StatusReader, pid: u32) -> Status {
    if pipe.connect().await.is_err() {
        return Status::Closed;
    }
    if !pipe.client_pid().is_ok_and(|client| client == pid) {
        return Status::Refused(StartError::UnknownClient);
    }
    match events(pipe, reader).await {
        Ok(mut events) => match events.remove(0) {
            Event::Ready => Status::Ready(events),
            Event::Failed(code) => Status::Refused(StartError::Failed(code)),
            Event::Stopping => Status::Refused(StartError::Protocol(ProtocolError::UnknownLine)),
            Event::Counters(_) => {
                Status::Refused(StartError::Protocol(ProtocolError::CountersBeforeReady))
            }
        },
        Err(End::Closed) => Status::Closed,
        Err(End::Protocol(error)) => Status::Refused(StartError::Protocol(error)),
    }
}

enum End {
    Closed,
    Protocol(ProtocolError),
}

async fn events<P: Pipe>(pipe: &mut P, reader: &mut StatusReader) -> Result<Vec<Event>, End> {
    let mut buffer = [0; MAX_LINE_BYTES];
    loop {
        let read = pipe.read(&mut buffer).await.unwrap_or(0);
        if read == 0 {
            return Err(reader.finish().map_or_else(End::Protocol, |()| End::Closed));
        }
        let events = reader.push(&buffer[..read]).map_err(End::Protocol)?;
        if !events.is_empty() {
            return Ok(events);
        }
    }
}

fn log(event: &Event) {
    let Event::Counters(Snapshot {
        engine:
            Counters {
                captured,
                new_flows,
                reflected,
                replies_restored,
                syn_retransmits,
                orphans_dropped,
                key_collisions,
                unknown_replies_dropped,
                fragments_dropped,
                malformed_dropped,
                options_dropped,
                table_full,
                contained_udp,
                contained_other,
                contained_ipv6,
                inbound_dropped,
            },
        receive_errors,
        send_errors,
    }) = event
    else {
        return;
    };
    debug!(
        captured,
        new_flows,
        reflected,
        replies_restored,
        syn_retransmits,
        orphans_dropped,
        key_collisions,
        unknown_replies_dropped,
        fragments_dropped,
        malformed_dropped,
        options_dropped,
        table_full,
        contained_udp,
        contained_other,
        contained_ipv6,
        inbound_dropped,
        receive_errors,
        send_errors,
        "transparent engine counters"
    );
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncWriteExt, DuplexStream, ReadBuf};
    use tokio::sync::{mpsc, oneshot};
    use tokio::task::JoinHandle;
    use tokio::time::{Instant, sleep, timeout};

    use super::*;

    const HELPER: u32 = 4242;
    const PORT: u16 = 50000;
    const SOON: Duration = Duration::from_millis(100);

    struct FakePipe {
        connected: oneshot::Receiver<u32>,
        client: Option<u32>,
        data: DuplexStream,
    }

    impl AsyncRead for FakePipe {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.data).poll_read(cx, buffer)
        }
    }

    impl Pipe for FakePipe {
        async fn connect(&mut self) -> io::Result<()> {
            if self.client.is_none() {
                let pid = (&mut self.connected)
                    .await
                    .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
                self.client = Some(pid);
            }
            Ok(())
        }

        fn client_pid(&self) -> io::Result<u32> {
            self.client
                .ok_or_else(|| io::ErrorKind::NotConnected.into())
        }
    }

    struct FakeProcess {
        id: u32,
        exit: oneshot::Receiver<u32>,
    }

    impl Process for FakeProcess {
        async fn wait(self) -> Option<u32> {
            match self.exit.await {
                Ok(code) => Some(code),
                Err(_) => std::future::pending().await,
            }
        }

        fn id(&self) -> u32 {
            self.id
        }
    }

    struct Helper {
        connect: Option<oneshot::Sender<u32>>,
        writer: Option<DuplexStream>,
        exit: Option<oneshot::Sender<u32>>,
    }

    impl Helper {
        fn connect(&mut self) {
            self.connect_as(HELPER);
        }

        fn connect_as(&mut self, pid: u32) {
            let _ = self.connect.take().expect("connected once").send(pid);
        }

        async fn write(&mut self, text: &str) -> io::Result<()> {
            let writer = self.writer.as_mut().expect("the pipe is open");
            writer.write_all(text.as_bytes()).await?;
            writer.flush().await
        }

        async fn report(&mut self, text: &str) {
            self.connect();
            self.write(text).await.unwrap();
        }

        fn close(&mut self) {
            drop(self.writer.take());
        }

        fn exit(&mut self, code: u32) {
            let _ = self.exit.take().expect("exited once").send(code);
        }
    }

    struct FakeState {
        launches: VecDeque<(Duration, io::Result<u32>)>,
        pipe_error: Option<io::Error>,
        names: Vec<String>,
        arguments: Vec<Vec<String>>,
        launched: Vec<Instant>,
        client: Option<(oneshot::Sender<u32>, DuplexStream)>,
        helpers: mpsc::UnboundedSender<Helper>,
    }

    #[derive(Clone)]
    struct Fake(Arc<Mutex<FakeState>>);

    impl Fake {
        fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
            self.0.lock().unwrap()
        }

        fn will_launch(&self, delay: Duration, result: io::Result<u32>) {
            self.state().launches.push_back((delay, result));
        }

        fn names(&self) -> Vec<String> {
            self.state().names.clone()
        }

        fn launched(&self) -> Vec<Instant> {
            self.state().launched.clone()
        }
    }

    impl Platform for Fake {
        type Pipe = FakePipe;
        type Process = FakeProcess;

        fn create_pipe(&self, name: &PipeName) -> io::Result<FakePipe> {
            let mut state = self.state();
            state.names.push(name.to_string());
            if let Some(error) = state.pipe_error.take() {
                return Err(error);
            }
            let (connect, connected) = oneshot::channel();
            let (data, writer) = tokio::io::duplex(4096);
            state.client = Some((connect, writer));
            Ok(FakePipe {
                connected,
                client: None,
                data,
            })
        }

        async fn launch(&self, arguments: Vec<String>) -> io::Result<FakeProcess> {
            let (delay, result) = {
                let mut state = self.state();
                state.arguments.push(arguments);
                state
                    .launches
                    .pop_front()
                    .unwrap_or((Duration::ZERO, Ok(HELPER)))
            };
            sleep(delay).await;
            let id = result?;
            let mut state = self.state();
            state.launched.push(Instant::now());
            let (connect, writer) = state.client.take().expect("the pipe exists");
            let (exit, exited) = oneshot::channel();
            let _ = state.helpers.send(Helper {
                connect: Some(connect),
                writer: Some(writer),
                exit: Some(exit),
            });
            Ok(FakeProcess { id, exit: exited })
        }
    }

    struct Harness {
        supervisor: Arc<Supervisor<Fake>>,
        fake: Fake,
        helpers: mpsc::UnboundedReceiver<Helper>,
    }

    type Started = JoinHandle<Result<Running<FakePipe>, StartError>>;

    impl Harness {
        fn new() -> Self {
            let (sender, helpers) = mpsc::unbounded_channel();
            let fake = Fake(Arc::new(Mutex::new(FakeState {
                launches: VecDeque::new(),
                pipe_error: None,
                names: Vec::new(),
                arguments: Vec::new(),
                launched: Vec::new(),
                client: None,
                helpers: sender,
            })));
            Self {
                supervisor: Arc::new(Supervisor::new(fake.clone())),
                fake,
                helpers,
            }
        }

        fn start(&self) -> Started {
            let supervisor = self.supervisor.clone();
            tokio::spawn(async move {
                supervisor
                    .start(ListenerPort::new(PORT).unwrap(), Dscp::DEFAULT)
                    .await
            })
        }

        async fn helper(&mut self) -> Helper {
            self.helpers.recv().await.expect("a helper was launched")
        }

        async fn running(&mut self) -> (Running<FakePipe>, Helper) {
            let started = self.start();
            let mut helper = self.helper().await;
            helper.report("ready\n").await;
            (started.await.unwrap().unwrap(), helper)
        }
    }

    async fn failure(started: Started) -> StartError {
        match started.await.unwrap() {
            Ok(_) => panic!("the start succeeded"),
            Err(error) => error,
        }
    }

    async fn failed_with(text: &str) -> StartError {
        let mut harness = Harness::new();
        let started = harness.start();
        harness.helper().await.report(text).await;
        failure(started).await
    }

    fn assert_send<T: Send>(_: &T) {}

    #[tokio::test(start_paused = true)]
    async fn a_helper_that_reports_ready_is_running_and_was_given_its_arguments() {
        let mut harness = Harness::new();
        let (running, _helper) = harness.running().await;
        assert_send(&running);
        let names = harness.fake.names();
        assert_eq!(names.len(), 1);
        assert_eq!(PipeName::parse(&names[0]).unwrap().as_str(), names[0]);
        let pid = std::process::id().to_string();
        assert_eq!(
            harness.fake.state().arguments,
            [[
                "divert",
                "--pipe",
                &names[0],
                "--agent-pid",
                &pid,
                "--port",
                "50000",
                "--dscp",
                "43"
            ]]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn each_start_uses_a_new_random_pipe_name() {
        let mut harness = Harness::new();
        let (first, mut helper) = harness.running().await;
        drop(first);
        helper.exit(0);
        drop(harness.running().await);
        let names = harness.fake.names();
        assert_eq!(names.len(), 2);
        assert_ne!(names[0], names[1]);
    }

    #[tokio::test(start_paused = true)]
    async fn the_start_is_send() {
        let harness = Harness::new();
        let start = harness
            .supervisor
            .start(ListenerPort::new(PORT).unwrap(), Dscp::DEFAULT);
        assert_send(&start);
    }

    #[tokio::test(start_paused = true)]
    async fn each_error_code_fails_the_start_with_its_message() {
        for (code, message) in [
            (
                ErrorCode::InvalidArguments,
                "the transparent engine refused its arguments",
            ),
            (
                ErrorCode::AnotherHelper,
                "another transparent engine is running or still ending on this machine; try \
                 again in a few seconds",
            ),
            (
                ErrorCode::FirewallRule,
                "the transparent engine could not add its firewall rule",
            ),
            (
                ErrorCode::FilesMissing,
                "the WinDivert files are missing next to gateinto.exe",
            ),
            (
                ErrorCode::DigestMismatch,
                "the WinDivert files next to gateinto.exe are not those of the pinned release",
            ),
            (
                ErrorCode::DriverLoad(1275),
                "the WinDivert driver could not be loaded (Windows error 1275)",
            ),
            (
                ErrorCode::DriverVersion,
                "a WinDivert driver of another version is loaded",
            ),
        ] {
            let error = failed_with(&Event::Failed(code).line()).await;
            assert!(
                matches!(error, StartError::Failed(failed) if failed == code),
                "{error:?}"
            );
            assert_eq!(error.to_string(), message);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_line_other_than_a_status_fails_the_start_as_a_protocol_error() {
        let counters = Event::Counters(Snapshot::default()).line();
        for (text, expected) in [
            (counters.as_str(), ProtocolError::CountersBeforeReady),
            ("hello\n", ProtocolError::UnknownLine),
            ("error unknown-code\n", ProtocolError::UnknownLine),
            ("\n", ProtocolError::EmptyLine),
            ("ready\nready\n", ProtocolError::SecondStatus),
            (
                "error another-helper\nready\n",
                ProtocolError::LineAfterError,
            ),
        ] {
            let error = failed_with(text).await;
            assert!(
                matches!(error, StartError::Protocol(found) if found == expected),
                "{text:?}: {error:?}"
            );
        }
        assert_eq!(
            StartError::Protocol(ProtocolError::UnknownLine).to_string(),
            "the transparent engine broke the status protocol: the divert helper sent an \
             unknown line"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_line_cut_off_by_the_end_of_the_pipe_is_a_protocol_error() {
        let mut harness = Harness::new();
        let started = harness.start();
        let mut helper = harness.helper().await;
        helper.report("rea").await;
        helper.close();
        let error = failure(started).await;
        assert!(
            matches!(error, StartError::Protocol(ProtocolError::UnfinishedLine)),
            "{error:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_helper_that_exits_before_connecting_is_reported_with_its_exit_code() {
        for (code, message) in [
            (
                3,
                "the transparent engine ended without reporting its status (exit code 3)",
            ),
            (
                4,
                "the transparent engine ended after an error report that did not arrive \
                 (exit code 4)",
            ),
            (5, "the transparent engine failed (exit code 5)"),
            (0, "the transparent engine ended with exit code 0"),
            (
                3221225477,
                "the transparent engine ended with exit code 3221225477",
            ),
        ] {
            let mut harness = Harness::new();
            let begun = Instant::now();
            let started = harness.start();
            let mut helper = harness.helper().await;
            sleep(Duration::from_secs(5)).await;
            helper.exit(code);
            let error = failure(started).await;
            assert!(
                matches!(error, StartError::Exited(exit) if exit.code() == Some(code)),
                "{error:?}"
            );
            assert_eq!(error.to_string(), message);
            assert_eq!(begun.elapsed(), Duration::from_secs(5) + DRAIN_TIMEOUT);
        }
        assert_eq!(
            StartError::Exited(Exit(None)).to_string(),
            "the transparent engine ended with an unknown exit code"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_error_line_followed_by_an_immediate_exit_is_drained_and_reported_with_its_code() {
        let mut harness = Harness::new();
        let started = harness.start();
        let mut helper = harness.helper().await;
        helper.write("error digest-mismatch\n").await.unwrap();
        helper.close();
        helper.exit(4);
        sleep(SOON).await;
        helper.connect();
        let error = failure(started).await;
        assert!(
            matches!(error, StartError::Failed(ErrorCode::DigestMismatch)),
            "{error:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn ready_from_a_helper_that_has_already_exited_fails_with_its_exit_code() {
        let mut harness = Harness::new();
        let started = harness.start();
        let mut helper = harness.helper().await;
        helper.write("ready\n").await.unwrap();
        helper.exit(5);
        sleep(SOON).await;
        helper.connect();
        let error = failure(started).await;
        assert!(
            matches!(error, StartError::Exited(exit) if exit.code() == Some(5)),
            "{error:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_helper_that_closes_the_pipe_without_a_line_is_reported_once_it_exits() {
        let mut harness = Harness::new();
        let begun = Instant::now();
        let started = harness.start();
        let mut helper = harness.helper().await;
        helper.connect();
        helper.close();
        sleep(Duration::from_secs(2)).await;
        helper.exit(3);
        let error = failure(started).await;
        assert!(
            matches!(error, StartError::Exited(exit) if exit.code() == Some(3)),
            "{error:?}"
        );
        assert_eq!(begun.elapsed(), Duration::from_secs(2));

        let begun = Instant::now();
        let started = harness.start();
        let mut helper = harness.helper().await;
        helper.connect();
        helper.close();
        let error = failure(started).await;
        assert!(matches!(error, StartError::TimedOut), "{error:?}");
        assert_eq!(begun.elapsed(), START_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn the_start_timeout_runs_from_the_launch_returning() {
        let prompt = Duration::from_secs(30);
        let mut harness = Harness::new();
        harness.fake.will_launch(prompt, Ok(HELPER));
        let begun = Instant::now();
        let started = harness.start();
        let mut helper = harness.helper().await;
        helper.connect();
        let error = failure(started).await;
        assert!(matches!(error, StartError::TimedOut), "{error:?}");
        assert_eq!(begun.elapsed(), prompt + START_TIMEOUT);
        assert_eq!(
            error.to_string(),
            "the transparent engine did not report within 60 s"
        );

        helper.exit(3);
        harness.fake.will_launch(prompt, Ok(HELPER));
        let started = harness.start();
        let mut helper = harness.helper().await;
        sleep(START_TIMEOUT - SOON).await;
        helper.report("ready\n").await;
        assert!(started.await.unwrap().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn a_declined_prompt_and_a_failed_launch_are_reported() {
        let mut harness = Harness::new();
        harness
            .fake
            .will_launch(SOON, Err(io::Error::from_raw_os_error(1223)));
        let error = failure(harness.start()).await;
        assert!(matches!(error, StartError::Declined), "{error:?}");
        assert_eq!(
            error.to_string(),
            "the administrator approval for the transparent engine was declined"
        );

        harness
            .fake
            .will_launch(SOON, Err(io::Error::other("no shell")));
        let error = failure(harness.start()).await;
        assert!(matches!(error, StartError::Launch(_)), "{error:?}");
        assert_eq!(
            error.to_string(),
            "starting the transparent engine failed: no shell"
        );
        assert!(harness.fake.launched().is_empty());
        assert!(harness.helpers.try_recv().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn a_pipe_that_cannot_be_created_fails_the_start_before_any_launch() {
        let harness = Harness::new();
        harness.fake.state().pipe_error = Some(io::Error::other("no pipe"));
        let error = failure(harness.start()).await;
        assert!(matches!(error, StartError::Pipe(_)), "{error:?}");
        assert_eq!(
            error.to_string(),
            "creating the pipe of the transparent engine failed: no pipe"
        );
        assert!(harness.fake.state().arguments.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_pipe_opened_by_another_process_fails_the_start_and_is_closed() {
        let mut harness = Harness::new();
        let started = harness.start();
        let mut helper = harness.helper().await;
        helper.connect_as(HELPER + 1);
        helper.write("ready\n").await.unwrap();
        let error = failure(started).await;
        assert!(matches!(error, StartError::UnknownClient), "{error:?}");
        assert_eq!(
            error.to_string(),
            "the process on the pipe of the transparent engine is not the engine"
        );
        let closed = helper.write("counters\n").await.unwrap_err();
        assert_eq!(closed.kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test(start_paused = true)]
    async fn after_ready_counters_keep_it_running() {
        let mut harness = Harness::new();
        let (running, mut helper) = harness.running().await;
        let stopped = tokio::spawn(running.stopped());
        helper
            .write(&Event::Counters(Snapshot::default()).line())
            .await
            .unwrap();
        sleep(START_TIMEOUT).await;
        assert!(!stopped.is_finished());
        helper.close();
        assert_eq!(stopped.await.unwrap(), Stopped::Closed);
        assert_eq!(
            Stopped::Closed.to_string(),
            "the pipe of the transparent engine closed"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn ready_and_stopping_in_one_read_preserve_the_pipe_until_the_agent_drops_it() {
        let mut harness = Harness::new();
        let started = harness.start();
        let mut helper = harness.helper().await;
        helper.connect_as(HELPER);
        helper.write("ready\nstopping\n").await.unwrap();
        let mut running = started.await.unwrap().unwrap();

        assert_eq!(running.wait_for_stop().await, Stopped::EngineFailed);
        assert!(helper.write("ignored").await.is_ok());
        drop(running);
        assert_eq!(
            helper.write("ignored").await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[tokio::test(start_paused = true)]
    async fn after_ready_a_protocol_error_ends_the_run() {
        for (text, expected) in [
            ("ready\n", ProtocolError::SecondStatus),
            ("error firewall-rule\n", ProtocolError::SecondStatus),
            ("counters captured=1\n", ProtocolError::InvalidCounters),
            ("bye\n", ProtocolError::UnknownLine),
        ] {
            let mut harness = Harness::new();
            let (running, mut helper) = harness.running().await;
            helper.write(text).await.unwrap();
            assert_eq!(
                running.stopped().await,
                Stopped::Protocol(expected),
                "{text}"
            );
        }
        let mut harness = Harness::new();
        let (running, mut helper) = harness.running().await;
        helper.write("count").await.unwrap();
        helper.close();
        assert_eq!(
            running.stopped().await,
            Stopped::Protocol(ProtocolError::UnfinishedLine)
        );
        assert_eq!(
            Stopped::Protocol(ProtocolError::SecondStatus).to_string(),
            "the transparent engine broke the status protocol: the divert helper sent a \
             second status line"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn after_ready_the_exit_of_the_helper_ends_the_run_with_its_code() {
        let mut harness = Harness::new();
        let (running, mut helper) = harness.running().await;
        let stopped = running.stopped();
        assert_send(&stopped);
        helper.exit(5);
        let stopped = stopped.await;
        assert_eq!(stopped, Stopped::Exited(Exit(Some(5))));
        assert_eq!(
            stopped.to_string(),
            "the transparent engine failed (exit code 5)"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_the_running_handle_closes_the_pipe() {
        let mut harness = Harness::new();
        let (running, mut helper) = harness.running().await;
        drop(running);
        let closed = helper.write("ready\n").await.unwrap_err();
        assert_eq!(closed.kind(), io::ErrorKind::BrokenPipe);
    }

    fn numbered() -> Snapshot {
        Snapshot {
            engine: Counters {
                captured: 1,
                new_flows: 2,
                reflected: 3,
                replies_restored: 4,
                syn_retransmits: 5,
                orphans_dropped: 6,
                key_collisions: 7,
                unknown_replies_dropped: 8,
                fragments_dropped: 9,
                malformed_dropped: 10,
                options_dropped: 11,
                table_full: 12,
                contained_udp: 13,
                contained_other: 14,
                contained_ipv6: 15,
                inbound_dropped: 16,
            },
            receive_errors: 17,
            send_errors: 18,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn counter_lines_are_logged_at_debug_as_aggregate_fields() {
        let logs = crate::test_logs::capture();
        let mut harness = Harness::new();
        let started = harness.start();
        let mut helper = harness.helper().await;
        let counters = Event::Counters(numbered()).line();
        helper.report(&format!("ready\n{counters}")).await;
        let running = started.await.unwrap().unwrap();
        let stopped = tokio::spawn(running.stopped());
        helper.write(&counters).await.unwrap();
        helper.close();
        assert_eq!(stopped.await.unwrap(), Stopped::Closed);
        let lines = logs.lines(" DEBUG ");
        assert_eq!(lines.len(), 2, "{:?}", logs.lines(""));
        let names = harness.fake.names();
        let pid = std::process::id().to_string();
        for line in &lines {
            assert!(line.contains("transparent engine counters"), "{line}");
            for field in counters.trim_end().split(' ').skip(1) {
                assert!(line.contains(field), "{field} in {line}");
            }
            assert!(!line.contains(&names[0]), "{line}");
            assert!(!line.contains("pipe"), "{line}");
            assert!(!line.contains(&format!("={pid}")), "{line}");
            assert!(!line.contains(&PORT.to_string()), "{line}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_next_start_waits_for_the_previous_helper_to_end() {
        let mut harness = Harness::new();
        let (running, mut first) = harness.running().await;
        drop(running);
        let begun = Instant::now();
        let started = harness.start();
        sleep(Duration::from_secs(3)).await;
        assert_eq!(harness.fake.names().len(), 1);
        first.exit(0);
        harness.helper().await.report("ready\n").await;
        assert!(started.await.unwrap().is_ok());
        assert_eq!(harness.fake.launched()[1] - begun, Duration::from_secs(3));
    }

    #[tokio::test(start_paused = true)]
    async fn the_next_start_fails_when_the_previous_helper_does_not_end_in_time() {
        let mut harness = Harness::new();
        let (running, _first) = harness.running().await;
        drop(running);
        let begun = Instant::now();
        let error = failure(harness.start()).await;
        assert!(matches!(error, StartError::PreviousRunning), "{error:?}");
        assert_eq!(begun.elapsed(), PREVIOUS_HELPER_TIMEOUT);
        assert_eq!(
            error.to_string(),
            "the previous transparent engine has not ended"
        );
        assert_eq!(harness.fake.names().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_start_still_makes_the_next_start_wait_for_its_helper() {
        let mut harness = Harness::new();
        let started = harness.start();
        let mut first = harness.helper().await;
        first.connect_as(HELPER + 1);
        assert!(matches!(failure(started).await, StartError::UnknownClient));
        let started = harness.start();
        sleep(Duration::from_secs(4)).await;
        assert_eq!(harness.fake.names().len(), 1);
        first.exit(3);
        harness.helper().await.report("ready\n").await;
        assert!(started.await.unwrap().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn a_running_helper_that_stops_is_not_waited_for_by_the_next_start() {
        let mut harness = Harness::new();
        let (running, mut first) = harness.running().await;
        first.exit(5);
        assert_eq!(running.stopped().await, Stopped::Exited(Exit(Some(5))));
        let begun = Instant::now();
        let (_running, _second) = timeout(SOON, harness.running()).await.unwrap();
        assert_eq!(begun.elapsed(), Duration::ZERO);
    }

    #[test]
    fn the_pipe_is_owned_by_the_user_and_open_only_to_it_and_the_administrators() {
        assert_eq!(
            pipe_sddl("S-1-5-21-1-2-3-1001"),
            "O:S-1-5-21-1-2-3-1001D:P(A;;GA;;;S-1-5-21-1-2-3-1001)(A;;GA;;;BA)"
        );
    }

    #[test]
    fn the_timeouts_are_those_of_the_design() {
        assert_eq!(PREVIOUS_HELPER_TIMEOUT, Duration::from_secs(25));
        assert_eq!(START_TIMEOUT, Duration::from_secs(60));
        assert_eq!(DRAIN_TIMEOUT, Duration::from_secs(1));
    }

    #[test]
    fn the_other_start_errors_name_their_cause() {
        assert_eq!(
            StartError::Random.to_string(),
            "the system random number generator failed"
        );
        assert!(StartError::Launch(io::Error::other("x")).source().is_some());
        assert!(StartError::TimedOut.source().is_none());
    }
}
