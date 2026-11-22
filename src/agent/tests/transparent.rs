use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::net::{TcpListener, TcpStream};

use super::*;
use crate::agent::engine::{Boxed, Engine, Listener, Registry, Started};
use crate::divert::protocol::ErrorCode;
use crate::ipc::SessionInfo;
use crate::link::{KnownGateway, Source};
use crate::proxy::Adopter;
use crate::transparent::availability::{Availability, Reason};
use crate::transparent::helper::StartError;
use crate::transparent::state::{Begin, Generation, Phase};

const PATIENCE: Duration = Duration::from_secs(10);
const STOPPED: &str = "the pipe of the transparent engine closed";

fn dscp() -> Dscp {
    Dscp::new(10).unwrap()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    HelperStarted(Dscp),
    AwaitHelperExit,
    Ready,
    Job,
    Tagged(Dscp),
    Spawned,
}

#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<Event>>>);

impl Events {
    fn push(&self, event: Event) {
        self.0.lock().unwrap().push(event);
    }

    fn all(&self) -> Vec<Event> {
        self.0.lock().unwrap().clone()
    }

    fn count(&self, event: Event) -> usize {
        self.all()
            .into_iter()
            .filter(|&found| found == event)
            .count()
    }
}

enum Plan {
    Ready,
    Fails(String),
    StopsAtOnce(String),
    Gated(oneshot::Receiver<Result<(), String>>),
}

type Served = Arc<Mutex<Vec<(Generation, bool)>>>;

#[derive(Default)]
struct Helpers {
    events: Events,
    unavailable: Option<Reason>,
    checks: Threads,
    check_panics: bool,
    plans: Mutex<VecDeque<Plan>>,
    stops: Mutex<Vec<oneshot::Sender<EngineStopped>>>,
    exit: Mutex<Option<oneshot::Receiver<Result<(), String>>>>,
    served: Served,
}

impl Helpers {
    fn will(&self, plan: Plan) {
        self.plans.lock().unwrap().push_back(plan);
    }

    fn gated(&self) -> oneshot::Sender<Result<(), String>> {
        let (open, gate) = oneshot::channel();
        self.will(Plan::Gated(gate));
        open
    }

    fn running(&self) -> Boxed<'static, EngineStopped> {
        let (stop, stopped) = oneshot::channel();
        self.stops.lock().unwrap().push(stop);
        Box::pin(async move {
            match stopped.await {
                Ok(message) => message,
                Err(_) => std::future::pending().await,
            }
        })
    }

    fn stop(&self, message: &str) {
        self.report_stop(message, None);
    }

    fn report_stop(&self, message: &str, capture: Option<Box<dyn Send>>) {
        let stop = self.stops.lock().unwrap().pop().expect("a helper runs");
        assert!(
            stop.send(EngineStopped {
                message: message.to_owned(),
                capture
            })
            .is_ok()
        );
    }

    fn served(&self) -> Vec<(Generation, bool)> {
        self.served.lock().unwrap().clone()
    }
}

impl Engine for Helpers {
    fn available(&self) -> Availability {
        record(&self.checks);
        assert!(!self.check_panics, "the availability check panicked");
        self.unavailable
            .map_or(Availability::Available, Availability::Unavailable)
    }

    fn start(&self, dscp: Dscp) -> Boxed<'_, Result<Started, String>> {
        self.events.push(Event::HelperStarted(dscp));
        let plan = self
            .plans
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Plan::Ready);
        Box::pin(async move {
            let stopped = match plan {
                Plan::Ready => self.running(),
                Plan::Fails(message) => return Err(message),
                Plan::StopsAtOnce(message) => Box::pin(std::future::ready(EngineStopped {
                    message,
                    capture: None,
                })),
                Plan::Gated(gate) => {
                    gate.await
                        .unwrap_or_else(|_| Err("the gate was dropped".to_owned()))?;
                    self.running()
                }
            };
            self.events.push(Event::Ready);
            Ok(Started {
                stopped,
                listener: Box::new(FakeListener(self.served.clone())),
            })
        })
    }

    fn wait_for_exit(&self) -> Boxed<'_, Result<(), String>> {
        let exit = self.exit.lock().unwrap().take();
        Box::pin(async move {
            if let Some(exit) = exit {
                self.events.push(Event::AwaitHelperExit);
                return exit
                    .await
                    .unwrap_or_else(|_| Err("the exit gate was dropped".to_owned()));
            }
            Ok(())
        })
    }
}

struct FakeListener(Served);

impl Listener for FakeListener {
    fn serve(
        self: Box<Self>,
        _: Arc<Registry>,
        generation: Generation,
        shutdown: Boxed<'static, ()>,
    ) -> Boxed<'static, ()> {
        let served = self.0;
        served.lock().unwrap().push((generation, false));
        Box::pin(async move {
            shutdown.await;
            for entry in served.lock().unwrap().iter_mut() {
                if entry.0 == generation {
                    entry.1 = true;
                }
            }
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Spawn {
    Runs,
    JobRefused,
    Fails,
}

struct Gate {
    entered: std::sync::mpsc::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

struct Opener {
    entered: std::sync::mpsc::Receiver<()>,
    release: std::sync::mpsc::Sender<()>,
}

impl Opener {
    async fn entered(self) -> std::sync::mpsc::Sender<()> {
        let Opener { entered, release } = self;
        tokio::task::spawn_blocking(move || entered.recv_timeout(PATIENCE))
            .await
            .unwrap()
            .expect("the gate was not entered");
        release
    }
}

fn gate() -> (Mutex<Option<Gate>>, Opener) {
    let (entered, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release) = std::sync::mpsc::channel();
    (
        Mutex::new(Some(Gate { entered, release })),
        Opener {
            entered: entered_rx,
            release: release_tx,
        },
    )
}

fn pass(gate: &Mutex<Option<Gate>>) {
    let gate = gate.lock().unwrap().take();
    if let Some(gate) = gate {
        gate.entered.send(()).unwrap();
        gate.release.recv().unwrap();
    }
}

struct Processes {
    events: Events,
    terminals: bool,
    job: bool,
    tag_fails: bool,
    spawn: Spawn,
    home: Option<&'static str>,
    browsers: Mutex<Vec<Vec<OsString>>>,
    shells: Mutex<Vec<TerminalSpawn>>,
    spawn_gate: Mutex<Option<Gate>>,
    tag_gate: Mutex<Option<Gate>>,
}

impl Processes {
    fn new(events: Events) -> Self {
        Self {
            events,
            terminals: true,
            job: true,
            tag_fails: false,
            spawn: Spawn::Runs,
            home: Some("/home/ana"),
            browsers: Mutex::new(Vec::new()),
            shells: Mutex::new(Vec::new()),
            spawn_gate: Mutex::new(None),
            tag_gate: Mutex::new(None),
        }
    }

    fn spawned(&self) -> Result<BrowserProcess, SpawnError> {
        pass(&self.spawn_gate);
        self.events.push(Event::Spawned);
        match self.spawn {
            Spawn::Runs => browser::spawn(Path::new("/bin/sleep"), vec!["30".into()], None),
            Spawn::JobRefused => Err(SpawnError::Job(io::Error::other("assigning refused"))),
            Spawn::Fails => Err(SpawnError::Process(io::Error::other("not found"))),
        }
    }
}

impl Launcher for Processes {
    fn job(&self) -> Option<Arc<Job>> {
        self.events.push(Event::Job);
        self.job.then(|| Arc::new(Job::fake()))
    }

    fn spawn(
        &self,
        _: &Path,
        args: Vec<OsString>,
        _: Option<&Arc<Job>>,
    ) -> Result<BrowserProcess, SpawnError> {
        self.browsers.lock().unwrap().push(args);
        self.spawned()
    }

    fn terminals(&self) -> bool {
        self.terminals
    }

    fn terminal_job(&self) -> io::Result<Job> {
        self.events.push(Event::Job);
        Ok(Job::fake())
    }

    fn environment(&self) -> Variables {
        let home = self.home.map(|home| ("USERPROFILE", home));
        home.into_iter()
            .chain([("Path", r"C:\Windows")])
            .map(|(name, value)| (name.into(), value.into()))
            .collect()
    }

    fn spawn_terminal(
        &self,
        spawn: TerminalSpawn,
        _: &Arc<Job>,
    ) -> Result<BrowserProcess, SpawnError> {
        self.shells.lock().unwrap().push(spawn);
        self.spawned()
    }

    fn tag(&self, _: &Job, dscp: Dscp) -> io::Result<()> {
        pass(&self.tag_gate);
        self.events.push(Event::Tagged(dscp));
        if self.tag_fails {
            return Err(io::Error::other("access denied"));
        }
        Ok(())
    }
}

type Threads = Arc<Mutex<Vec<std::thread::ThreadId>>>;

fn record(threads: &Threads) {
    threads.lock().unwrap().push(std::thread::current().id());
}

#[derive(Default)]
struct Gateways {
    browser_plan: Option<&'static str>,
    terminal_plan_breaks: Option<&'static str>,
    forgets: bool,
    builds: Threads,
    reads: Threads,
    links: Threads,
}

fn again(calls: &Threads) -> bool {
    record(calls);
    calls.lock().unwrap().len() > 1
}

impl Profiles for Gateways {
    fn known(&self) -> Result<Known, String> {
        let office = KnownGateway {
            name: "office".parse().unwrap(),
            display_name: None,
            host: Some("127.0.0.1".to_owned()),
            port: Some(9),
            portal_url: None,
            route: proxy::Route::Gateway,
            source: Source::Config,
        };
        Ok(Known {
            gateways: (!(again(&self.reads) && self.forgets))
                .then_some(office)
                .into_iter()
                .collect(),
            invalid: Vec::new(),
            unavailable: None,
        })
    }

    fn link(&self, _: &LinkedGateway) -> Result<(), String> {
        record(&self.links);
        Ok(())
    }

    fn browser_session(&self, _: &GatewayName) -> Result<BrowserSessionPlan, String> {
        record(&self.builds);
        if let Some(error) = self.browser_plan {
            return Err(error.to_owned());
        }
        Ok(BrowserSessionPlan {
            proxy: super::no_job_retry::proxy_config(),
        })
    }

    fn terminal_session(&self, gateway: &GatewayName) -> Result<TerminalSessionPlan, String> {
        if let (true, Some(error)) = (again(&self.builds), self.terminal_plan_breaks) {
            return Err(error.to_owned());
        }
        if gateway.as_str() != "office" {
            return Err(format!("unknown gateway \"{gateway}\""));
        }
        Ok(TerminalSessionPlan {
            proxy: super::no_job_retry::proxy_config(),
            route: proxy::Route::Gateway,
            shell: Shell {
                executable: PathBuf::from("/opt/shells/pwsh"),
                args: Vec::new(),
            },
        })
    }
}

struct Harness {
    agent: Agent,
    events: Events,
    processes: Arc<Processes>,
    helpers: Arc<Helpers>,
    root: PathBuf,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

static HARNESSES: AtomicUsize = AtomicUsize::new(0);

struct Setup {
    processes: Processes,
    helpers: Helpers,
    limits: AgentLimits,
    gateways: Gateways,
    browser: &'static str,
}

fn harness(configure: impl FnOnce(&mut Setup)) -> Harness {
    let events = Events::default();
    let mut setup = Setup {
        processes: Processes::new(events.clone()),
        helpers: Helpers {
            events: events.clone(),
            ..Helpers::default()
        },
        limits: AgentLimits::default(),
        gateways: Gateways::default(),
        browser: "/bin/sleep",
    };
    configure(&mut setup);
    let (processes, helpers) = (Arc::new(setup.processes), Arc::new(setup.helpers));
    let root = std::env::temp_dir().join(format!(
        "gateinto-transparent-agent-{}-{}",
        std::process::id(),
        HARNESSES.fetch_add(1, Ordering::Relaxed)
    ));
    let agent = Agent::with_seams(
        AgentOptions {
            browser: Some(PathBuf::from(setup.browser)),
            profiles_root: root.clone(),
            limits: setup.limits,
            logbook: Default::default(),
            config: ipc::ConfigSource::Defaults,
            dscp: dscp(),
        },
        setup.gateways,
        processes.clone(),
        helpers.clone(),
    );
    Harness {
        agent,
        events,
        processes,
        helpers,
        root,
    }
}

fn plain() -> Harness {
    harness(|_| {})
}

fn serve(harness: &Harness) -> (ipc::Endpoint, oneshot::Sender<()>, JoinHandle<()>) {
    let endpoint = ipc::Endpoint::unix(harness.root.join("agent.sock"));
    let server = Server::bind(&endpoint).unwrap();
    let (shutdown, requested) = oneshot::channel();
    let agent = harness.agent.clone();
    let serving = tokio::spawn(async move {
        agent
            .serve(server, async {
                let _ = requested.await;
            })
            .await;
    });
    (endpoint, shutdown, serving)
}

fn terminal(mode: Mode) -> Request {
    terminal_for("office", mode)
}

fn terminal_for(gateway: &str, mode: Mode) -> Request {
    Request::Terminal(TerminalRequest {
        gateway: gateway.parse().unwrap(),
        route: None,
        mode,
    })
}

fn browser(mode: Mode) -> Request {
    Request::Launch(
        LaunchRequest::new("office", "session_credentials").unwrap(),
        mode,
    )
}

fn new_gateway() -> Request {
    let link = LaunchRequest::new("newco", "session_credentials")
        .unwrap()
        .with_link(
            None,
            Some("127.0.0.1:10"),
            Some("https://portal.newco.example/home"),
        )
        .unwrap();
    Request::Launch(link, Mode::Proxy)
}

async fn approved(agent: &Agent) -> Vec<String> {
    let lines = answer(agent, new_gateway()).await.unwrap();
    let token = ipc::confirm_token(&lines).unwrap_or_else(|| panic!("{lines:?}"));
    answer(agent, Request::Approve(token)).await.unwrap()
}

fn both() -> [Request; 2] {
    [terminal(Mode::Transparent), browser(Mode::Transparent)]
}

async fn answer(agent: &Agent, request: Request) -> Result<Vec<String>, String> {
    match agent.handle(request).await {
        Response::Ok(lines) => Ok(lines),
        Response::Error(error) => Err(error),
    }
}

async fn session_ids(agent: &Agent) -> Vec<SessionId> {
    agent
        .inner
        .sessions
        .lock()
        .await
        .sessions()
        .map(crate::sessions::Session::id)
        .collect()
}

fn running(agent: &Agent) -> Generation {
    match agent.inner.registry.phase() {
        Phase::Running(generation) => generation,
        phase => panic!("the engine is {phase:?}"),
    }
}

fn registered(agent: &Agent, generation: Generation) -> Vec<SessionId> {
    agent
        .inner
        .registry
        .jobs(generation)
        .into_iter()
        .map(|(id, _)| id)
        .collect()
}

async fn until<F: Future<Output = bool>>(what: &str, mut done: impl FnMut() -> F) {
    let waited = tokio::time::timeout(PATIENCE, async {
        while !done().await {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(waited.is_ok(), "timed out waiting until {what}");
}

async fn stream() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    (client, listener.accept().await.unwrap().0)
}

fn listen(lines: &[String]) -> SocketAddr {
    lines
        .iter()
        .find_map(|line| line.strip_prefix("listen: "))
        .expect("a listen line")
        .parse()
        .unwrap()
}

const CONFIRMATION: &str = "a transparent session is not started for a request that needs a \
                            gateway confirmation; add the gateway or use its saved route first";

#[tokio::test]
async fn a_transparent_terminal_starts_the_helper_then_tags_its_job_and_then_the_shell() {
    let h = plain();
    let lines = answer(&h.agent, terminal(Mode::Transparent)).await.unwrap();

    assert_eq!(
        h.events.all(),
        [
            Event::HelperStarted(dscp()),
            Event::Ready,
            Event::Job,
            Event::Tagged(dscp()),
            Event::Spawned
        ]
    );
    let ids = session_ids(&h.agent).await;
    assert_eq!(ids.len(), 1);
    let generation = running(&h.agent);
    assert_eq!(registered(&h.agent, generation), ids);
    let url = format!("http://{}", listen(&lines));
    let shells = std::mem::take(&mut *h.processes.shells.lock().unwrap());
    for name in ["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"] {
        assert!(
            shells[0]
                .environment
                .contains(&(name.into(), url.clone().into())),
            "{name} in {:?}",
            shells[0].environment
        );
    }
    let listed = SessionInfo::parse_list(&h.agent.list().await).unwrap();
    assert!(listed[0].transparent);
    let (_client, accepted) = stream().await;
    let target = "203.0.113.7:443".parse().unwrap();
    assert!(
        h.agent
            .inner
            .registry
            .adopt(generation, &ids[0], accepted, target)
            .is_ok()
    );

    h.agent.close_all().await;
    assert!(registered(&h.agent, generation).is_empty());
}

#[tokio::test]
async fn a_transparent_browser_starts_the_helper_then_tags_its_job_and_keeps_its_proxy_setting() {
    let h = plain();
    let lines = answer(&h.agent, browser(Mode::Transparent)).await.unwrap();

    assert_eq!(
        h.events.all(),
        [
            Event::HelperStarted(dscp()),
            Event::Ready,
            Event::Job,
            Event::Tagged(dscp()),
            Event::Spawned
        ]
    );
    let ids = session_ids(&h.agent).await;
    assert_eq!(registered(&h.agent, running(&h.agent)), ids);
    let proxy = OsString::from(format!("--proxy-server=http://{}", listen(&lines)));
    assert!(h.processes.browsers.lock().unwrap()[0].contains(&proxy));
    let listed = SessionInfo::parse_list(&h.agent.list().await).unwrap();
    assert!(listed[0].transparent);
    h.agent.close_all().await;
}

#[tokio::test]
async fn proxy_mode_sessions_start_no_helper_and_are_not_listed_as_transparent() {
    let h = plain();
    answer(&h.agent, terminal(Mode::Proxy)).await.unwrap();
    answer(&h.agent, browser(Mode::Proxy)).await.unwrap();

    assert_eq!(h.events.count(Event::HelperStarted(dscp())), 0);
    assert!(
        !h.events
            .all()
            .iter()
            .any(|event| matches!(event, Event::Tagged(_)))
    );
    assert_eq!(h.agent.inner.registry.phase(), Phase::Stopped);
    let listed = SessionInfo::parse_list(&h.agent.list().await).unwrap();
    assert_eq!(listed.len(), 2);
    assert!(listed.iter().all(|session| !session.transparent));
    h.agent.close_all().await;
}

#[tokio::test]
async fn each_helper_failure_is_answered_with_its_cause_and_starts_nothing() {
    for message in [
        StartError::Failed(ErrorCode::AnotherHelper).to_string(),
        StartError::Declined.to_string(),
        StartError::TimedOut.to_string(),
        StartError::PreviousRunning.to_string(),
        "the transparent engine ended with exit code 7".to_owned(),
    ] {
        for request in both() {
            let h = plain();
            h.helpers.will(Plan::Fails(message.clone()));

            assert_eq!(answer(&h.agent, request).await, Err(message.clone()));
            assert_eq!(h.events.all(), [Event::HelperStarted(dscp())]);
            assert!(session_ids(&h.agent).await.is_empty());
            let status = h.agent.transparent_engine();
            assert_eq!(status.phase, Phase::Stopped);
            assert_eq!(status.last_error, Some(message.clone()));
        }
    }
}

#[tokio::test]
async fn a_helper_that_stops_right_after_ready_fails_the_start_with_its_cause() {
    for request in both() {
        let h = plain();
        h.helpers.will(Plan::StopsAtOnce(STOPPED.to_owned()));

        assert_eq!(answer(&h.agent, request).await, Err(STOPPED.to_owned()));
        assert_eq!(h.events.all(), [Event::HelperStarted(dscp()), Event::Ready]);
        assert_eq!(h.agent.inner.registry.phase(), Phase::Stopped);
        assert!(session_ids(&h.agent).await.is_empty());
        assert!(h.helpers.served().is_empty());
        assert_eq!(
            h.agent.transparent_engine().last_error.as_deref(),
            Some(STOPPED)
        );
    }
}

#[tokio::test]
async fn a_tag_that_cannot_be_set_starts_nothing() {
    for request in both() {
        let h = harness(|setup| setup.processes.tag_fails = true);

        assert_eq!(
            answer(&h.agent, request).await,
            Err(
                "setting the DSCP tag 10 on the job of the session failed: access denied; \
                 nothing was started"
                    .to_owned()
            )
        );
        assert_eq!(
            h.events.all(),
            [
                Event::HelperStarted(dscp()),
                Event::Ready,
                Event::Job,
                Event::Tagged(dscp())
            ]
        );
        assert!(session_ids(&h.agent).await.is_empty());
        assert!(registered(&h.agent, running(&h.agent)).is_empty());
    }
}

#[tokio::test]
async fn a_transparent_browser_without_a_job_starts_nothing() {
    let h = harness(|setup| setup.processes.job = false);

    assert_eq!(
        answer(&h.agent, browser(Mode::Transparent)).await,
        Err(
            "a transparent browser session needs a job object, which could not be created; \
             nothing was started"
                .to_owned()
        )
    );
    assert_eq!(
        h.events.all(),
        [Event::HelperStarted(dscp()), Event::Ready, Event::Job]
    );
    assert!(session_ids(&h.agent).await.is_empty());
}

#[tokio::test]
async fn a_failed_spawn_closes_and_unregisters_its_session_without_a_proxy_mode_retry() {
    for (spawn, reason) in [
        (Spawn::JobRefused, "putting the process in the job failed"),
        (Spawn::Fails, "not found"),
    ] {
        for request in both() {
            let h = harness(|setup| setup.processes.spawn = spawn);

            let error = answer(&h.agent, request).await.unwrap_err();
            assert!(error.starts_with("starting "), "{error}");
            assert!(error.contains(reason), "{error}");
            assert_eq!(h.events.count(Event::Spawned), 1);
            assert!(session_ids(&h.agent).await.is_empty());
            assert!(registered(&h.agent, running(&h.agent)).is_empty());
            assert!(h.agent.inner.browsers.lock().await.is_empty());
            assert!(h.agent.inner.terminals.lock().await.is_empty());
        }
    }
}

#[tokio::test]
async fn a_helper_that_stops_before_registration_refuses_it_without_waiting_for_the_launch() {
    for request in both() {
        let (tag_gate, opener) = gate();
        let h = harness(|setup| setup.processes.tag_gate = tag_gate);
        let is_terminal = matches!(request, Request::Terminal(_));
        let launching = tokio::spawn({
            let agent = h.agent.clone();
            async move { answer(&agent, request).await }
        });
        let release = opener.entered().await;
        let generation = running(&h.agent);

        h.helpers.stop(STOPPED);
        until(
            "the handler stopped the engine and its listener",
            || async {
                h.agent.inner.registry.phase() == Phase::Stopped
                    && h.helpers.served() == [(generation, true)]
            },
        )
        .await;
        if is_terminal {
            assert!(h.agent.inner.terminals.try_lock().is_err());
        }
        release.send(()).unwrap();

        assert_eq!(
            launching.await.unwrap(),
            Err("the transparent engine is not running; nothing was started".to_owned())
        );
        assert_eq!(h.events.count(Event::Spawned), 0);
        assert!(session_ids(&h.agent).await.is_empty());
        assert_eq!(
            h.agent.transparent_engine().last_error.as_deref(),
            Some(STOPPED)
        );
    }
}

#[tokio::test]
async fn closing_a_browser_while_it_starts_keeps_its_job_registered_until_it_can_stop() {
    let (spawn_gate, opener) = gate();
    let h = harness(|setup| setup.processes.spawn_gate = spawn_gate);
    let launching = tokio::spawn({
        let agent = h.agent.clone();
        async move { answer(&agent, browser(Mode::Transparent)).await }
    });
    let release = opener.entered().await;
    let generation = running(&h.agent);
    let id = registered(&h.agent, generation)[0];
    let closing = answer(&h.agent, Request::Close(id));
    tokio::pin!(closing);
    assert!(matches!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(closing.as_mut().poll(cx))).await,
        std::task::Poll::Pending
    ));
    let still_registered = registered(&h.agent, generation);
    release.send(()).unwrap();
    launching.await.unwrap().unwrap();
    closing.await.unwrap();
    assert_eq!(still_registered, [id]);
    assert!(h.agent.inner.browsers.lock().await.is_empty());
    assert!(session_ids(&h.agent).await.is_empty());
}

#[tokio::test]
async fn stopping_cancels_a_launch_waiting_for_administrator_approval() {
    let h = plain();
    let approval = h.helpers.gated();
    let launching = tokio::spawn({
        let agent = h.agent.clone();
        async move { answer(&agent, terminal(Mode::Transparent)).await }
    });
    until("the launch waits for administrator approval", || async {
        h.events.count(Event::HelperStarted(dscp())) == 1
    })
    .await;
    answer(&h.agent, Request::Stop).await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), launching).await;
    assert!(approval.send(Ok(())).is_err());
    assert!(result.unwrap().unwrap().is_err());
    assert_eq!(h.events.count(Event::Spawned), 0);
    assert!(session_ids(&h.agent).await.is_empty());
}

#[tokio::test]
async fn pending_transparent_launches_leave_ipc_capacity_to_list_and_stop() {
    let h = plain();
    let approval = h.helpers.gated();
    let (endpoint, _shutdown, serving) = serve(&h);
    let mut launches = JoinSet::new();
    for waiting in 0..MAX_PENDING_TRANSPARENT_LAUNCHES {
        let endpoint = endpoint.clone();
        launches.spawn(async move {
            ipc::send_with_timeout(&endpoint, &terminal(Mode::Transparent), PATIENCE).await
        });
        until("the launch waits on the same approval", || async {
            h.events.count(Event::HelperStarted(dscp())) == 1
                && h.agent.inner.registry.joiners() >= waiting
        })
        .await;
    }
    assert!(
        matches!(ipc::send(&endpoint, &terminal(Mode::Transparent)).await,
        Ok(Response::Error(message)) if message == TRANSPARENT_LAUNCH_BUSY)
    );
    assert!(matches!(
        ipc::send(&endpoint, &Request::List).await,
        Ok(Response::Ok(_))
    ));
    assert!(matches!(
        ipc::send(&endpoint, &Request::Stop).await,
        Ok(Response::Ok(_))
    ));
    assert!(approval.send(Ok(())).is_err());
    while let Some(launch) = launches.join_next().await {
        assert!(
            matches!(launch.unwrap(), Ok(Response::Error(message)) if message == AGENT_STOPPING)
        );
    }
    serving.await.unwrap();
}

#[tokio::test]
async fn a_stop_during_console_shutdown_waits_for_the_same_helper_exit() {
    let h = plain();
    let (exited, exit) = oneshot::channel();
    *h.helpers.exit.lock().unwrap() = Some(exit);
    let (endpoint, shutdown, serving) = serve(&h);
    shutdown.send(()).unwrap();
    until("console shutdown waits for the helper", || async {
        h.events.count(Event::AwaitHelperExit) == 1
    })
    .await;
    assert!(matches!(
        ipc::send(&endpoint, &Request::List).await,
        Ok(Response::Ok(_))
    ));
    let stop = ipc::send(&endpoint, &Request::Stop);
    tokio::pin!(stop);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut stop)
            .await
            .is_err()
    );
    exited.send(Ok(())).unwrap();
    assert!(matches!(stop.await, Ok(Response::Ok(_))));
    serving.await.unwrap();
}

#[tokio::test]
async fn a_helper_wait_failure_leaves_stop_reachable_and_the_wait_can_be_retried() {
    let h = plain();
    answer(&h.agent, terminal(Mode::Transparent)).await.unwrap();
    let (failed, exit) = oneshot::channel();
    *h.helpers.exit.lock().unwrap() = Some(exit);
    let (endpoint, _shutdown, serving) = serve(&h);
    failed
        .send(Err("could not confirm the helper exit".to_owned()))
        .unwrap();
    assert!(
        matches!(ipc::send(&endpoint, &Request::Stop).await, Ok(Response::Error(message)) if message == "could not confirm the helper exit")
    );
    assert!(
        matches!(ipc::send(&endpoint, &Request::List).await, Ok(Response::Ok(lines)) if lines.is_empty())
    );
    assert!(
        matches!(ipc::send(&endpoint, &Request::Transparent).await, Ok(Response::Error(message)) if message == AGENT_STOPPING)
    );
    assert!(
        matches!(ipc::send(&endpoint, &terminal(Mode::Transparent)).await, Ok(Response::Error(message)) if message == AGENT_STOPPING)
    );

    let (exited, exit) = oneshot::channel();
    *h.helpers.exit.lock().unwrap() = Some(exit);
    exited.send(Ok(())).unwrap();
    assert!(
        matches!(ipc::send(&endpoint, &Request::Stop).await, Ok(Response::Ok(lines)) if ipc::closed_terminals(&lines) == Some(1))
    );
    assert_eq!(h.events.count(Event::AwaitHelperExit), 2);
    serving.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn stopping_is_not_cut_off_by_the_deadline_for_draining_requests() {
    let h = plain();
    let (endpoint, _shutdown, serving) = serve(&h);
    let launching = h.agent.inner.launching.lock().await;
    let stop = tokio::spawn(async move { ipc::send(&endpoint, &Request::Stop).await });
    until("the agent starts shutting down", || async {
        *h.agent.inner.stop.borrow()
    })
    .await;
    tokio::time::advance(DRAIN_TIMEOUT + Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert!(!stop.is_finished());
    drop(launching);
    assert!(matches!(stop.await.unwrap(), Ok(Response::Ok(_))));
    serving.await.unwrap();
}

#[tokio::test]
async fn stop_replies_after_closing_sessions_and_waiting_for_the_helper_to_exit() {
    let h = plain();
    answer(&h.agent, terminal(Mode::Transparent)).await.unwrap();
    let (exited, exit) = oneshot::channel();
    *h.helpers.exit.lock().unwrap() = Some(exit);
    let stopping = tokio::spawn({
        let agent = h.agent.clone();
        async move { answer(&agent, Request::Stop).await }
    });
    until("stop waits for the helper to exit", || async {
        h.events.count(Event::AwaitHelperExit) == 1
    })
    .await;
    assert!(session_ids(&h.agent).await.is_empty());
    assert!(!stopping.is_finished());
    exited.send(Ok(())).unwrap();
    let response = stopping.await.unwrap().unwrap();
    assert_eq!(ipc::closed_terminals(&response), Some(1));
}

#[tokio::test]
async fn a_launch_that_holds_the_mark_when_the_helper_stops_is_closed_once_it_started() {
    for request in both() {
        let (spawn_gate, opener) = gate();
        let h = harness(|setup| setup.processes.spawn_gate = spawn_gate);
        let launching = tokio::spawn({
            let agent = h.agent.clone();
            async move { answer(&agent, request).await }
        });
        let release = opener.entered().await;

        let (capture, mut released) = oneshot::channel::<()>();
        h.helpers.report_stop(STOPPED, Some(Box::new(capture)));
        until("the handler stopped the engine", || async {
            h.agent.inner.registry.phase() == Phase::Stopped
        })
        .await;
        assert_eq!(h.events.count(Event::Spawned), 0);
        assert_eq!(
            released.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        );
        release.send(()).unwrap();

        assert!(launching.await.unwrap().is_ok());
        assert_eq!(h.events.count(Event::Spawned), 1);
        until("the stopped helper closed the session", || async {
            session_ids(&h.agent).await.is_empty()
                && h.agent.inner.browsers.lock().await.is_empty()
                && h.agent.inner.terminals.lock().await.is_empty()
        })
        .await;
        assert!(
            tokio::time::timeout(PATIENCE, released)
                .await
                .unwrap()
                .is_err()
        );
    }
}

#[test]
fn a_launch_after_the_stop_handler_ran_sees_closing_and_starts_nothing() {
    let registry = Registry::new();
    let registry = Arc::new(registry);
    let Begin::Start(starter) = registry.begin() else {
        panic!("the engine is not stopped")
    };
    let generation = starter.generation();
    starter.finish(Ok(())).unwrap();
    let mark = registry
        .register(
            SessionId::from(1),
            Arc::new(Job::fake()),
            Adopter::channel(1).0,
        )
        .unwrap();
    assert_eq!(registry.stop(generation), [SessionId::from(1)]);

    let mut spawned = false;
    let refused = launched(Some(&mark), || {
        spawned = true;
        Ok(())
    });
    assert!(!spawned);
    let error = refused.unwrap_err().to_string();
    assert_eq!(error, "the transparent session is closing");
    assert_eq!(launched(None, || Ok(7)).unwrap(), 7);
}

#[tokio::test]
async fn concurrent_requests_while_the_helper_starts_share_its_success() {
    let h = plain();
    let open = h.helpers.gated();
    let requests: Vec<_> = [
        terminal(Mode::Transparent),
        terminal(Mode::Transparent),
        browser(Mode::Transparent),
    ]
    .into_iter()
    .map(|request| {
        let agent = h.agent.clone();
        tokio::spawn(async move { answer(&agent, request).await })
    })
    .collect();
    until("the other requests joined the start", || async {
        h.agent.inner.registry.joiners() == 2
    })
    .await;
    assert!(matches!(h.agent.inner.registry.phase(), Phase::Starting(_)));

    open.send(Ok(())).unwrap();
    for request in requests {
        assert!(request.await.unwrap().is_ok());
    }
    assert_eq!(h.events.count(Event::HelperStarted(dscp())), 1);
    assert_eq!(registered(&h.agent, running(&h.agent)).len(), 3);
    h.agent.close_all().await;
}

#[tokio::test]
async fn concurrent_requests_while_the_helper_starts_share_its_failure() {
    let h = plain();
    let open = h.helpers.gated();
    let requests: Vec<_> = [terminal(Mode::Transparent), browser(Mode::Transparent)]
        .into_iter()
        .map(|request| {
            let agent = h.agent.clone();
            tokio::spawn(async move { answer(&agent, request).await })
        })
        .collect();
    until("the other request joined the start", || async {
        h.agent.inner.registry.joiners() == 1
    })
    .await;

    let declined = StartError::Declined.to_string();
    open.send(Err(declined.clone())).unwrap();
    for request in requests {
        assert_eq!(request.await.unwrap(), Err(declined.clone()));
    }
    assert_eq!(h.events.count(Event::HelperStarted(dscp())), 1);
    assert!(session_ids(&h.agent).await.is_empty());
}

#[tokio::test]
async fn waiting_for_the_helper_blocks_no_other_launch_and_no_close() {
    let h = plain();
    let open = h.helpers.gated();
    let waiting = tokio::spawn({
        let agent = h.agent.clone();
        async move { answer(&agent, terminal(Mode::Transparent)).await }
    });
    until("the request waits for the helper", || async {
        h.events.count(Event::HelperStarted(dscp())) == 1
    })
    .await;

    let others = tokio::time::timeout(PATIENCE, async {
        answer(&h.agent, terminal(Mode::Proxy)).await.unwrap();
        answer(&h.agent, browser(Mode::Proxy)).await.unwrap();
        let ids = session_ids(&h.agent).await;
        assert_eq!(ids.len(), 2);
        for id in ids {
            answer(&h.agent, Request::Close(id)).await.unwrap();
        }
    })
    .await;
    assert!(others.is_ok(), "a launch or a close waited for the helper");
    assert!(!waiting.is_finished());

    open.send(Ok(())).unwrap();
    assert!(waiting.await.unwrap().is_ok());
    h.agent.close_all().await;
}

#[tokio::test]
async fn a_rate_limited_transparent_request_is_refused_before_the_helper() {
    let h = harness(|setup| setup.limits.launches = 1);
    answer(&h.agent, terminal(Mode::Proxy)).await.unwrap();

    for request in both() {
        let error = answer(&h.agent, request).await.unwrap_err();
        assert!(error.starts_with("too many launch requests"), "{error}");
    }
    assert_eq!(h.events.count(Event::HelperStarted(dscp())), 0);
    h.agent.close_all().await;
}

#[tokio::test]
async fn the_rate_limit_pre_check_takes_no_slot() {
    let h = harness(|setup| setup.limits.launches = 2);
    answer(&h.agent, terminal(Mode::Transparent)).await.unwrap();
    answer(&h.agent, terminal(Mode::Proxy)).await.unwrap();

    let error = answer(&h.agent, terminal(Mode::Proxy)).await.unwrap_err();
    assert!(error.starts_with("too many launch requests"), "{error}");
    h.agent.close_all().await;
}

#[tokio::test]
async fn an_unsupported_platform_is_refused_before_the_helper() {
    let h = harness(|setup| setup.processes.terminals = false);

    assert_eq!(
        answer(&h.agent, terminal(Mode::Transparent)).await,
        Err("terminal sessions from the agent are not supported on this platform".to_owned())
    );
    assert_eq!(h.events.count(Event::HelperStarted(dscp())), 0);
}

#[tokio::test]
async fn unavailable_transparent_sessions_are_refused_with_the_reason_before_the_helper() {
    let h = harness(|setup| setup.helpers.unavailable = Some(Reason::TooOld));

    for request in both() {
        assert_eq!(
            answer(&h.agent, request).await,
            Err(
                "transparent sessions are unavailable: Windows 10 1607 or Windows Server 2016 \
                 or later is required"
                    .to_owned()
            )
        );
    }
    assert_eq!(h.events.count(Event::HelperStarted(dscp())), 0);
    assert_eq!(
        answer(&h.agent, Request::Transparent).await,
        Ok(vec![
            "availability: unavailable: Windows 10 1607 or Windows Server 2016 or later is \
             required"
                .to_owned(),
            "engine: stopped".to_owned()
        ])
    );
    answer(&h.agent, terminal(Mode::Proxy)).await.unwrap();
    h.agent.close_all().await;
}

#[tokio::test]
async fn full_capacity_is_refused_before_the_helper() {
    let h = harness(|setup| {
        setup.limits.max_terminal_sessions = 1;
        setup.limits.max_browser_sessions = 1;
    });
    answer(&h.agent, terminal(Mode::Proxy)).await.unwrap();
    answer(&h.agent, browser(Mode::Proxy)).await.unwrap();

    assert_eq!(
        answer(&h.agent, terminal(Mode::Transparent)).await,
        Err("1 terminal sessions are already open; close one first".to_owned())
    );
    assert_eq!(
        answer(&h.agent, browser(Mode::Transparent)).await,
        Err("1 browser sessions are already open; close one first".to_owned())
    );
    assert_eq!(h.events.count(Event::HelperStarted(dscp())), 0);
    h.agent.close_all().await;
}

#[tokio::test]
async fn a_browser_plan_that_fails_is_refused_before_the_helper() {
    let h = harness(|setup| setup.gateways.browser_plan = Some("the CA file cannot be read"));

    assert_eq!(
        answer(&h.agent, browser(Mode::Transparent)).await,
        Err("the CA file cannot be read".to_owned())
    );
    assert_eq!(h.events.count(Event::HelperStarted(dscp())), 0);
    assert!(session_ids(&h.agent).await.is_empty());
}

#[tokio::test]
async fn browser_plans_are_built_off_the_async_worker_twice_in_transparent_once_in_proxy_mode() {
    let builds = Threads::default();
    let h = harness(|setup| setup.gateways.builds = builds.clone());
    let worker = std::thread::current().id();

    answer(&h.agent, browser(Mode::Transparent)).await.unwrap();
    assert_eq!(builds.lock().unwrap().len(), 2);
    answer(&h.agent, browser(Mode::Proxy)).await.unwrap();

    let builds = builds.lock().unwrap().clone();
    assert_eq!(builds.len(), 3);
    assert!(builds.iter().all(|&thread| thread != worker));
    h.agent.close_all().await;
}

#[tokio::test]
async fn terminal_plans_are_built_off_the_async_worker_twice_in_transparent_once_in_proxy_mode() {
    let builds = Threads::default();
    let h = harness(|setup| setup.gateways.builds = builds.clone());
    let worker = std::thread::current().id();

    answer(&h.agent, terminal(Mode::Transparent)).await.unwrap();
    assert_eq!(builds.lock().unwrap().len(), 2);
    answer(&h.agent, terminal(Mode::Proxy)).await.unwrap();

    let builds = builds.lock().unwrap().clone();
    assert_eq!(builds.len(), 3);
    assert!(builds.iter().all(|&thread| thread != worker));
    h.agent.close_all().await;
}

#[tokio::test]
async fn a_gateway_forgotten_while_the_helper_starts_refuses_the_browser_launch_after_the_start() {
    let h = harness(|setup| setup.gateways.forgets = true);

    assert_eq!(
        answer(&h.agent, browser(Mode::Transparent)).await,
        Err(
            "unknown gateway \"office\": it is not set up on this device and the link does not \
             bring one; the link must provide the gateway address, or an administrator must add \
             [gateways.office] to the config file"
                .to_owned()
        )
    );
    refused_after_the_start(&h).await;
}

#[tokio::test]
async fn a_terminal_plan_that_no_longer_builds_after_the_helper_starts_refuses_the_launch() {
    let h =
        harness(|setup| setup.gateways.terminal_plan_breaks = Some("the CA file cannot be read"));

    assert_eq!(
        answer(&h.agent, terminal(Mode::Transparent)).await,
        Err("the CA file cannot be read".to_owned())
    );
    refused_after_the_start(&h).await;
}

async fn refused_after_the_start(h: &Harness) {
    assert_eq!(h.events.all(), [Event::HelperStarted(dscp()), Event::Ready]);
    assert!(session_ids(&h.agent).await.is_empty());
    assert!(h.processes.browsers.lock().unwrap().is_empty());
    assert!(h.processes.shells.lock().unwrap().is_empty());
    assert!(registered(&h.agent, running(&h.agent)).is_empty());
}

#[tokio::test]
async fn the_gateways_are_read_off_the_async_worker_by_every_launch_and_approval() {
    let reads = Threads::default();
    let h = harness(|setup| setup.gateways.reads = reads.clone());
    let worker = std::thread::current().id();

    answer(&h.agent, browser(Mode::Proxy)).await.unwrap();
    assert_eq!(reads.lock().unwrap().len(), 1);
    answer(&h.agent, browser(Mode::Transparent)).await.unwrap();
    assert_eq!(reads.lock().unwrap().len(), 3);
    answer(&h.agent, terminal(Mode::Proxy)).await.unwrap();
    assert_eq!(reads.lock().unwrap().len(), 4);
    approved(&h.agent).await;

    let reads = reads.lock().unwrap().clone();
    assert_eq!(reads.len(), 6);
    assert!(reads.iter().all(|&thread| thread != worker));
    h.agent.close_all().await;
}

#[tokio::test]
async fn an_approved_gateway_is_stored_off_the_async_worker() {
    let links = Threads::default();
    let h = harness(|setup| setup.gateways.links = links.clone());
    let worker = std::thread::current().id();

    approved(&h.agent).await;

    let links = links.lock().unwrap().clone();
    assert_eq!(links.len(), 1);
    assert!(links.iter().all(|&thread| thread != worker));
    h.agent.close_all().await;
}

#[tokio::test]
async fn a_missing_browser_is_refused_before_the_helper() {
    let h = harness(|setup| setup.browser = "/nonexistent/browser");

    assert_eq!(
        answer(&h.agent, browser(Mode::Transparent)).await,
        Err("browser executable /nonexistent/browser not found".to_owned())
    );
    assert_eq!(h.events.count(Event::HelperStarted(dscp())), 0);
    assert!(session_ids(&h.agent).await.is_empty());
}

#[tokio::test]
async fn a_missing_or_relative_userprofile_is_refused_before_the_helper() {
    for home in [None, Some("ana")] {
        let h = harness(|setup| setup.processes.home = home);

        assert_eq!(
            answer(&h.agent, terminal(Mode::Transparent)).await,
            Err(NO_HOME.to_owned())
        );
        assert_eq!(h.events.count(Event::HelperStarted(dscp())), 0);
        assert!(session_ids(&h.agent).await.is_empty());
    }
}

#[tokio::test]
async fn an_unknown_gateway_or_a_request_needing_a_confirmation_is_refused_before_the_helper() {
    let h = plain();
    assert_eq!(
        answer(&h.agent, terminal_for("newco", Mode::Transparent)).await,
        Err("unknown gateway \"newco\"".to_owned())
    );
    let unknown = LaunchRequest::new("newco", "session_credentials").unwrap();
    assert!(
        answer(&h.agent, Request::Launch(unknown, Mode::Transparent))
            .await
            .is_err()
    );
    let mixed = LaunchRequest::new("office", "session_credentials")
        .unwrap()
        .with_route("mixed")
        .unwrap();
    let added = LaunchRequest::new("newco", "session_credentials")
        .unwrap()
        .with_link(None, Some("newco.example:443"), None)
        .unwrap();
    for request in [mixed, added] {
        assert_eq!(
            answer(&h.agent, Request::Launch(request, Mode::Transparent)).await,
            Err(CONFIRMATION.to_owned())
        );
    }
    assert!(h.agent.inner.launching.lock().await.is_none());
    assert_eq!(h.events.count(Event::HelperStarted(dscp())), 0);
    assert!(session_ids(&h.agent).await.is_empty());
}

#[tokio::test]
async fn a_helper_that_stops_closes_its_transparent_sessions_and_listener_and_no_other() {
    let h = plain();
    for request in [
        terminal(Mode::Transparent),
        browser(Mode::Transparent),
        terminal(Mode::Proxy),
        browser(Mode::Proxy),
    ] {
        answer(&h.agent, request).await.unwrap();
    }
    let generation = running(&h.agent);
    assert_eq!(registered(&h.agent, generation).len(), 2);
    until("the listener serves", || async {
        h.helpers.served() == [(generation, false)]
    })
    .await;

    let failed = "the transparent engine failed (exit code 5)";
    h.helpers.stop(failed);
    until("the transparent sessions closed", || async {
        session_ids(&h.agent).await.len() == 2
    })
    .await;

    assert_eq!(h.helpers.served(), [(generation, true)]);
    assert!(registered(&h.agent, generation).is_empty());
    let status = h.agent.transparent_engine();
    assert_eq!(status.phase, Phase::Stopped);
    assert_eq!(status.last_error.as_deref(), Some(failed));
    let listed = SessionInfo::parse_list(&h.agent.list().await).unwrap();
    assert_eq!(listed.len(), 2);
    assert!(listed.iter().all(|session| !session.transparent));
    assert_eq!(h.agent.inner.terminals.lock().await.len(), 1);
    assert_eq!(h.agent.inner.browsers.lock().await.len(), 1);
    h.agent.close_all().await;
}

#[tokio::test]
async fn a_stop_that_did_not_finish_closes_every_transparent_session_and_no_other() {
    let h = plain();
    for request in [
        terminal(Mode::Transparent),
        browser(Mode::Transparent),
        terminal(Mode::Proxy),
        browser(Mode::Proxy),
    ] {
        answer(&h.agent, request).await.unwrap();
    }
    let generation = running(&h.agent);
    let stopping = tokio::spawn(std::future::pending());
    stopping.abort();

    h.agent.close_stopped(stopping, oneshot::channel().0).await;

    assert!(registered(&h.agent, generation).is_empty());
    let listed = SessionInfo::parse_list(&h.agent.list().await).unwrap();
    assert_eq!(listed.len(), 2);
    assert!(listed.iter().all(|session| !session.transparent));
    h.agent.close_all().await;
}

#[tokio::test]
async fn the_helper_starts_once_while_it_runs_and_again_after_it_stopped() {
    let h = plain();
    answer(&h.agent, terminal(Mode::Transparent)).await.unwrap();
    answer(&h.agent, browser(Mode::Transparent)).await.unwrap();
    assert_eq!(h.events.count(Event::HelperStarted(dscp())), 1);
    let first = running(&h.agent);

    h.helpers.stop(STOPPED);
    until("the first generation closed", || async {
        session_ids(&h.agent).await.is_empty()
    })
    .await;
    answer(&h.agent, terminal(Mode::Transparent)).await.unwrap();

    assert_eq!(h.events.count(Event::HelperStarted(dscp())), 2);
    let second = running(&h.agent);
    assert_ne!(second, first);
    assert_eq!(registered(&h.agent, second).len(), 1);
    h.agent.close_all().await;
}

async fn engine_line(agent: &Agent) -> String {
    let lines = answer(agent, Request::Transparent).await.unwrap();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert_eq!(lines[0], "availability: available");
    lines[1].clone()
}

#[tokio::test]
async fn the_transparent_status_follows_the_engine_through_each_phase() {
    let h = plain();
    assert_eq!(engine_line(&h.agent).await, "engine: stopped");

    let open = h.helpers.gated();
    let starting = tokio::spawn({
        let agent = h.agent.clone();
        async move { answer(&agent, terminal(Mode::Transparent)).await }
    });
    until("the engine is starting", || async {
        matches!(h.agent.inner.registry.phase(), Phase::Starting(_))
    })
    .await;
    assert_eq!(engine_line(&h.agent).await, "engine: starting");

    open.send(Ok(())).unwrap();
    starting.await.unwrap().unwrap();
    assert_eq!(engine_line(&h.agent).await, "engine: running");

    h.helpers.stop(STOPPED);
    until("the engine stopped", || async {
        h.agent.inner.registry.phase() == Phase::Stopped
    })
    .await;
    assert_eq!(
        engine_line(&h.agent).await,
        format!("engine: stopped: {STOPPED}")
    );
    h.agent.close_all().await;
}

#[tokio::test]
async fn the_transparent_status_names_why_the_last_start_failed() {
    let failed = "the transparent engine failed (exit code 5)";
    for (plan, error) in [
        (Plan::Fails(failed.to_owned()), failed),
        (Plan::StopsAtOnce(STOPPED.to_owned()), STOPPED),
    ] {
        let h = plain();
        h.helpers.will(plan);
        answer(&h.agent, browser(Mode::Transparent))
            .await
            .unwrap_err();

        assert_eq!(
            engine_line(&h.agent).await,
            format!("engine: stopped: {error}")
        );
    }
}

#[tokio::test]
async fn a_successful_start_clears_the_error_of_the_last_one() {
    let failed = "the transparent engine failed (exit code 5)";
    let h = plain();
    h.helpers.will(Plan::Fails(failed.to_owned()));
    answer(&h.agent, terminal(Mode::Transparent))
        .await
        .unwrap_err();

    answer(&h.agent, terminal(Mode::Transparent)).await.unwrap();

    assert_eq!(h.agent.transparent_engine().last_error, None);
    assert_eq!(engine_line(&h.agent).await, "engine: running");
    h.helpers.stop(STOPPED);
    until("the engine stopped", || async {
        h.agent.inner.registry.phase() == Phase::Stopped
    })
    .await;
    assert_eq!(
        h.agent.transparent_engine().last_error.as_deref(),
        Some(STOPPED)
    );
    h.agent.close_all().await;
}

#[tokio::test]
async fn a_start_abandoned_by_its_request_is_named_as_the_engine_error() {
    let h = plain();
    let _open = h.helpers.gated();
    let starting = tokio::spawn({
        let agent = h.agent.clone();
        async move { answer(&agent, terminal(Mode::Transparent)).await }
    });
    until("the engine is starting", || async {
        matches!(h.agent.inner.registry.phase(), Phase::Starting(_))
    })
    .await;

    starting.abort();
    assert!(starting.await.unwrap_err().is_cancelled());

    assert_eq!(h.agent.inner.registry.phase(), Phase::Stopped);
    assert_eq!(
        engine_line(&h.agent).await,
        "engine: stopped: the start of the transparent engine was abandoned"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_engine_error_is_stored_before_the_engine_counts_as_stopped() {
    let h = plain();
    answer(&h.agent, terminal(Mode::Transparent)).await.unwrap();
    let launching = h.agent.inner.launching.lock().await;
    let (agent, helpers) = (h.agent.clone(), h.helpers.clone());

    let stopped_unstored = tokio::task::spawn_blocking(move || {
        let error = agent.engine_error();
        helpers.stop(STOPPED);
        let deadline = Instant::now() + Duration::from_millis(300);
        while agent.inner.registry.phase() != Phase::Stopped && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        let stopped = agent.inner.registry.phase() == Phase::Stopped;
        drop(error);
        stopped
    })
    .await
    .unwrap();
    assert!(
        !stopped_unstored,
        "the engine counted as stopped before its error was stored"
    );

    until("the engine stopped", || async {
        h.agent.inner.registry.phase() == Phase::Stopped
    })
    .await;

    assert_eq!(
        h.agent.transparent_engine().last_error.as_deref(),
        Some(STOPPED)
    );
    drop(launching);
    h.agent.close_all().await;
}

#[tokio::test]
async fn the_availability_is_checked_off_the_async_worker() {
    let checks = Threads::default();
    let h = harness(|setup| setup.helpers.checks = checks.clone());
    let worker = std::thread::current().id();

    answer(&h.agent, Request::Transparent).await.unwrap();
    answer(&h.agent, terminal(Mode::Transparent)).await.unwrap();

    let checks = checks.lock().unwrap().clone();
    assert_eq!(checks.len(), 2);
    assert!(checks.iter().all(|&thread| thread != worker));
    h.agent.close_all().await;
}

#[tokio::test]
async fn an_availability_check_that_fails_is_answered_and_starts_nothing() {
    let h = harness(|setup| setup.helpers.check_panics = true);
    for request in [Request::Transparent, terminal(Mode::Transparent)] {
        let error = answer(&h.agent, request).await.unwrap_err();
        assert!(
            error.starts_with("checking whether transparent sessions are available failed: "),
            "{error}"
        );
    }
    assert_eq!(h.events.count(Event::HelperStarted(dscp())), 0);
}
