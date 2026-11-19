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
    plans: Mutex<VecDeque<Plan>>,
    stops: Mutex<Vec<oneshot::Sender<String>>>,
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

    fn running(&self) -> Boxed<'static, String> {
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
        let stop = self.stops.lock().unwrap().pop().expect("a helper runs");
        stop.send(message.to_owned()).unwrap();
    }

    fn served(&self) -> Vec<(Generation, bool)> {
        self.served.lock().unwrap().clone()
    }
}

impl Engine for Helpers {
    fn available(&self) -> Availability {
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
                Plan::StopsAtOnce(message) => Box::pin(std::future::ready(message)),
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

#[derive(Default)]
struct Gateways {
    browser_plan: Option<&'static str>,
}

impl Profiles for Gateways {
    fn known(&self) -> Result<Known, String> {
        Ok(Known {
            gateways: vec![KnownGateway {
                name: "office".parse().unwrap(),
                display_name: None,
                host: Some("127.0.0.1".to_owned()),
                port: Some(9),
                portal_url: None,
                route: proxy::Route::Gateway,
                source: Source::Config,
            }],
            invalid: Vec::new(),
            unavailable: None,
        })
    }

    fn link(&self, _: &LinkedGateway) -> Result<(), String> {
        Err("not used".to_owned())
    }

    fn browser_session(&self, _: &GatewayName) -> Result<BrowserSessionPlan, String> {
        if let Some(error) = self.browser_plan {
            return Err(error.to_owned());
        }
        Ok(BrowserSessionPlan {
            proxy: super::no_job_retry::proxy_config(),
        })
    }

    fn terminal_session(&self, gateway: &GatewayName) -> Result<TerminalSessionPlan, String> {
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
async fn a_launch_that_holds_the_mark_when_the_helper_stops_is_closed_once_it_started() {
    for request in both() {
        let (spawn_gate, opener) = gate();
        let h = harness(|setup| setup.processes.spawn_gate = spawn_gate);
        let launching = tokio::spawn({
            let agent = h.agent.clone();
            async move { answer(&agent, request).await }
        });
        let release = opener.entered().await;

        h.helpers.stop(STOPPED);
        until("the handler stopped the engine", || async {
            h.agent.inner.registry.phase() == Phase::Stopped
        })
        .await;
        assert_eq!(h.events.count(Event::Spawned), 0);
        release.send(()).unwrap();

        assert!(launching.await.unwrap().is_ok());
        assert_eq!(h.events.count(Event::Spawned), 1);
        until("the stopped helper closed the session", || async {
            session_ids(&h.agent).await.is_empty()
                && h.agent.inner.browsers.lock().await.is_empty()
                && h.agent.inner.terminals.lock().await.is_empty()
        })
        .await;
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
        h.agent.transparent_availability(),
        Availability::Unavailable(Reason::TooOld)
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
