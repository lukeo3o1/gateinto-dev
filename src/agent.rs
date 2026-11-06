use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsString;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, Notify, Semaphore, oneshot};
use tokio::task::{JoinHandle, JoinSet};
use tracing::{Instrument, info, info_span, warn};

use crate::browser::{self, BrowserProcess, ProfileDir};
use crate::clock::unix_now;
use crate::config::GatewayName;
use crate::ipc::{
    self, BrowserKind, ConfirmToken, Connection, Request, Response, Server, TerminalRequest,
};
use crate::job::{Job, SpawnError};
use crate::link::{self, Ask, Confirm, Decision, Known, Launch, LinkedGateway, Resolution};
use crate::logbook::Logbook;
use crate::proxy::{self, LocalAuth};
use crate::sessions::{SessionConfig, SessionId, SessionKind, SessionManager};
use crate::terminal::{self, Shell, Variables};
use crate::uri::LaunchRequest;

const MAX_CONNECTIONS: usize = 8;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
const DRAIN_REJECTED_BYTES: usize = 64 * 1024;
const DRAIN_REJECTED_TIMEOUT: Duration = Duration::from_secs(1);
const PROFILE_REMOVAL_ATTEMPTS: u32 = 40;
const PROFILE_REMOVAL_DELAY: Duration = Duration::from_millis(250);
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);
const ACCEPT_RETRY_MAX_DELAY: Duration = Duration::from_secs(5);

fn accept_retry_delay(failures: u32) -> Duration {
    match failures.checked_sub(1) {
        None => Duration::ZERO,
        Some(doublings) => ACCEPT_RETRY_DELAY
            .saturating_mul(2u32.saturating_pow(doublings))
            .min(ACCEPT_RETRY_MAX_DELAY),
    }
}

#[derive(Debug, Default)]
struct AcceptBackoff {
    failures: u32,
    retry_at: Option<tokio::time::Instant>,
}

impl AcceptBackoff {
    fn failed(&mut self, now: tokio::time::Instant) {
        self.failures = self.failures.saturating_add(1);
        self.retry_at = Some(now + accept_retry_delay(self.failures));
    }

    fn succeeded(&mut self) {
        *self = Self::default();
    }

    fn retry_at(&self) -> Option<tokio::time::Instant> {
        self.retry_at
    }
}

#[derive(Debug, Clone)]
pub struct AgentLimits {
    pub launches: usize,
    pub launch_window: Duration,
    pub max_browser_sessions: usize,
    pub max_terminal_sessions: usize,
    pub confirm_timeout: Duration,
}

impl Default for AgentLimits {
    fn default() -> Self {
        Self {
            launches: 5,
            launch_window: Duration::from_secs(60),
            max_browser_sessions: 4,
            max_terminal_sessions: 4,
            confirm_timeout: Duration::from_secs(120),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BrowserSessionPlan {
    pub proxy: proxy::Config,
}

#[derive(Debug, Clone)]
pub struct TerminalSessionPlan {
    pub proxy: proxy::Config,
    pub route: proxy::Route,
    pub shell: Shell,
}

pub trait Profiles: Send + Sync + 'static {
    fn known(&self) -> Result<Known, String>;
    fn link(&self, gateway: &LinkedGateway) -> Result<(), String>;
    fn browser_session(&self, gateway: &GatewayName) -> Result<BrowserSessionPlan, String>;
    fn terminal_session(&self, gateway: &GatewayName) -> Result<TerminalSessionPlan, String>;
}

struct Pending {
    token: ConfirmToken,
    request: LaunchRequest,
    ask: Ask,
    expires: Instant,
}

struct Asked<'a> {
    ask: &'a Ask,
    approved: bool,
}

impl Confirm for Asked<'_> {
    fn decide(&mut self, ask: &Ask) -> Decision {
        self.approved = ask == self.ask;
        if self.approved {
            Decision::Approve
        } else {
            Decision::Deny
        }
    }
}

#[derive(Debug, Clone)]
pub struct AgentOptions {
    pub browser: Option<PathBuf>,
    pub profiles_root: PathBuf,
    pub limits: AgentLimits,
    pub logbook: Logbook,
    pub config: ipc::ConfigSource,
}

#[derive(Debug)]
struct LaunchLimiter {
    limit: usize,
    window: Duration,
    recent: VecDeque<Instant>,
}

impl LaunchLimiter {
    fn new(limit: usize, window: Duration) -> Self {
        Self {
            limit,
            window,
            recent: VecDeque::new(),
        }
    }

    fn allow(&mut self, now: Instant) -> bool {
        while self
            .recent
            .front()
            .is_some_and(|&at| now.saturating_duration_since(at) >= self.window)
        {
            self.recent.pop_front();
        }
        if self.recent.len() >= self.limit {
            return false;
        }
        self.recent.push_back(now);
        true
    }
}

struct Browser {
    name: Option<BrowserKind>,
    close: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

struct Terminal {
    shell: String,
    close: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug)]
struct TerminalSpawn {
    executable: PathBuf,
    args: Vec<OsString>,
    environment: Variables,
    current_dir: Option<PathBuf>,
    title: String,
    new_console: bool,
}

trait Launcher: Send + Sync + 'static {
    fn job(&self) -> Option<Arc<Job>>;
    fn spawn(
        &self,
        executable: &Path,
        args: Vec<OsString>,
        job: Option<&Arc<Job>>,
    ) -> Result<BrowserProcess, SpawnError>;
    fn terminals(&self) -> bool;
    fn terminal_job(&self) -> io::Result<Job>;
    fn environment(&self) -> Variables;
    fn spawn_terminal(
        &self,
        spawn: TerminalSpawn,
        job: &Arc<Job>,
    ) -> Result<BrowserProcess, SpawnError>;
}

struct System;

impl Launcher for System {
    fn job(&self) -> Option<Arc<Job>> {
        browser_job()
    }

    fn spawn(
        &self,
        executable: &Path,
        args: Vec<OsString>,
        job: Option<&Arc<Job>>,
    ) -> Result<BrowserProcess, SpawnError> {
        browser::spawn(executable, args, job)
    }

    fn terminals(&self) -> bool {
        cfg!(windows)
    }

    fn terminal_job(&self) -> io::Result<Job> {
        Job::new()
    }

    fn environment(&self) -> Variables {
        std::env::vars_os().collect()
    }

    #[cfg(windows)]
    fn spawn_terminal(
        &self,
        spawn: TerminalSpawn,
        job: &Arc<Job>,
    ) -> Result<BrowserProcess, SpawnError> {
        let block = terminal::environment_block(&spawn.environment).map_err(|error| {
            SpawnError::Process(io::Error::new(io::ErrorKind::InvalidInput, error))
        })?;
        let options = crate::job::SpawnOptions {
            environment: Some(&block),
            new_console: spawn.new_console,
            current_dir: spawn.current_dir.as_deref(),
            title: Some(&spawn.title),
        };
        job.spawn_with(&spawn.executable, &spawn.args, options)
            .map(BrowserProcess::Job)
    }

    #[cfg(not(windows))]
    fn spawn_terminal(&self, _: TerminalSpawn, _: &Arc<Job>) -> Result<BrowserProcess, SpawnError> {
        Err(SpawnError::Process(io::Error::new(
            io::ErrorKind::Unsupported,
            "terminal sessions from the agent are only available on Windows",
        )))
    }
}

struct Inner {
    profiles: Box<dyn Profiles>,
    launcher: Arc<dyn Launcher>,
    options: AgentOptions,
    sessions: Mutex<SessionManager>,
    browsers: Mutex<BTreeMap<SessionId, Browser>>,
    terminals: Mutex<BTreeMap<SessionId, Terminal>>,
    launches: std::sync::Mutex<LaunchLimiter>,
    launching: Mutex<Option<Pending>>,
    stop: Notify,
}

#[derive(Clone)]
pub struct Agent {
    inner: Arc<Inner>,
}

impl Agent {
    pub fn new(options: AgentOptions, profiles: impl Profiles) -> Self {
        Self::with_launcher(options, profiles, Arc::new(System))
    }

    fn with_launcher(
        options: AgentOptions,
        profiles: impl Profiles,
        launcher: Arc<dyn Launcher>,
    ) -> Self {
        let limiter = LaunchLimiter::new(options.limits.launches, options.limits.launch_window);
        Self {
            inner: Arc::new(Inner {
                profiles: Box::new(profiles),
                launcher,
                options,
                sessions: Mutex::new(SessionManager::new()),
                browsers: Mutex::new(BTreeMap::new()),
                terminals: Mutex::new(BTreeMap::new()),
                launches: std::sync::Mutex::new(limiter),
                launching: Mutex::new(None),
                stop: Notify::new(),
            }),
        }
    }

    pub async fn serve(&self, mut server: Server, shutdown: impl Future<Output = ()>) {
        let removed = browser::sweep(&self.inner.options.profiles_root);
        if removed > 0 {
            info!("removed {removed} browser profiles left behind by an earlier agent");
        }
        let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let mut tasks = JoinSet::new();
        tokio::pin!(shutdown);
        let mut backoff = AcceptBackoff::default();
        loop {
            let retry_at = backoff.retry_at();
            let accept = async {
                if let Some(at) = retry_at {
                    tokio::time::sleep_until(at).await;
                }
                server.accept().await
            };
            tokio::select! {
                () = &mut shutdown => break,
                () = self.inner.stop.notified() => break,
                accepted = accept => match accepted {
                    Ok(connection) => {
                        backoff.succeeded();
                        match connections.clone().try_acquire_owned() {
                            Ok(permit) => {
                                let agent = self.clone();
                                tasks.spawn(async move {
                                    agent.respond(connection).await;
                                    drop(permit);
                                });
                            }
                            Err(_) => warn!("too many agent requests at once; dropping one"),
                        }
                    }
                    Err(error) => {
                        backoff.failed(tokio::time::Instant::now());
                        warn!("accepting an agent request failed: {error}");
                    }
                },
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
        drop(server);
        let drained = tokio::time::timeout(DRAIN_TIMEOUT, async {
            while tasks.join_next().await.is_some() {}
        })
        .await;
        if drained.is_err() {
            tasks.abort_all();
        }
        self.close_all().await;
    }

    async fn respond(&self, mut connection: Connection) {
        let request = tokio::time::timeout(REQUEST_TIMEOUT, ipc::read_request(&mut connection));
        let (response, rejected) = match request.await {
            Ok(Ok(request)) => (self.handle(request).await, false),
            Ok(Err(error)) => {
                warn!("rejected an agent request: {error}");
                (Response::Error(error.to_string()), true)
            }
            Err(_) => return,
        };
        let _ = ipc::write_response(&mut connection, &response).await;
        if rejected {
            // Closing with unread input resets the connection and discards the answer.
            let drain = ipc::read_to_close(&mut connection, DRAIN_REJECTED_BYTES);
            let _ = tokio::time::timeout(DRAIN_REJECTED_TIMEOUT, drain).await;
        }
    }

    pub async fn handle(&self, request: Request) -> Response {
        let result = match request {
            Request::Launch(request) => self.launch(request).await,
            Request::Terminal(request) => self.terminal(request).await,
            Request::Approve(token) => self.approve(token).await,
            Request::Deny(token) => self.deny(token).await.map(|()| Vec::new()),
            Request::List => Ok(self.list().await),
            Request::Close(id) => self.close(id).await.map(|()| Vec::new()),
            Request::Credentials(id) => self.credentials(id).await,
            Request::Stop => {
                self.inner.stop.notify_one();
                let terminals = self.close_all().await;
                Ok(vec![
                    ipc::agent_pid_line(),
                    ipc::closed_terminals_line(terminals),
                ])
            }
            Request::Log { after } => return self.inner.options.logbook.response(after),
            Request::Config => ipc::config_line(&self.inner.options.config)
                .map(|line| vec![line])
                .ok_or_else(|| "the config path cannot be sent over IPC".to_owned()),
        };
        match result {
            Ok(lines) => Response::Ok(lines),
            Err(error) => Response::Error(error),
        }
    }

    async fn launch(&self, request: LaunchRequest) -> Result<Vec<String>, String> {
        let mut pending = self.inner.launching.lock().await;
        let limits = &self.inner.options.limits;
        if let Err(error) = self.allow_launch() {
            warn!(gateway = ?request.profile, "refused a browser launch: rate limit reached");
            return Err(error);
        }
        self.check_capacity().await?;
        let known = self.inner.profiles.known()?;
        let resolution = link::resolve(&request, &known, &mut Decision::Defer, unix_now())
            .map_err(|error| error.to_string())?;
        let ask = match resolution {
            Resolution::Launch(launch) => {
                return self.start(launch).await.map(|lines| warned(lines, &known));
            }
            Resolution::Confirm(ask) => ask,
        };
        let now = Instant::now();
        if pending
            .as_ref()
            .is_some_and(|pending| pending.expires > now)
        {
            warn!(gateway = ?request.profile, "refused a new gateway: another confirmation is open");
            return Err(
                "another gateway confirmation is already waiting for an answer; answer it first"
                    .to_owned(),
            );
        }
        let token = ConfirmToken::random().map_err(|error| error.to_string())?;
        match &ask {
            Ask::Add(confirmation) => info!(
                gateway = %confirmation.profile,
                address = %confirmation.gateway,
                "a link asks to add a gateway; waiting for the user's confirmation"
            ),
            Ask::Loosen(loosening) => info!(
                gateway = %loosening.profile,
                "a link asks for the mixed route on a gateway saved with the gateway route; \
                 waiting for the user's confirmation"
            ),
        }
        let mut lines = vec![ipc::confirm_line(&token)];
        lines.extend(ask.echo());
        *pending = Some(Pending {
            token,
            request,
            ask,
            expires: now + limits.confirm_timeout,
        });
        Ok(warned(lines, &known))
    }

    fn allow_launch(&self) -> Result<(), String> {
        let allowed = self
            .inner
            .launches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .allow(Instant::now());
        if allowed {
            return Ok(());
        }
        let limits = &self.inner.options.limits;
        Err(format!(
            "too many launch requests; at most {} are accepted every {} seconds",
            limits.launches,
            limits.launch_window.as_secs()
        ))
    }

    async fn terminal(&self, request: TerminalRequest) -> Result<Vec<String>, String> {
        let _launching = self.inner.launching.lock().await;
        let gateway = request.gateway;
        if let Err(error) = self.allow_launch() {
            warn!(%gateway, "refused a terminal: rate limit reached");
            return Err(error);
        }
        let launcher = self.inner.launcher.clone();
        if !launcher.terminals() {
            return Err(
                "terminal sessions from the agent are not supported on this platform".to_owned(),
            );
        }
        let limit = self.inner.options.limits.max_terminal_sessions;
        // Held until the terminal is registered, so that a close or stop arriving while the
        // shell starts waits for it instead of missing it.
        let mut terminals = self.inner.terminals.lock().await;
        if terminals.len() >= limit {
            return Err(format!(
                "{limit} terminal sessions are already open; close one first"
            ));
        }
        let known = self.inner.profiles.known()?;
        let plan = self.inner.profiles.terminal_session(&gateway)?;
        let route = terminal::terminal_route(request.route, plan.route);
        let job =
            terminal::terminal_job(launcher.terminal_job()).map_err(|error| error.to_string())?;
        let mut proxy = terminal::terminal_proxy(plan.proxy, route, job.clone());
        proxy.listen = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let (id, listen) = {
            let mut sessions = self.inner.sessions.lock().await;
            let id = sessions
                .start(SessionConfig {
                    kind: SessionKind::Terminal,
                    gateway: gateway.clone(),
                    proxy,
                })
                .await
                .map_err(|error| error.to_string())?;
            let listen = sessions
                .session(id)
                .expect("the session just started")
                .local_addr();
            (id, listen)
        };
        let span = info_span!("session", %id, kind = %SessionKind::Terminal, gateway = %gateway);
        let inherited = launcher.environment();
        let current_dir = home_dir(&inherited);
        let (environment, _) =
            terminal::terminal_environment(terminal::without_hidden_entries(inherited), listen);
        let Shell { executable, args } = plan.shell;
        let spawn = TerminalSpawn {
            executable: executable.clone(),
            args,
            environment,
            current_dir,
            title: format!("Gateinto: {gateway}"),
            new_console: true,
        };
        let spawned = tokio::task::spawn_blocking({
            let job = job.clone();
            move || launcher.spawn_terminal(spawn, &job)
        })
        .await
        .map_err(|error| SpawnError::Process(io::Error::other(error)))
        .and_then(|spawned| spawned);
        let child = match spawned {
            Ok(child) => child,
            Err(error) => {
                self.inner.sessions.lock().await.close(id).await;
                let message = format!("starting {} failed: {error}", executable.display());
                span.in_scope(|| warn!("{message}"));
                return Err(message);
            }
        };
        span.in_scope(|| info!(shell = %executable.display(), "started a shell for the session"));
        let shell = executable
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut lines = vec![
            format!("session: {id}"),
            format!("gateway: {gateway}"),
            format!("listen: {listen}"),
            format!("route: {route}"),
            "auth: os_user".to_owned(),
            format!("shell: {shell}"),
        ];
        lines = warned(lines, &known);
        lines.extend(terminal::route_warning(route).map(str::to_owned));
        let (close, closed) = oneshot::channel();
        let task =
            tokio::spawn(watch_terminal(self.inner.clone(), id, child, closed).instrument(span));
        terminals.insert(id, Terminal { shell, close, task });
        Ok(lines)
    }

    fn answered(pending: &mut Option<Pending>, token: ConfirmToken) -> Result<Pending, String> {
        let waiting = pending
            .as_ref()
            .is_some_and(|pending| pending.token == token && pending.expires > Instant::now());
        if !waiting {
            return Err(
                "no gateway confirmation is waiting for this answer; open the link again"
                    .to_owned(),
            );
        }
        Ok(pending.take().expect("checked above"))
    }

    async fn approve(&self, token: ConfirmToken) -> Result<Vec<String>, String> {
        let mut pending = self.inner.launching.lock().await;
        let answered = Self::answered(&mut pending, token)?;
        let known = self.inner.profiles.known()?;
        let mut asked = Asked {
            ask: &answered.ask,
            approved: false,
        };
        let resolution = link::resolve(&answered.request, &known, &mut asked, unix_now());
        if !asked.approved {
            warn!(
                gateway = %answered.ask.profile(),
                "refused an approval: the link asks for something else than when it was confirmed"
            );
            return Err(
                "the gateways changed while the confirmation was open; nothing was done, open \
                 the link again"
                    .to_owned(),
            );
        }
        let resolution = resolution.map_err(|error| error.to_string())?;
        let Resolution::Launch(launch) = resolution else {
            return Err("the gateway could not be approved".to_owned());
        };
        if let Some(gateway) = &launch.add {
            self.inner.profiles.link(gateway)?;
            info!(
                gateway = %gateway.name,
                address = %gateway.address,
                "the user approved a gateway from a link; stored it"
            );
        }
        if let Err(error) = self.check_capacity().await {
            return Err(match &launch.add {
                Some(gateway) => format!(
                    "the gateway \"{}\" was added, but {error}, then open the link again",
                    gateway.name
                ),
                None => error,
            });
        }
        self.start(launch).await.map(|lines| warned(lines, &known))
    }

    async fn deny(&self, token: ConfirmToken) -> Result<(), String> {
        let mut pending = self.inner.launching.lock().await;
        let answered = Self::answered(&mut pending, token)?;
        match &answered.ask {
            Ask::Add(_) => {
                info!(gateway = ?answered.request.profile, "the user did not allow a gateway from a link");
            }
            Ask::Loosen(loosening) => {
                info!(gateway = %loosening.profile, "the user did not allow a link to use the mixed route");
            }
        }
        Ok(())
    }

    async fn check_capacity(&self) -> Result<(), String> {
        let limit = self.inner.options.limits.max_browser_sessions;
        if self.inner.browsers.lock().await.len() >= limit {
            return Err(format!(
                "{limit} browser sessions are already open; close one first"
            ));
        }
        Ok(())
    }

    async fn start(&self, launch: Launch) -> Result<Vec<String>, String> {
        let profile = launch.profile;
        let plan = self.inner.profiles.browser_session(&profile)?;
        let executable = browser::find_browser(self.inner.options.browser.as_deref())
            .map_err(|e| e.to_string())?;
        let mut proxy = plan.proxy;
        proxy.listen = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        proxy.route = launch.route;
        let mut job = self.inner.launcher.job();
        let mut sessions = self.inner.sessions.lock().await;
        let (id, listen, realm, credentials, span, dir, child) = loop {
            let local_auth = browser_local_auth(job.is_some());
            let id = sessions
                .start(SessionConfig {
                    kind: SessionKind::Browser,
                    gateway: profile.clone(),
                    proxy: proxy::Config {
                        local_auth,
                        os_user_job: job.clone(),
                        ..proxy.clone()
                    },
                })
                .await
                .map_err(|error| error.to_string())?;
            let session = sessions.session(id).expect("the session just started");
            let (listen, realm, credentials) = (
                session.local_addr(),
                session.realm().unwrap_or_default().to_owned(),
                launch_credentials(local_auth, session.credentials().map(ipc::credential_lines)),
            );
            let span = info_span!("session", %id, kind = %SessionKind::Browser, gateway = %profile);
            let started = match ProfileDir::create(&self.inner.options.profiles_root, id) {
                Ok(dir) => {
                    let args =
                        browser::browser_args(dir.path(), listen, launch.start_page.as_ref());
                    match self.spawn_browser(&executable, args, job.clone()).await {
                        Ok(child) => Ok((dir, child)),
                        Err(error) => {
                            let _ = dir.remove();
                            Err(error)
                        }
                    }
                }
                Err(error) => Err(SpawnError::Process(error)),
            };
            match started {
                Ok((dir, child)) => break (id, listen, realm, credentials, span, dir, child),
                Err(SpawnError::Job(error)) if job.is_some() => {
                    sessions.close(id).await;
                    span.in_scope(|| {
                        warn!(
                            "putting the browser in a job object failed: {error}; starting it \
                             without one, so its session accepts only session credentials"
                        )
                    });
                    job = None;
                }
                Err(error) => {
                    sessions.close(id).await;
                    let message = format!("starting {} failed: {error}", executable.display());
                    span.in_scope(|| warn!("{message}"));
                    return Err(message);
                }
            }
        };
        drop(sessions);
        span.in_scope(|| {
            info!(
                browser = %executable.display(),
                profile = %dir.path().display(),
                "started a browser for the session"
            )
        });
        let mut lines = vec![
            format!("session: {id}"),
            format!("gateway: {profile}"),
            format!("listen: {listen}"),
            format!("realm: {realm}"),
            format!("profile: {}", dir.path().display()),
            format!("browser: {}", executable.display()),
        ];
        lines.extend(credentials);
        if launch.route != proxy::Route::Gateway {
            lines.push(format!("route: {}", launch.route));
        }
        let (close, closed) = oneshot::channel();
        let mut browsers = self.inner.browsers.lock().await;
        let task = tokio::spawn(watch(self.inner.clone(), id, child, dir, closed).instrument(span));
        let name = browser::browser_name(&executable);
        browsers.insert(id, Browser { name, close, task });
        Ok(lines)
    }

    async fn spawn_browser(
        &self,
        executable: &Path,
        args: Vec<OsString>,
        job: Option<Arc<Job>>,
    ) -> Result<BrowserProcess, SpawnError> {
        let launcher = self.inner.launcher.clone();
        let executable = executable.to_owned();
        tokio::task::spawn_blocking(move || launcher.spawn(&executable, args, job.as_ref()))
            .await
            .map_err(|error| SpawnError::Process(std::io::Error::other(error)))?
    }

    async fn list(&self) -> Vec<String> {
        let names: BTreeMap<SessionId, BrowserKind> = self
            .inner
            .browsers
            .lock()
            .await
            .iter()
            .filter_map(|(&id, browser)| Some((id, browser.name?)))
            .collect();
        let shells: BTreeMap<SessionId, String> = self
            .inner
            .terminals
            .lock()
            .await
            .iter()
            .map(|(&id, terminal)| (id, terminal.shell.clone()))
            .collect();
        self.inner
            .sessions
            .lock()
            .await
            .sessions()
            .map(|session| {
                let mut info = session.info(names.get(&session.id()).copied());
                info.shell = shells.get(&session.id()).cloned();
                info.to_line()
            })
            .collect()
    }

    async fn credentials(&self, id: SessionId) -> Result<Vec<String>, String> {
        let sessions = self.inner.sessions.lock().await;
        let session = sessions
            .session(id)
            .ok_or_else(|| format!("no session {id}"))?;
        let credentials = session
            .credentials()
            .ok_or_else(|| format!("session {id} has no credentials"))?;
        let mut lines = vec![format!("listen: {}", session.local_addr())];
        lines.extend(ipc::credential_lines(credentials));
        Ok(lines)
    }

    async fn close(&self, id: SessionId) -> Result<(), String> {
        let browser = self.inner.browsers.lock().await.remove(&id);
        if let Some(browser) = browser {
            let _ = browser.close.send(());
            let _ = browser.task.await;
            return Ok(());
        }
        let terminal = self.inner.terminals.lock().await.remove(&id);
        if let Some(terminal) = terminal {
            let _ = terminal.close.send(());
            let _ = terminal.task.await;
            return Ok(());
        }
        if self.inner.sessions.lock().await.close(id).await {
            Ok(())
        } else {
            Err(format!("no session {id}"))
        }
    }

    pub async fn close_all(&self) -> usize {
        let browsers = std::mem::take(&mut *self.inner.browsers.lock().await);
        for (_, browser) in browsers {
            let _ = browser.close.send(());
            let _ = browser.task.await;
        }
        let terminals = std::mem::take(&mut *self.inner.terminals.lock().await);
        let count = terminals.len();
        for (_, terminal) in terminals {
            let _ = terminal.close.send(());
            let _ = terminal.task.await;
        }
        self.inner.sessions.lock().await.close_all().await;
        count
    }
}

fn warned(mut lines: Vec<String>, known: &Known) -> Vec<String> {
    for line in known.error_lines() {
        warn!("{line}");
        lines.push(line);
    }
    lines
}

async fn watch(
    inner: Arc<Inner>,
    id: SessionId,
    mut child: BrowserProcess,
    profile: ProfileDir,
    closed: oneshot::Receiver<()>,
) {
    tokio::select! {
        status = child.wait() => match status {
            Ok(status) => {
                info!("the browser exited with {status}; closing the session");
                if let Err(error) = child.release().await {
                    warn!("stopping the processes the browser left failed: {error}");
                }
            }
            Err(error) => {
                warn!("waiting for the browser failed: {error}; closing the session");
                if let Err(error) = child.release().await {
                    warn!("stopping the processes the browser left failed: {error}");
                }
            }
        },
        _ = closed => {
            if let Err(error) = child.kill().await {
                warn!("stopping the browser failed: {error}");
            }
            info!("stopped the browser; closing the session");
        }
    }
    drop(child);
    inner.sessions.lock().await.close(id).await;
    remove_profile(&profile).await;
    inner.browsers.lock().await.remove(&id);
}

async fn watch_terminal(
    inner: Arc<Inner>,
    id: SessionId,
    mut child: BrowserProcess,
    closed: oneshot::Receiver<()>,
) {
    tokio::select! {
        status = child.wait() => {
            match status {
                Ok(status) => info!(
                    "the shell exited with code {}; closing the session",
                    terminal::exit_code(status)
                ),
                Err(error) => warn!("waiting for the shell failed: {error}; closing the session"),
            }
            if let Err(error) = child.release().await {
                warn!("stopping the processes the shell left failed: {error}");
            }
        }
        _ = closed => {
            if let Err(error) = child.kill().await {
                warn!("stopping the shell failed: {error}");
            }
            info!("stopped the shell; closing the session");
        }
    }
    drop(child);
    inner.sessions.lock().await.close(id).await;
    inner.terminals.lock().await.remove(&id);
}

fn home_dir(environment: &Variables) -> Option<PathBuf> {
    environment
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("USERPROFILE"))
        .map(|(_, value)| PathBuf::from(value))
        .filter(|path| path.is_absolute())
}

async fn remove_profile(profile: &ProfileDir) {
    for attempt in 1..=PROFILE_REMOVAL_ATTEMPTS {
        match profile.remove() {
            Ok(()) => return,
            Err(error) if attempt == PROFILE_REMOVAL_ATTEMPTS => warn!(
                "removing the browser profile {} failed: {error}; the next agent start retries",
                profile.path().display()
            ),
            Err(_) => tokio::time::sleep(PROFILE_REMOVAL_DELAY).await,
        }
    }
}

fn browser_job() -> Option<Arc<Job>> {
    if !cfg!(windows) {
        return None;
    }
    match Job::new() {
        Ok(job) => Some(Arc::new(job)),
        Err(error) => {
            warn!(
                "creating a job object for the browser failed: {error}; its session accepts only \
                 session credentials"
            );
            None
        }
    }
}

fn browser_local_auth(in_job: bool) -> LocalAuth {
    LocalAuth {
        os_user: cfg!(windows) && in_job,
        session_credentials: true,
    }
}

fn launch_credentials(local_auth: LocalAuth, lines: Option<[String; 2]>) -> Vec<String> {
    match lines {
        Some(lines) if !local_auth.os_user => lines.to_vec(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_sessions_offer_the_os_user_on_windows_with_session_credentials_as_a_fallback() {
        let expected = LocalAuth {
            os_user: cfg!(windows),
            session_credentials: true,
        };
        assert_eq!(browser_local_auth(true), expected);
    }

    #[test]
    fn a_browser_outside_a_job_gets_only_session_credentials_and_sees_them() {
        assert_eq!(browser_local_auth(false), LocalAuth::SESSION_CREDENTIALS);
        let credentials = ["username: u".to_owned(), "password: p".to_owned()];
        assert_eq!(
            launch_credentials(browser_local_auth(false), Some(credentials.clone())),
            credentials.to_vec()
        );
    }

    #[test]
    fn launch_lines_carry_the_credentials_only_when_they_are_the_only_method() {
        let credentials = ["username: u".to_owned(), "password: p".to_owned()];
        assert_eq!(
            launch_credentials(LocalAuth::SESSION_CREDENTIALS, Some(credentials.clone())),
            credentials.to_vec()
        );
        let both = LocalAuth {
            os_user: true,
            session_credentials: true,
        };
        assert!(launch_credentials(both, Some(credentials)).is_empty());
        assert!(launch_credentials(LocalAuth::OS_USER, None).is_empty());
    }

    #[test]
    fn the_limiter_allows_a_burst_up_to_the_limit_per_window() {
        let mut limiter = LaunchLimiter::new(3, Duration::from_secs(60));
        let start = Instant::now();
        for _ in 0..3 {
            assert!(limiter.allow(start));
        }
        assert!(!limiter.allow(start));
        assert!(!limiter.allow(start + Duration::from_secs(59)));
        assert!(limiter.allow(start + Duration::from_secs(60)));
        assert!(limiter.allow(start + Duration::from_secs(60)));
        assert!(limiter.allow(start + Duration::from_secs(61)));
        assert!(!limiter.allow(start + Duration::from_secs(61)));
    }

    #[test]
    fn refused_requests_do_not_extend_the_window() {
        let mut limiter = LaunchLimiter::new(1, Duration::from_secs(10));
        let start = Instant::now();
        assert!(limiter.allow(start));
        for second in 1..10 {
            assert!(!limiter.allow(start + Duration::from_secs(second)));
        }
        assert!(limiter.allow(start + Duration::from_secs(10)));
    }

    #[test]
    fn repeated_accept_failures_back_off_up_to_a_limit() {
        assert_eq!(accept_retry_delay(0), Duration::ZERO);
        assert_eq!(accept_retry_delay(1), Duration::from_millis(100));
        assert_eq!(accept_retry_delay(2), Duration::from_millis(200));
        assert_eq!(accept_retry_delay(6), Duration::from_millis(3200));
        assert_eq!(accept_retry_delay(7), Duration::from_secs(5));
        assert_eq!(accept_retry_delay(u32::MAX), Duration::from_secs(5));
    }

    #[test]
    fn an_accept_retry_waits_until_a_fixed_time_after_the_last_failure() {
        let start = tokio::time::Instant::now();
        let mut backoff = AcceptBackoff::default();
        assert_eq!(backoff.retry_at(), None);

        backoff.failed(start);
        assert_eq!(backoff.retry_at(), Some(start + Duration::from_millis(100)));
        assert_eq!(backoff.retry_at(), Some(start + Duration::from_millis(100)));

        let later = start + Duration::from_secs(1);
        backoff.failed(later);
        assert_eq!(backoff.retry_at(), Some(later + Duration::from_millis(200)));

        backoff.succeeded();
        assert_eq!(backoff.retry_at(), None);
        backoff.failed(later);
        assert_eq!(backoff.retry_at(), Some(later + Duration::from_millis(100)));
    }

    #[test]
    fn a_zero_limit_refuses_everything() {
        let mut limiter = LaunchLimiter::new(0, Duration::from_secs(10));
        assert!(!limiter.allow(Instant::now()));
    }

    #[cfg(unix)]
    mod no_job_retry {
        use std::io;

        use rustls::RootCertStore;
        use rustls::pki_types::ServerName;

        use super::*;
        use crate::sessions::Session;

        struct Plan(proxy::Config);

        impl Profiles for Plan {
            fn known(&self) -> Result<Known, String> {
                Ok(Known::default())
            }

            fn link(&self, _: &LinkedGateway) -> Result<(), String> {
                Err("not used".to_owned())
            }

            fn browser_session(&self, _: &GatewayName) -> Result<BrowserSessionPlan, String> {
                Ok(BrowserSessionPlan {
                    proxy: self.0.clone(),
                })
            }

            fn terminal_session(&self, _: &GatewayName) -> Result<TerminalSessionPlan, String> {
                Err("not used".to_owned())
            }
        }

        #[derive(Default)]
        struct JobFailsOnce {
            jobs: std::sync::Mutex<Vec<bool>>,
        }

        impl Launcher for JobFailsOnce {
            fn job(&self) -> Option<Arc<Job>> {
                Some(Arc::new(Job::fake()))
            }

            fn spawn(
                &self,
                executable: &Path,
                _: Vec<OsString>,
                job: Option<&Arc<Job>>,
            ) -> Result<BrowserProcess, SpawnError> {
                let mut jobs = self.jobs.lock().unwrap();
                jobs.push(job.is_some());
                if jobs.len() == 1 {
                    return Err(SpawnError::Job(io::Error::other("assigning refused")));
                }
                browser::spawn(executable, vec!["30".into()], None)
            }

            fn terminals(&self) -> bool {
                false
            }

            fn terminal_job(&self) -> io::Result<Job> {
                Err(io::Error::other("not used"))
            }

            fn environment(&self) -> Variables {
                Variables::new()
            }

            fn spawn_terminal(
                &self,
                _: TerminalSpawn,
                _: &Arc<Job>,
            ) -> Result<BrowserProcess, SpawnError> {
                Err(SpawnError::Process(io::Error::other("not used")))
            }
        }

        pub(super) fn proxy_config() -> proxy::Config {
            proxy::Config {
                listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                local_auth: LocalAuth::SESSION_CREDENTIALS,
                route: proxy::Route::Gateway,
                upstream: proxy::Upstream {
                    host: "127.0.0.1".to_owned(),
                    port: 9,
                    server_name: ServerName::try_from("upstream.test").unwrap(),
                    roots: RootCertStore::empty(),
                },
                tls_mode: crate::tls::TlsMode::default(),
                client_certificate: None,
                limits: proxy::Limits::default(),
                os_user_job: None,
            }
        }

        #[tokio::test]
        async fn a_refused_job_closes_the_session_and_retries_with_session_credentials_only() {
            let root = std::env::temp_dir().join(format!("gateinto-no-job-{}", std::process::id()));
            let launcher = Arc::new(JobFailsOnce::default());
            let agent = Agent::with_launcher(
                AgentOptions {
                    browser: Some(PathBuf::from("/bin/sleep")),
                    profiles_root: root.clone(),
                    limits: AgentLimits::default(),
                    logbook: Default::default(),
                    config: ipc::ConfigSource::Defaults,
                },
                Plan(proxy_config()),
                launcher.clone(),
            );
            let logs = crate::test_logs::capture();

            let lines = agent
                .start(Launch {
                    route: proxy::Route::Gateway,
                    profile: "work".parse().unwrap(),
                    start_page: None,
                    add: None,
                })
                .await
                .unwrap();
            let warnings = logs.lines(" WARN ");
            drop(logs);

            assert_eq!(*launcher.jobs.lock().unwrap(), [true, false]);
            assert_eq!(warnings.len(), 1, "{warnings:?}");
            assert!(warnings[0].contains("putting the browser in a job object failed"));
            {
                let sessions = agent.inner.sessions.lock().await;
                let ids: Vec<_> = sessions.sessions().map(Session::id).collect();
                assert_eq!(ids.len(), 1);
                let session = sessions.session(ids[0]).unwrap();
                assert_eq!(session.local_auth(), LocalAuth::SESSION_CREDENTIALS);
                let credentials = ipc::credential_lines(session.credentials().unwrap());
                assert_eq!(lines[0], format!("session: {}", ids[0]));
                for line in credentials {
                    assert!(lines.contains(&line), "{lines:?}");
                }
            }
            agent.close_all().await;
            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[cfg(unix)]
    mod terminal_sessions {
        use std::io;

        use super::*;
        use crate::ipc::SessionInfo;
        use crate::sessions::Session;
        use crate::terminal::{Shell, Variables};

        #[derive(Default)]
        struct Gateways {
            calls: std::sync::Mutex<usize>,
        }

        impl Profiles for Gateways {
            fn known(&self) -> Result<Known, String> {
                *self.calls.lock().unwrap() += 1;
                Ok(Known::default())
            }

            fn link(&self, _: &LinkedGateway) -> Result<(), String> {
                Err("not used".to_owned())
            }

            fn browser_session(&self, _: &GatewayName) -> Result<BrowserSessionPlan, String> {
                *self.calls.lock().unwrap() += 1;
                Ok(BrowserSessionPlan {
                    proxy: super::no_job_retry::proxy_config(),
                })
            }

            fn terminal_session(
                &self,
                gateway: &GatewayName,
            ) -> Result<TerminalSessionPlan, String> {
                *self.calls.lock().unwrap() += 1;
                if gateway.as_str() != "office" {
                    return Err(format!("unknown gateway \"{gateway}\""));
                }
                Ok(TerminalSessionPlan {
                    proxy: super::no_job_retry::proxy_config(),
                    route: proxy::Route::Gateway,
                    shell: Shell {
                        executable: PathBuf::from("/opt/shells/pwsh"),
                        args: vec!["-NoLogo".into()],
                    },
                })
            }
        }

        #[derive(Clone, Copy, PartialEq)]
        enum Spawn {
            Runs,
            Exits,
            JobRefused,
            Fails,
        }

        struct Terminals {
            supported: bool,
            job: bool,
            spawn: Spawn,
            spawned: std::sync::Mutex<Vec<TerminalSpawn>>,
            gate: std::sync::Mutex<Option<Gate>>,
        }

        struct Gate {
            started: std::sync::mpsc::Sender<()>,
            release: std::sync::mpsc::Receiver<()>,
        }

        struct Opener {
            started: std::sync::mpsc::Receiver<()>,
            release: std::sync::mpsc::Sender<()>,
        }

        impl Opener {
            async fn wait_started(self) -> std::sync::mpsc::Sender<()> {
                let Opener { started, release } = self;
                tokio::task::spawn_blocking(move || started.recv().unwrap())
                    .await
                    .unwrap();
                release
            }
        }

        fn gated() -> (Terminals, Opener) {
            let (started, started_rx) = std::sync::mpsc::channel();
            let (release_tx, release) = std::sync::mpsc::channel();
            let launcher = Terminals {
                gate: std::sync::Mutex::new(Some(Gate { started, release })),
                ..Terminals::default()
            };
            (
                launcher,
                Opener {
                    started: started_rx,
                    release: release_tx,
                },
            )
        }

        impl Default for Terminals {
            fn default() -> Self {
                Self {
                    supported: true,
                    job: true,
                    spawn: Spawn::Runs,
                    spawned: std::sync::Mutex::new(Vec::new()),
                    gate: std::sync::Mutex::new(None),
                }
            }
        }

        fn pairs(entries: &[(&str, &str)]) -> Variables {
            entries
                .iter()
                .map(|(name, value)| ((*name).into(), (*value).into()))
                .collect()
        }

        impl Launcher for Terminals {
            fn job(&self) -> Option<Arc<Job>> {
                None
            }

            fn spawn(
                &self,
                _: &Path,
                _: Vec<OsString>,
                _: Option<&Arc<Job>>,
            ) -> Result<BrowserProcess, SpawnError> {
                browser::spawn(Path::new("/bin/sleep"), vec!["30".into()], None)
            }

            fn terminals(&self) -> bool {
                self.supported
            }

            fn terminal_job(&self) -> io::Result<Job> {
                if self.job {
                    Ok(Job::fake())
                } else {
                    Err(io::Error::other("refused"))
                }
            }

            fn environment(&self) -> Variables {
                pairs(&[
                    ("=C:", r"C:\work"),
                    ("USERPROFILE", "/home/ana"),
                    ("https_proxy", "http://old.example:8080"),
                    ("Path", r"C:\Windows"),
                ])
            }

            fn spawn_terminal(
                &self,
                spawn: TerminalSpawn,
                _: &Arc<Job>,
            ) -> Result<BrowserProcess, SpawnError> {
                self.spawned.lock().unwrap().push(spawn);
                let gate = self.gate.lock().unwrap().take();
                if let Some(gate) = gate {
                    gate.started.send(()).unwrap();
                    gate.release.recv().unwrap();
                }
                match self.spawn {
                    Spawn::Runs => browser::spawn(Path::new("/bin/sleep"), vec!["30".into()], None),
                    Spawn::Exits => browser::spawn(Path::new("/bin/true"), Vec::new(), None),
                    Spawn::JobRefused => {
                        Err(SpawnError::Job(io::Error::other("assigning refused")))
                    }
                    Spawn::Fails => Err(SpawnError::Process(io::Error::other("not found"))),
                }
            }
        }

        fn agent_with(
            launcher: Terminals,
            limits: AgentLimits,
        ) -> (Agent, Arc<Terminals>, Arc<Gateways>) {
            let launcher = Arc::new(launcher);
            let gateways = Arc::new(Gateways::default());
            let agent = Agent::with_launcher(
                AgentOptions {
                    browser: Some(PathBuf::from("/bin/sleep")),
                    profiles_root: std::env::temp_dir()
                        .join(format!("gateinto-terminal-agent-{}", std::process::id())),
                    limits,
                    logbook: Default::default(),
                    config: ipc::ConfigSource::Defaults,
                },
                SharedGateways(gateways.clone()),
                launcher.clone(),
            );
            (agent, launcher, gateways)
        }

        struct SharedGateways(Arc<Gateways>);

        impl Profiles for SharedGateways {
            fn known(&self) -> Result<Known, String> {
                self.0.known()
            }

            fn link(&self, gateway: &LinkedGateway) -> Result<(), String> {
                self.0.link(gateway)
            }

            fn browser_session(&self, gateway: &GatewayName) -> Result<BrowserSessionPlan, String> {
                self.0.browser_session(gateway)
            }

            fn terminal_session(
                &self,
                gateway: &GatewayName,
            ) -> Result<TerminalSessionPlan, String> {
                self.0.terminal_session(gateway)
            }
        }

        fn agent(launcher: Terminals) -> (Agent, Arc<Terminals>, Arc<Gateways>) {
            agent_with(launcher, AgentLimits::default())
        }

        fn request(gateway: &str, route: Option<proxy::Route>) -> Request {
            Request::Terminal(TerminalRequest {
                gateway: gateway.parse().unwrap(),
                route,
            })
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
                .map(Session::id)
                .collect()
        }

        #[test]
        fn the_system_launcher_offers_terminals_only_on_windows() {
            assert_eq!(System.terminals(), cfg!(windows));
        }

        #[tokio::test]
        async fn an_unsupported_platform_is_refused_after_the_rate_limit_and_before_any_gateway() {
            let limits = AgentLimits {
                launches: 1,
                ..AgentLimits::default()
            };
            let launcher = Terminals {
                supported: false,
                ..Terminals::default()
            };
            let (agent, launcher, gateways) = agent_with(launcher, limits);

            let error = answer(&agent, request("office", None)).await.unwrap_err();
            assert_eq!(
                error,
                "terminal sessions from the agent are not supported on this platform"
            );
            assert_eq!(*gateways.calls.lock().unwrap(), 0);
            assert!(launcher.spawned.lock().unwrap().is_empty());
            let error = answer(&agent, request("office", None)).await.unwrap_err();
            assert!(error.starts_with("too many launch requests"), "{error}");
        }

        #[tokio::test]
        async fn a_terminal_request_starts_an_os_user_session_and_a_shell_in_a_new_console() {
            let (agent, launcher, _) = agent(Terminals::default());

            let lines = answer(&agent, request("office", None)).await.unwrap();

            let ids = session_ids(&agent).await;
            assert_eq!(ids.len(), 1);
            let (listen, auth, kind, credentials) = {
                let sessions = agent.inner.sessions.lock().await;
                let session = sessions.session(ids[0]).unwrap();
                (
                    session.local_addr(),
                    session.local_auth(),
                    session.kind(),
                    session.credentials().is_some(),
                )
            };
            assert_eq!(kind, SessionKind::Terminal);
            assert_eq!(auth, LocalAuth::OS_USER);
            assert!(!credentials);
            assert_eq!(
                lines,
                [
                    format!("session: {}", ids[0]),
                    "gateway: office".to_owned(),
                    format!("listen: {listen}"),
                    "route: gateway".to_owned(),
                    "auth: os_user".to_owned(),
                    "shell: pwsh".to_owned(),
                ]
            );
            let spawned = std::mem::take(&mut *launcher.spawned.lock().unwrap());
            assert_eq!(spawned.len(), 1);
            let spawn = &spawned[0];
            assert_eq!(spawn.executable, Path::new("/opt/shells/pwsh"));
            assert_eq!(spawn.args, [OsString::from("-NoLogo")]);
            assert!(spawn.new_console);
            assert_eq!(spawn.current_dir.as_deref(), Some(Path::new("/home/ana")));
            assert_eq!(spawn.title, "Gateinto: office");
            let url = format!("http://{listen}");
            assert_eq!(
                spawn.environment,
                pairs(&[
                    ("USERPROFILE", "/home/ana"),
                    ("Path", r"C:\Windows"),
                    ("HTTPS_PROXY", &url),
                    ("https_proxy", &url),
                    ("HTTP_PROXY", &url),
                    ("http_proxy", &url),
                    ("ALL_PROXY", &url),
                    ("all_proxy", &url),
                    ("NO_PROXY", crate::terminal::NO_PROXY_HOSTS),
                    ("no_proxy", crate::terminal::NO_PROXY_HOSTS),
                ])
            );
            agent.close_all().await;
        }

        #[tokio::test]
        async fn a_requested_mixed_route_is_answered_with_its_warning() {
            let (agent, _, _) = agent(Terminals::default());
            let lines = answer(&agent, request("office", Some(proxy::Route::Mixed)))
                .await
                .unwrap();
            assert_eq!(lines[3], "route: mixed");
            assert_eq!(lines.last().unwrap(), crate::link::MIXED_WARNING);
            agent.close_all().await;
        }

        #[tokio::test]
        async fn a_job_that_cannot_be_created_starts_nothing() {
            let launcher = Terminals {
                job: false,
                ..Terminals::default()
            };
            let (agent, launcher, _) = agent(launcher);
            let error = answer(&agent, request("office", None)).await.unwrap_err();
            assert_eq!(
                error,
                "creating the job object for the terminal failed: refused; nothing was started"
            );
            assert!(session_ids(&agent).await.is_empty());
            assert!(launcher.spawned.lock().unwrap().is_empty());
        }

        #[tokio::test]
        async fn a_shell_that_cannot_join_the_job_or_start_closes_its_session() {
            for (spawn, reason) in [
                (Spawn::JobRefused, "putting the process in the job failed"),
                (Spawn::Fails, "not found"),
            ] {
                let launcher = Terminals {
                    spawn,
                    ..Terminals::default()
                };
                let (agent, launcher, _) = agent(launcher);
                let error = answer(&agent, request("office", None)).await.unwrap_err();
                assert!(
                    error.starts_with("starting /opt/shells/pwsh failed: "),
                    "{error}"
                );
                assert!(error.contains(reason), "{error}");
                assert_eq!(launcher.spawned.lock().unwrap().len(), 1);
                assert!(session_ids(&agent).await.is_empty());
                assert!(agent.inner.terminals.lock().await.is_empty());
            }
        }

        #[tokio::test]
        async fn an_unknown_gateway_is_refused_without_a_confirmation() {
            let (agent, launcher, _) = agent(Terminals::default());
            let error = answer(&agent, request("newco", None)).await.unwrap_err();
            assert_eq!(error, "unknown gateway \"newco\"");
            assert!(agent.inner.launching.lock().await.is_none());
            assert!(launcher.spawned.lock().unwrap().is_empty());
            assert!(session_ids(&agent).await.is_empty());
        }

        #[tokio::test]
        async fn terminals_share_the_launch_rate_limit() {
            let limits = AgentLimits {
                launches: 2,
                ..AgentLimits::default()
            };
            let (agent, _, _) = agent_with(Terminals::default(), limits);
            answer(&agent, request("office", None)).await.unwrap();
            answer(&agent, request("office", None)).await.unwrap();
            let launch = LaunchRequest::new("office", "session_credentials").unwrap();
            let error = answer(&agent, Request::Launch(launch)).await.unwrap_err();
            assert!(error.starts_with("too many launch requests"), "{error}");
            agent.close_all().await;
        }

        #[tokio::test]
        async fn terminal_capacity_is_counted_apart_from_browsers() {
            let limits = AgentLimits {
                max_terminal_sessions: 1,
                max_browser_sessions: 1,
                ..AgentLimits::default()
            };
            let (agent, _, _) = agent_with(Terminals::default(), limits);
            answer(&agent, request("office", None)).await.unwrap();
            let error = answer(&agent, request("office", None)).await.unwrap_err();
            assert_eq!(
                error,
                "1 terminal sessions are already open; close one first"
            );
            assert_eq!(agent.check_capacity().await, Ok(()));
            agent.close_all().await;
        }

        #[tokio::test]
        async fn a_terminal_is_listed_with_its_shell_and_has_no_credentials() {
            let (agent, _, _) = agent(Terminals::default());
            answer(&agent, request("office", None)).await.unwrap();
            let id = session_ids(&agent).await[0];

            let listed = SessionInfo::parse_list(&agent.list().await).unwrap();
            assert_eq!(listed.len(), 1);
            assert_eq!(listed[0].kind, SessionKind::Terminal);
            assert_eq!(listed[0].shell.as_deref(), Some("pwsh"));
            assert_eq!(listed[0].browser, None);
            assert_eq!(
                answer(&agent, Request::Credentials(id)).await,
                Err(format!("session {id} has no credentials"))
            );
            agent.close_all().await;
        }

        #[tokio::test]
        async fn closing_a_terminal_stops_its_shell_and_closes_its_session() {
            let (agent, _, _) = agent(Terminals::default());
            answer(&agent, request("office", None)).await.unwrap();
            let id = session_ids(&agent).await[0];

            assert_eq!(answer(&agent, Request::Close(id)).await, Ok(Vec::new()));
            assert!(session_ids(&agent).await.is_empty());
            assert!(agent.inner.terminals.lock().await.is_empty());
            assert_eq!(
                answer(&agent, Request::Close(id)).await,
                Err(format!("no session {id}"))
            );
        }

        #[tokio::test]
        async fn other_sessions_stay_reachable_while_a_shell_starts() {
            let (launcher, opener) = gated();
            let (agent, _, _) = agent(launcher);
            let starting = tokio::spawn({
                let agent = agent.clone();
                async move { answer(&agent, request("office", None)).await }
            });
            let release = opener.wait_started().await;

            let reachable = agent.inner.sessions.try_lock().is_ok();
            release.send(()).unwrap();
            starting.await.unwrap().unwrap();
            assert!(reachable);
            agent.close_all().await;
        }

        #[tokio::test]
        async fn a_close_while_a_shell_starts_stops_that_shell() {
            let (launcher, opener) = gated();
            let (agent, _, _) = agent(launcher);
            let starting = tokio::spawn({
                let agent = agent.clone();
                async move { answer(&agent, request("office", None)).await }
            });
            let release = opener.wait_started().await;
            let id = tokio::time::timeout(Duration::from_secs(5), session_ids(&agent))
                .await
                .expect("the sessions are reachable while the shell starts")[0];
            let closing = tokio::spawn({
                let agent = agent.clone();
                async move { answer(&agent, Request::Close(id)).await }
            });
            tokio::time::sleep(Duration::from_millis(50)).await;

            release.send(()).unwrap();
            starting.await.unwrap().unwrap();
            assert_eq!(closing.await.unwrap(), Ok(Vec::new()));
            assert!(session_ids(&agent).await.is_empty());
            assert!(agent.inner.terminals.lock().await.is_empty());
        }

        #[tokio::test]
        async fn stop_counts_a_terminal_whose_shell_is_still_starting() {
            let (launcher, opener) = gated();
            let (agent, _, _) = agent(launcher);
            let starting = tokio::spawn({
                let agent = agent.clone();
                async move { answer(&agent, request("office", None)).await }
            });
            let release = opener.wait_started().await;
            let stopping = tokio::spawn({
                let agent = agent.clone();
                async move { agent.close_all().await }
            });
            tokio::time::sleep(Duration::from_millis(50)).await;

            release.send(()).unwrap();
            starting.await.unwrap().unwrap();
            assert_eq!(stopping.await.unwrap(), 1);
            assert!(session_ids(&agent).await.is_empty());
            assert!(agent.inner.terminals.lock().await.is_empty());
        }

        #[test]
        fn the_home_directory_is_userprofile_in_any_case_when_absolute() {
            let absolute = "/home/ana";
            assert_eq!(
                home_dir(&pairs(&[("Path", "x"), ("UserProfile", absolute)])),
                Some(PathBuf::from(absolute))
            );
            assert_eq!(
                home_dir(&pairs(&[("userprofile", absolute)])),
                Some(PathBuf::from(absolute))
            );
            assert_eq!(home_dir(&pairs(&[("USERPROFILE", r"Users\ana")])), None);
            assert_eq!(home_dir(&pairs(&[("USERPROFILE", "")])), None);
            assert_eq!(home_dir(&pairs(&[("HOME", absolute)])), None);
        }

        #[tokio::test]
        async fn a_shell_that_exits_closes_its_session() {
            let launcher = Terminals {
                spawn: Spawn::Exits,
                ..Terminals::default()
            };
            let (agent, _, _) = agent(launcher);
            answer(&agent, request("office", None)).await.unwrap();
            tokio::time::timeout(Duration::from_secs(10), async {
                while !session_ids(&agent).await.is_empty()
                    || !agent.inner.terminals.lock().await.is_empty()
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
        }

        #[tokio::test]
        async fn stop_closes_browsers_and_terminals_and_counts_the_terminals() {
            let (agent, _, _) = agent(Terminals::default());
            answer(&agent, request("office", None)).await.unwrap();
            answer(&agent, request("office", None)).await.unwrap();
            agent
                .start(Launch {
                    route: proxy::Route::Gateway,
                    profile: "office".parse().unwrap(),
                    start_page: None,
                    add: None,
                })
                .await
                .unwrap();
            assert_eq!(session_ids(&agent).await.len(), 3);

            let lines = answer(&agent, Request::Stop).await.unwrap();
            assert_eq!(
                lines,
                [ipc::agent_pid_line(), ipc::closed_terminals_line(2)]
            );
            assert_eq!(ipc::closed_terminals(&lines), Some(2));
            assert!(session_ids(&agent).await.is_empty());
            assert!(agent.inner.terminals.lock().await.is_empty());
            assert!(agent.inner.browsers.lock().await.is_empty());
        }
    }
}
