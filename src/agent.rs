use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsString;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, Notify, Semaphore, oneshot};
use tokio::task::{JoinHandle, JoinSet};
use tracing::{Instrument, info, info_span, warn};

use crate::browser::{self, BrowserProcess, ProfileDir};
use crate::config::GatewayName;
use crate::ipc::{self, ConfirmToken, Connection, Request, Response, Server};
use crate::job::{Job, SpawnError};
use crate::link::{self, Decision, Known, Launch, LinkedGateway, Resolution};
use crate::proxy::{self, LocalAuth};
use crate::sessions::{SessionConfig, SessionError, SessionId, SessionKind, SessionManager};
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
    pub confirm_timeout: Duration,
}

impl Default for AgentLimits {
    fn default() -> Self {
        Self {
            launches: 5,
            launch_window: Duration::from_secs(60),
            max_browser_sessions: 4,
            confirm_timeout: Duration::from_secs(120),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BrowserSessionPlan {
    pub proxy: proxy::Config,
}

pub trait Profiles: Send + Sync + 'static {
    fn known(&self) -> Result<Known, String>;
    fn link(&self, gateway: &LinkedGateway) -> Result<(), String>;
    fn browser_session(&self, gateway: &GatewayName) -> Result<BrowserSessionPlan, String>;
}

struct Pending {
    token: ConfirmToken,
    request: LaunchRequest,
    expires: Instant,
}

#[derive(Debug, Clone)]
pub struct AgentOptions {
    pub browser: Option<PathBuf>,
    pub profiles_root: PathBuf,
    pub limits: AgentLimits,
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
    close: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

trait Launcher: Send + Sync + 'static {
    fn job(&self) -> Option<Arc<Job>>;
    fn spawn(
        &self,
        executable: &Path,
        args: Vec<OsString>,
        job: Option<&Arc<Job>>,
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
}

struct Inner {
    profiles: Box<dyn Profiles>,
    launcher: Arc<dyn Launcher>,
    options: AgentOptions,
    sessions: Mutex<SessionManager>,
    browsers: Mutex<BTreeMap<SessionId, Browser>>,
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
                launches: std::sync::Mutex::new(limiter),
                launching: Mutex::new(None),
                stop: Notify::new(),
            }),
        }
    }

    pub async fn start_session(&self, config: SessionConfig) -> Result<SessionId, SessionError> {
        self.inner.sessions.lock().await.start(config).await
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
            Request::Approve(token) => self.approve(token).await,
            Request::Deny(token) => self.deny(token).await.map(|()| Vec::new()),
            Request::List => Ok(self.list().await),
            Request::Close(id) => self.close(id).await.map(|()| Vec::new()),
            Request::Credentials(id) => self.credentials(id).await,
            Request::Stop => {
                self.inner.stop.notify_one();
                self.close_all().await;
                Ok(vec![ipc::agent_pid_line()])
            }
        };
        match result {
            Ok(lines) => Response::Ok(lines),
            Err(error) => Response::Error(error),
        }
    }

    async fn launch(&self, request: LaunchRequest) -> Result<Vec<String>, String> {
        let mut pending = self.inner.launching.lock().await;
        let limits = &self.inner.options.limits;
        let allowed = self
            .inner
            .launches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .allow(Instant::now());
        if !allowed {
            warn!(gateway = ?request.profile, "refused a browser launch: rate limit reached");
            return Err(format!(
                "too many launch requests; at most {} are accepted every {} seconds",
                limits.launches,
                limits.launch_window.as_secs()
            ));
        }
        self.check_capacity().await?;
        let known = self.inner.profiles.known()?;
        let resolution = link::resolve(&request, &known, &mut Decision::Defer, unix_now())
            .map_err(|error| error.to_string())?;
        let confirmation = match resolution {
            Resolution::Launch(launch) => {
                return self.start(launch).await.map(|lines| warned(lines, &known));
            }
            Resolution::Confirm(confirmation) => confirmation,
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
        *pending = Some(Pending {
            token,
            request,
            expires: now + limits.confirm_timeout,
        });
        info!(
            gateway = %confirmation.profile,
            address = %confirmation.gateway,
            "a link asks to add a gateway; waiting for the user's confirmation"
        );
        let mut lines = vec![ipc::confirm_line(&token)];
        lines.extend(confirmation.echo());
        Ok(warned(lines, &known))
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
        let resolution = link::resolve(
            &answered.request,
            &known,
            &mut Decision::Approve,
            unix_now(),
        )
        .map_err(|error| error.to_string())?;
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
        info!(gateway = ?answered.request.profile, "the user did not allow a gateway from a link");
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
        proxy.allow_non_loopback = false;
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
        browsers.insert(id, Browser { close, task });
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
        self.inner
            .sessions
            .lock()
            .await
            .sessions()
            .map(|session| {
                format!(
                    "session: {} {} {} {}{}",
                    session.id(),
                    session.kind(),
                    session.gateway(),
                    session.local_addr(),
                    if session.route() == proxy::Route::Mixed {
                        " route=mixed"
                    } else {
                        ""
                    }
                )
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
        if self.inner.sessions.lock().await.close(id).await {
            Ok(())
        } else {
            Err(format!("no session {id}"))
        }
    }

    pub async fn close_all(&self) {
        let browsers = std::mem::take(&mut *self.inner.browsers.lock().await);
        for (_, browser) in browsers {
            let _ = browser.close.send(());
            let _ = browser.task.await;
        }
        self.inner.sessions.lock().await.close_all().await;
    }
}

fn warned(mut lines: Vec<String>, known: &Known) -> Vec<String> {
    for line in known.error_lines() {
        warn!("{line}");
        lines.push(line);
    }
    lines
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
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
        }

        #[derive(Clone, Default)]
        struct Logs(Arc<std::sync::Mutex<Vec<u8>>>);

        impl io::Write for Logs {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        impl Logs {
            fn warnings(&self) -> Vec<String> {
                String::from_utf8(self.0.lock().unwrap().clone())
                    .unwrap()
                    .lines()
                    .filter(|line| line.contains("WARN"))
                    .map(str::to_owned)
                    .collect()
            }
        }

        fn proxy_config() -> proxy::Config {
            proxy::Config {
                listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                allow_non_loopback: false,
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
                },
                Plan(proxy_config()),
                launcher.clone(),
            );
            let logs = Logs::default();
            let writer = logs.clone();
            let subscriber = tracing_subscriber::fmt()
                .with_writer(move || writer.clone())
                .finish();
            let guard = tracing::subscriber::set_default(subscriber);

            let lines = agent
                .start(Launch {
                    route: proxy::Route::Gateway,
                    profile: "work".parse().unwrap(),
                    start_page: None,
                    add: None,
                })
                .await
                .unwrap();
            drop(guard);

            assert_eq!(*launcher.jobs.lock().unwrap(), [true, false]);
            let warnings = logs.warnings();
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
}
