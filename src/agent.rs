use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::process::Child;
use tokio::sync::{Mutex, Notify, Semaphore, oneshot};
use tokio::task::{JoinHandle, JoinSet};
use tracing::{Instrument, info, info_span, warn};

use crate::browser::{self, ProfileDir};
use crate::config::GatewayName;
use crate::ipc::{self, ConfirmToken, Connection, Request, Response, Server};
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

struct Inner {
    profiles: Box<dyn Profiles>,
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
        let limiter = LaunchLimiter::new(options.limits.launches, options.limits.launch_window);
        Self {
            inner: Arc::new(Inner {
                profiles: Box::new(profiles),
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
        loop {
            tokio::select! {
                () = &mut shutdown => break,
                () = self.inner.stop.notified() => break,
                accepted = server.accept() => match accepted {
                    Ok(connection) => match connections.clone().try_acquire_owned() {
                        Ok(permit) => {
                            let agent = self.clone();
                            tasks.spawn(async move {
                                agent.respond(connection).await;
                                drop(permit);
                            });
                        }
                        Err(_) => warn!("too many agent requests at once; dropping one"),
                    },
                    Err(error) => {
                        warn!("accepting an agent request failed: {error}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
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
            warn!(gateway = %request.profile, "refused a browser launch: rate limit reached");
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
            warn!(gateway = %request.profile, "refused a new gateway: another confirmation is open");
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
        info!(gateway = %answered.request.profile, "the user did not allow a gateway from a link");
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
        proxy.local_auth = LocalAuth::BasicTofu;
        let mut sessions = self.inner.sessions.lock().await;
        let id = sessions
            .start(SessionConfig {
                kind: SessionKind::Browser,
                gateway: profile.clone(),
                proxy,
            })
            .await
            .map_err(|error| error.to_string())?;
        let session = sessions.session(id).expect("the session just started");
        let (listen, realm) = (
            session.local_addr(),
            session.realm().unwrap_or_default().to_owned(),
        );
        let span = info_span!("session", %id, kind = %SessionKind::Browser, gateway = %profile);
        let started = ProfileDir::create(&self.inner.options.profiles_root, id).and_then(|dir| {
            let args = browser::browser_args(dir.path(), listen, launch.start_page.as_ref());
            match browser::spawn(&executable, args) {
                Ok(child) => Ok((dir, child)),
                Err(error) => {
                    let _ = dir.remove();
                    Err(error)
                }
            }
        });
        let (dir, child) = match started {
            Ok(started) => started,
            Err(error) => {
                sessions.close(id).await;
                let message = format!("starting {} failed: {error}", executable.display());
                span.in_scope(|| warn!("{message}"));
                return Err(message);
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
        let lines = vec![
            format!("session: {id}"),
            format!("gateway: {profile}"),
            format!("listen: {listen}"),
            format!("realm: {realm}"),
            format!("profile: {}", dir.path().display()),
            format!("browser: {}", executable.display()),
        ];
        let (close, closed) = oneshot::channel();
        let mut browsers = self.inner.browsers.lock().await;
        let task = tokio::spawn(watch(self.inner.clone(), id, child, dir, closed).instrument(span));
        browsers.insert(id, Browser { close, task });
        Ok(lines)
    }

    async fn list(&self) -> Vec<String> {
        self.inner
            .sessions
            .lock()
            .await
            .sessions()
            .map(|session| {
                format!(
                    "session: {} {} {} {}",
                    session.id(),
                    session.kind(),
                    session.gateway(),
                    session.local_addr()
                )
            })
            .collect()
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
    mut child: Child,
    profile: ProfileDir,
    closed: oneshot::Receiver<()>,
) {
    tokio::select! {
        status = child.wait() => match status {
            Ok(status) => info!("the browser exited with {status}; closing the session"),
            Err(error) => warn!("waiting for the browser failed: {error}; closing the session"),
        },
        _ = closed => {
            if let Err(error) = child.kill().await {
                warn!("stopping the browser failed: {error}");
            }
            info!("stopped the browser; closing the session");
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn a_zero_limit_refuses_everything() {
        let mut limiter = LaunchLimiter::new(0, Duration::from_secs(10));
        assert!(!limiter.allow(Instant::now()));
    }
}
