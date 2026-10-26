use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::pki_types::UnixTime;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{Instrument, info, info_span, warn};

use crate::config::GatewayName;
use crate::identity::certificates::IssueError;
use crate::identity::client_cert::ClientCertificate;
use crate::identity::encoding::sha256_fingerprint;
use crate::ipc::{BrowserKind, SessionAuth, SessionInfo, SessionRoute};
use crate::proxy::{self, LocalAuth, OpenTunnels, Proxy};

pub use gateinto_ipc_types::SessionKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(pub(crate) u64);

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for SessionId {
    type Err = InvalidSessionId;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(InvalidSessionId);
        }
        text.parse().map(Self).map_err(|_| InvalidSessionId)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidSessionId;

impl fmt::Display for InvalidSessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a session id is a decimal number")
    }
}

impl std::error::Error for InvalidSessionId {}

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub kind: SessionKind,
    pub gateway: GatewayName,
    pub proxy: proxy::Config,
}

#[derive(Debug)]
pub enum SessionError {
    Certificate(IssueError),
    Proxy(proxy::Error),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Certificate(error) => write!(
                f,
                "issuing the session's self-signed client certificate failed: {error}"
            ),
            Self::Proxy(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for SessionError {}

#[derive(Debug)]
pub struct Session {
    id: SessionId,
    kind: SessionKind,
    gateway: GatewayName,
    route: proxy::Route,
    upstream: String,
    started: SystemTime,
    local_addr: SocketAddr,
    open_tunnels: OpenTunnels,
    realm: Option<String>,
    local_auth: LocalAuth,
    credentials: Option<proxy::SessionCredentials>,
    close: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl Session {
    pub fn id(&self) -> SessionId {
        self.id
    }

    pub fn kind(&self) -> SessionKind {
        self.kind
    }

    pub fn gateway(&self) -> &GatewayName {
        &self.gateway
    }

    pub fn route(&self) -> proxy::Route {
        self.route
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn realm(&self) -> Option<&str> {
        self.realm.as_deref()
    }

    pub fn local_auth(&self) -> LocalAuth {
        self.local_auth
    }

    pub fn credentials(&self) -> Option<&proxy::SessionCredentials> {
        self.credentials.as_ref()
    }

    pub fn info(&self, browser: Option<BrowserKind>) -> SessionInfo {
        SessionInfo {
            id: self.id.0,
            kind: self.kind,
            gateway: self.gateway.to_string(),
            upstream: self.upstream.clone(),
            listen: self.local_addr,
            route: match self.route {
                proxy::Route::Gateway => SessionRoute::All,
                proxy::Route::Mixed => SessionRoute::Mixed,
            },
            auth: auth_kind(self.local_auth),
            started: self
                .started
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs()),
            tunnels: self.open_tunnels.count() as u64,
            browser,
        }
    }

    async fn close(self) {
        let _ = self.close.send(());
        let _ = self.task.await;
    }
}

#[derive(Debug, Default)]
pub struct SessionManager {
    next_id: u64,
    sessions: BTreeMap<SessionId, Session>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn start(&mut self, config: SessionConfig) -> Result<SessionId, SessionError> {
        self.next_id += 1;
        let id = SessionId(self.next_id);
        let span = info_span!("session", %id, kind = %config.kind, gateway = %config.gateway);
        let mut proxy_config = config.proxy;
        proxy_config.client_certificate = span.in_scope(|| {
            session_certificate(proxy_config.client_certificate.as_ref(), UnixTime::now())
        })?;
        let route = proxy_config.route;
        let local_auth = proxy_config.local_auth;
        let upstream = proxy_config.upstream.address();
        let proxy = Proxy::bind(proxy_config)
            .await
            .map_err(SessionError::Proxy)?;
        let local_addr = proxy.local_addr();
        let open_tunnels = proxy.open_tunnels();
        let realm = proxy.realm().map(str::to_owned);
        let credentials = proxy.credentials().cloned();
        if !local_auth.is_none() {
            span.in_scope(|| {
                info!(
                    realm = realm.as_deref(),
                    "local proxy authentication: {local_auth}"
                )
            });
        }
        let (close, closed) = oneshot::channel();
        let shutdown = async {
            let _ = closed.await;
        };
        let task = tokio::spawn(proxy.run_until(shutdown).instrument(span));
        let session = Session {
            id,
            kind: config.kind,
            gateway: config.gateway,
            route,
            upstream,
            started: SystemTime::now(),
            local_addr,
            open_tunnels,
            realm,
            local_auth,
            credentials,
            close,
            task,
        };
        self.sessions.insert(id, session);
        Ok(id)
    }

    pub fn session(&self, id: SessionId) -> Option<&Session> {
        self.sessions.get(&id)
    }

    pub fn sessions(&self) -> impl Iterator<Item = &Session> {
        self.sessions.values()
    }

    pub async fn close(&mut self, id: SessionId) -> bool {
        match self.sessions.remove(&id) {
            Some(session) => {
                session.close().await;
                true
            }
            None => false,
        }
    }

    pub async fn close_all(&mut self) {
        for (_, session) in std::mem::take(&mut self.sessions) {
            session.close().await;
        }
    }
}

fn session_certificate(
    source: Option<&ClientCertificate>,
    now: UnixTime,
) -> Result<Option<ClientCertificate>, SessionError> {
    let Some(source) = source else {
        return Ok(None);
    };
    match source.for_session(now) {
        Ok(certificate) => {
            if let ClientCertificate::SelfSigned { certificates, .. } = &certificate {
                info!(
                    sha256 = %sha256_fingerprint(&certificates.current().cert[0]),
                    "issued the session's self-signed client certificate"
                );
            }
            Ok(Some(certificate))
        }
        Err(error) => match source {
            ClientCertificate::SelfSigned {
                required: false, ..
            } => {
                warn!(
                    "issuing the session's self-signed client certificate failed: {error}; \
                     its upstream connections do not authenticate this device"
                );
                Ok(None)
            }
            _ => Err(SessionError::Certificate(error)),
        },
    }
}

fn auth_kind(local_auth: LocalAuth) -> SessionAuth {
    if local_auth.os_user {
        SessionAuth::OsUser
    } else if local_auth.session_credentials {
        SessionAuth::Password
    } else {
        SessionAuth::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_listed_auth_kind_prefers_the_os_user_when_it_is_in_effect() {
        let both = LocalAuth {
            os_user: true,
            session_credentials: true,
        };
        assert_eq!(auth_kind(both), SessionAuth::OsUser);
        assert_eq!(auth_kind(LocalAuth::OS_USER), SessionAuth::OsUser);
        assert_eq!(
            auth_kind(LocalAuth::SESSION_CREDENTIALS),
            SessionAuth::Password
        );
        assert_eq!(auth_kind(LocalAuth::NONE), SessionAuth::None);
    }
}
