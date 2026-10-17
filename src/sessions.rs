use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;

use rustls::pki_types::UnixTime;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{Instrument, info, info_span, warn};

use crate::config::GatewayName;
use crate::identity::certificates::IssueError;
use crate::identity::client_cert::ClientCertificate;
use crate::identity::encoding::sha256_fingerprint;
use crate::proxy::{self, Proxy};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    Device,
}

impl fmt::Display for SessionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Device => "device",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(u64);

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

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
    local_addr: SocketAddr,
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

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
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
        let proxy = Proxy::bind(proxy_config)
            .await
            .map_err(SessionError::Proxy)?;
        let local_addr = proxy.local_addr();
        let (close, closed) = oneshot::channel();
        let shutdown = async {
            let _ = closed.await;
        };
        let task = tokio::spawn(proxy.run_until(shutdown).instrument(span));
        let session = Session {
            id,
            kind: config.kind,
            gateway: config.gateway,
            local_addr,
            close,
            task,
        };
        self.sessions.insert(id, session);
        Ok(id)
    }

    pub fn session(&self, id: SessionId) -> Option<&Session> {
        self.sessions.get(&id)
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
