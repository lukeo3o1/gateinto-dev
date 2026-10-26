use std::fmt;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use aws_lc_rs::rand::SystemRandom;
use rustls::RootCertStore;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{timeout, timeout_at};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tracing::{Instrument, debug, info, info_span, warn};

use crate::http::{
    Authority, DEFAULT_MAX_HEADER_BYTES, ParseError, ParseResult, parse_connect_request,
};
use crate::identity::certificates::ExpiredCertificate;
use crate::identity::client_cert::ClientCertificate;
use crate::job::Job;
use crate::tls::{self, NegotiationError, TlsMode};

#[cfg(any(test, fuzzing))]
#[doc(hidden)]
pub mod fuzzing;
pub(crate) mod h2;
mod local_auth;
mod os_user;
mod pool;
mod relay;
mod routing;
mod session_credentials;

pub use local_auth::LocalAuth;
pub use routing::Route;

use local_auth::Authenticator;
pub use session_credentials::{FailureLimit, SessionCredentials};
use session_credentials::{Verdict, Verifier};

pub const MAX_TUNNELS: u32 = h2::MAX_STREAMS;

pub const DEFAULT_LISTEN: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18736));

#[derive(Debug, Clone)]
pub struct Limits {
    pub max_header_bytes: usize,
    pub max_tunnels: usize,
    pub handshake_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_pending_rejects: usize,
    pub reject_linger: Duration,
    pub local_auth_failures: FailureLimit,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            max_tunnels: 64,
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(300),
            max_pending_rejects: 64,
            reject_linger: Duration::from_secs(1),
            local_auth_failures: FailureLimit::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Upstream {
    pub host: String,
    pub port: u16,
    pub server_name: ServerName<'static>,
    pub roots: RootCertStore,
}

impl Upstream {
    pub fn address(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct OpenTunnels(Arc<AtomicUsize>);

impl OpenTunnels {
    pub fn count(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }

    fn open(&self) -> OpenTunnel {
        self.0.fetch_add(1, Ordering::Relaxed);
        OpenTunnel(self.clone())
    }
}

struct OpenTunnel(OpenTunnels);

impl Drop for OpenTunnel {
    fn drop(&mut self) {
        self.0.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub allow_non_loopback: bool,
    pub local_auth: LocalAuth,
    pub route: Route,
    pub upstream: Upstream,
    pub tls_mode: TlsMode,
    pub client_certificate: Option<ClientCertificate>,
    pub limits: Limits,
    pub os_user_job: Option<Arc<Job>>,
}

#[derive(Debug)]
pub enum Error {
    NonLoopbackListen(SocketAddr),
    TunnelLimit(usize),
    Random,
    OsUser(io::Error),
    Tls(rustls::Error),
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonLoopbackListen(addr) => write!(
                f,
                "refusing to listen on non-loopback address {addr}; pass --unsafe-allow-non-loopback-listen to override"
            ),
            Self::TunnelLimit(limit) => write!(
                f,
                "the tunnel limit is {limit}; the maximum is {MAX_TUNNELS}"
            ),
            Self::Random => f.write_str("the system random number generator failed"),
            Self::OsUser(error) => write!(f, "os_user authentication is unavailable: {error}"),
            Self::Tls(error) => write!(f, "invalid upstream TLS configuration: {error}"),
            Self::Io(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for Error {}

pub struct Proxy {
    listener: TcpListener,
    credentials: Option<SessionCredentials>,
    shared: Arc<Shared>,
}

pub(crate) struct Endpoint {
    config: Arc<rustls::ClientConfig>,
    client_certificate: Arc<tls::ClientCertificateResolver>,
    host: String,
    port: u16,
    server_name: ServerName<'static>,
    tls_mode: TlsMode,
}

impl Endpoint {
    pub(crate) fn new(
        upstream: Upstream,
        tls_mode: TlsMode,
        client_certificate: Arc<tls::ClientCertificateResolver>,
    ) -> Result<Self, rustls::Error> {
        let config = tls::client_config(tls_mode, upstream.roots, client_certificate.clone())?;
        Ok(Self {
            config: Arc::new(config),
            client_certificate,
            host: upstream.host,
            port: upstream.port,
            server_name: upstream.server_name,
            tls_mode,
        })
    }

    pub(crate) async fn connect(&self) -> Result<TlsStream<TcpStream>, UpstreamError> {
        self.connect_with(self.client_certificate.clone()).await
    }

    async fn connect_with(
        &self,
        resolver: Arc<tls::ClientCertificateResolver>,
    ) -> Result<TlsStream<TcpStream>, UpstreamError> {
        resolver
            .check_required(resolver.now())
            .map_err(UpstreamError::ClientCertificate)?;
        let addresses = crate::dns::resolve(&self.host, self.port)
            .await
            .map_err(UpstreamError::Connect)?;
        let tcp = TcpStream::connect(addresses.as_slice())
            .await
            .map_err(UpstreamError::Connect)?;
        let _ = tcp.set_nodelay(true);
        let mut config = (*self.config).clone();
        config.client_auth_cert_resolver = resolver;
        let tls = TlsConnector::from(Arc::new(config))
            .connect(self.server_name.clone(), tcp)
            .await
            .map_err(UpstreamError::Tls)?;
        let connection = tls.get_ref().1;
        let version = connection.protocol_version();
        let group = connection
            .negotiated_key_exchange_group()
            .map(|group| group.name());
        debug!(?version, key_exchange_group = ?group, "upstream TLS established");
        self.tls_mode
            .verify_negotiated(version, group)
            .map_err(UpstreamError::Negotiation)?;
        Ok(tls)
    }
}

pub(crate) async fn request_tunnel<T>(
    tls: &mut TlsStream<TcpStream>,
    target: &Authority,
    max_header_bytes: usize,
    parse: fn(&[u8], usize) -> ParseResult<T>,
) -> Result<(T, Vec<u8>), UpstreamError> {
    let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    tls.write_all(request.as_bytes())
        .await
        .map_err(UpstreamError::Request)?;
    tls.flush().await.map_err(UpstreamError::Request)?;
    read_head(tls, max_header_bytes, parse)
        .await
        .map_err(UpstreamError::Head)
}

struct Shared {
    endpoint: Endpoint,
    pool: pool::Pool,
    route: Route,
    auth: Authenticator,
    limits: Limits,
    tunnels: Arc<Semaphore>,
    rejects: Arc<Semaphore>,
    open_tunnels: OpenTunnels,
}

impl Proxy {
    pub async fn bind(config: Config) -> Result<Self, Error> {
        Self::bind_inner(config, Arc::new(rustls::time_provider::DefaultTimeProvider)).await
    }

    #[cfg(feature = "test-hooks")]
    pub async fn bind_with_time_provider(
        config: Config,
        time_provider: Arc<dyn rustls::time_provider::TimeProvider>,
    ) -> Result<Self, Error> {
        Self::bind_inner(config, time_provider).await
    }

    async fn bind_inner(
        config: Config,
        time_provider: Arc<dyn rustls::time_provider::TimeProvider>,
    ) -> Result<Self, Error> {
        if !config.listen.ip().is_loopback() && !config.allow_non_loopback {
            return Err(Error::NonLoopbackListen(config.listen));
        }
        if config.limits.max_tunnels > MAX_TUNNELS as usize {
            return Err(Error::TunnelLimit(config.limits.max_tunnels));
        }
        let endpoint = Endpoint::new(
            config.upstream,
            config.tls_mode,
            Arc::new(tls::ClientCertificateResolver::with_time_provider(
                config.client_certificate,
                time_provider,
            )),
        )
        .map_err(Error::Tls)?;
        let (credentials, verifier) = if config.local_auth.session_credentials {
            let random = SystemRandom::new();
            let credentials = SessionCredentials::generate(&random).map_err(|_| Error::Random)?;
            let verifier = Verifier::new(&credentials, config.limits.local_auth_failures, &random)
                .map_err(|_| Error::Random)?;
            (Some(credentials), Some(verifier))
        } else {
            (None, None)
        };
        let owners = if config.local_auth.os_user {
            Some(os_user::system(config.os_user_job).map_err(Error::OsUser)?)
        } else {
            None
        };
        let listener = TcpListener::bind(config.listen).await.map_err(Error::Io)?;
        let tunnels = Arc::new(Semaphore::new(
            config.limits.max_tunnels.min(Semaphore::MAX_PERMITS),
        ));
        let rejects = Arc::new(Semaphore::new(
            config
                .limits
                .max_pending_rejects
                .min(Semaphore::MAX_PERMITS),
        ));
        let shared = Shared {
            endpoint,
            pool: pool::Pool::default(),
            route: config.route,
            auth: Authenticator::new(verifier, owners),
            limits: config.limits,
            tunnels,
            rejects,
            open_tunnels: OpenTunnels::default(),
        };
        Ok(Self {
            listener,
            credentials,
            shared: Arc::new(shared),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.listener
            .local_addr()
            .expect("a bound listener has a local address")
    }

    pub fn realm(&self) -> Option<&str> {
        self.shared.auth.realm()
    }

    pub fn credentials(&self) -> Option<&SessionCredentials> {
        self.credentials.as_ref()
    }

    pub fn open_tunnels(&self) -> OpenTunnels {
        self.shared.open_tunnels.clone()
    }

    pub async fn run(self) {
        self.run_until(std::future::pending()).await;
    }

    pub async fn run_until(self, shutdown: impl Future<Output = ()>) {
        info!(local_addr = %self.local_addr(), route = %self.shared.route, "listening");
        let Self {
            listener, shared, ..
        } = self;
        let mut connections = JoinSet::new();
        let mut shutdown = std::pin::pin!(shutdown);
        loop {
            let accepted = tokio::select! {
                biased;
                () = &mut shutdown => break,
                Some(_) = connections.join_next(), if !connections.is_empty() => continue,
                accepted = listener.accept() => accepted,
            };
            let (stream, peer) = match accepted {
                Ok(accepted) => accepted,
                Err(error) => {
                    warn!(%error, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let span = info_span!("connection", %peer);
            match shared.tunnels.clone().try_acquire_owned() {
                Ok(permit) => {
                    let shared = shared.clone();
                    connections.spawn(
                        async move {
                            shared.handle(stream).await;
                            drop(permit);
                        }
                        .instrument(span),
                    );
                }
                Err(_) => match shared.rejects.clone().try_acquire_owned() {
                    Ok(permit) => {
                        let linger = shared.limits.reject_linger;
                        connections.spawn(
                            async move {
                                warn!("tunnel limit reached");
                                reject(stream, Status::ServiceUnavailable, linger).await;
                                drop(permit);
                            }
                            .instrument(span),
                        );
                    }
                    Err(_) => {
                        span.in_scope(|| debug!("reject limit reached, closing without response"));
                        drop(stream);
                    }
                },
            }
        }
        drop(listener);
        let aborted = connections.len();
        connections.shutdown().await;
        info!(aborted, "closed");
    }
}

impl Shared {
    async fn handle(&self, mut client: TcpStream) {
        let _ = client.set_nodelay(true);
        let limits = &self.limits;
        let deadline = tokio::time::Instant::now() + limits.handshake_timeout;
        let os_user = self
            .auth
            .os_user(client.peer_addr(), client.local_addr(), deadline);
        let Some(os_user) = os_user.await else {
            return reject(client, Status::RequestTimeout, limits.reject_linger).await;
        };
        let request = read_head(&mut client, limits.max_header_bytes, parse_connect_request);
        let (request, client_early) = match timeout_at(deadline, request).await {
            Err(_) => {
                return reject(client, Status::RequestTimeout, limits.reject_linger).await;
            }
            Ok(Err(error)) => {
                debug!(?error, "invalid request");
                return reject(client, error.local_status(), limits.reject_linger).await;
            }
            Ok(Ok(request)) => request,
        };
        let authorization = request.proxy_authorization.as_deref();
        if let Err(response) = self.auth.check(os_user, authorization, Instant::now()) {
            debug!("rejecting");
            return reject_with(client, &response, limits.reject_linger).await;
        }
        let target = request.target;
        debug!(%target, "opening tunnel");
        let opening = timeout(limits.handshake_timeout, self.open_upstream(&target));
        let (mut upstream, upstream_early) = match opening.await {
            Err(_) => {
                warn!("upstream timed out");
                return reject(client, Status::GatewayTimeout, limits.reject_linger).await;
            }
            Ok(Err(error)) => {
                warn!(%error, "upstream refused tunnel");
                return reject(client, error.local_status(), limits.reject_linger).await;
            }
            Ok(Ok(opened)) => opened,
        };
        info!("tunnel established");
        let _open = self.open_tunnels.open();
        let mut response = b"HTTP/1.1 200 Connection Established\r\n\r\n".to_vec();
        response.extend_from_slice(&upstream_early);
        let established = async {
            client.write_all(&response).await?;
            upstream.write_all(&client_early).await?;
            upstream.flush().await
        };
        match timeout(limits.idle_timeout, established).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return debug!(%error, "tunnel closed"),
            Err(_) => return info!("tunnel idle timeout"),
        }
        match relay::relay(client, upstream, limits.idle_timeout).await {
            Some(Ok((sent, received))) => debug!(sent, received, "tunnel closed"),
            Some(Err(error)) => debug!(%error, "tunnel closed"),
            None => info!("tunnel idle timeout"),
        }
    }

    async fn open_upstream(
        &self,
        target: &Authority,
    ) -> Result<(pool::Tunnel, Vec<u8>), UpstreamError> {
        if let Some(stream) = routing::attempt(
            self.route,
            self.limits.handshake_timeout,
            target,
            (&self.endpoint.host, self.endpoint.port),
            routing::resolve,
        )
        .await
        {
            info!(route = "direct", "selected tunnel route");
            return Ok((Box::new(stream), Vec::new()));
        }
        info!(route = "gateway", "selected tunnel route");
        self.pool.open(&self.endpoint, target, &self.limits).await
    }
}

fn authenticate(
    verifier: &Verifier,
    authorization: Option<&[u8]>,
    now: Instant,
) -> Result<(), Status> {
    match verifier.check(authorization, now) {
        Verdict::Accepted => Ok(()),
        Verdict::Challenge => Err(Status::ProxyAuthenticationRequired),
        Verdict::Rejected => {
            warn!("local proxy credentials differ from the ones issued to this session");
            Err(Status::ProxyAuthenticationRequired)
        }
        Verdict::Malformed => {
            warn!("malformed local proxy credential");
            Err(Status::BadRequest)
        }
        Verdict::RateLimited { retry_after } => {
            warn!("local proxy authentication rate limited");
            Err(Status::TooManyRequests { retry_after })
        }
    }
}

#[derive(Debug)]
pub(crate) enum HeadError {
    Io(io::Error),
    Closed,
    Parse(ParseError),
}

impl HeadError {
    fn local_status(&self) -> Status {
        match self {
            Self::Parse(ParseError::MethodNotAllowed) => Status::MethodNotAllowed,
            Self::Parse(ParseError::TooLarge) => Status::HeaderFieldsTooLarge,
            Self::Parse(ParseError::Malformed) | Self::Io(_) | Self::Closed => Status::BadRequest,
        }
    }
}

impl fmt::Display for HeadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::Closed => write!(f, "connection closed before the header ended"),
            Self::Parse(error) => write!(f, "invalid header: {error:?}"),
        }
    }
}

async fn read_head<S, T>(
    stream: &mut S,
    max_header_bytes: usize,
    parse: fn(&[u8], usize) -> ParseResult<T>,
) -> Result<(T, Vec<u8>), HeadError>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        if let Some(parsed) = parse(&buf, max_header_bytes).map_err(HeadError::Parse)? {
            buf.drain(..parsed.head_len);
            return Ok((parsed.value, buf));
        }
        match stream.read(&mut chunk).await.map_err(HeadError::Io)? {
            0 => return Err(HeadError::Closed),
            n => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

#[derive(Debug)]
pub(crate) enum UpstreamError {
    ClientCertificate(ExpiredCertificate),
    Connect(io::Error),
    Tls(io::Error),
    Negotiation(NegotiationError),
    Request(io::Error),
    Head(HeadError),
    Status(u16),
    Http2(::h2::Error),
}

impl UpstreamError {
    fn local_status(&self) -> Status {
        match self {
            Self::Status(403) => Status::Forbidden,
            _ => Status::BadGateway,
        }
    }
}

impl fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClientCertificate(error) => {
                write!(f, "no client certificate available: {error}")
            }
            Self::Connect(error) => write!(f, "connect failed: {error}"),
            Self::Tls(error) => write!(f, "TLS handshake failed: {error}"),
            Self::Negotiation(error) => write!(f, "TLS negotiation refused: {error}"),
            Self::Request(error) => write!(f, "sending CONNECT failed: {error}"),
            Self::Head(error) => write!(f, "invalid CONNECT response: {error}"),
            Self::Status(status) => write!(f, "CONNECT answered with status {status}"),
            Self::Http2(error) => write!(f, "HTTP/2 CONNECT failed: {error}"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Status {
    BadRequest,
    ProxyAuthenticationRequired,
    TooManyRequests { retry_after: Duration },
    Forbidden,
    MethodNotAllowed,
    RequestTimeout,
    HeaderFieldsTooLarge,
    BadGateway,
    ServiceUnavailable,
    GatewayTimeout,
}

impl Status {
    fn response(self) -> String {
        self.response_in("")
    }

    fn response_in(self, realm: &str) -> String {
        let (code, reason) = match self {
            Self::BadRequest => (400, "Bad Request"),
            Self::ProxyAuthenticationRequired => (407, "Proxy Authentication Required"),
            Self::TooManyRequests { .. } => (429, "Too Many Requests"),
            Self::Forbidden => (403, "Forbidden"),
            Self::MethodNotAllowed => (405, "Method Not Allowed"),
            Self::RequestTimeout => (408, "Request Timeout"),
            Self::HeaderFieldsTooLarge => (431, "Request Header Fields Too Large"),
            Self::BadGateway => (502, "Bad Gateway"),
            Self::ServiceUnavailable => (503, "Service Unavailable"),
            Self::GatewayTimeout => (504, "Gateway Timeout"),
        };
        let extra = match self {
            Self::MethodNotAllowed => "Allow: CONNECT\r\n".to_owned(),
            Self::ProxyAuthenticationRequired => {
                format!("Proxy-Authenticate: Basic realm=\"{realm}\", charset=\"UTF-8\"\r\n")
            }
            Self::TooManyRequests { retry_after } => {
                let seconds = retry_after.as_millis().div_ceil(1000).max(1);
                format!("Retry-After: {seconds}\r\n")
            }
            _ => String::new(),
        };
        format!("HTTP/1.1 {code} {reason}\r\n{extra}Connection: close\r\nContent-Length: 0\r\n\r\n")
    }
}

const LINGER_BYTES: usize = 64 * 1024;

async fn reject(stream: TcpStream, status: Status, linger: Duration) {
    debug!(?status, "rejecting");
    reject_with(stream, &status.response(), linger).await;
}

async fn reject_with(mut stream: TcpStream, response: &str, linger: Duration) {
    if stream.write_all(response.as_bytes()).await.is_err() || stream.shutdown().await.is_err() {
        return;
    }
    // Closing with unread input makes the kernel send RST, which can discard the response before
    // the client reads it.
    let drain = async {
        let mut sink = [0; 4096];
        let mut drained = 0;
        while drained < LINGER_BYTES {
            match stream.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(n) => drained += n,
            }
        }
    };
    let _ = timeout(linger, drain).await;
}

#[cfg(test)]
mod tests {
    use rustls::NamedGroup;

    use super::os_user::tests::{Fake, fake, slow};
    use super::os_user::{Denial, Owners};
    use super::*;

    async fn closed_port() -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        listener.local_addr().unwrap()
    }

    async fn config(local_auth: LocalAuth, handshake: Duration) -> Config {
        let upstream = closed_port().await;
        Config {
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            allow_non_loopback: false,
            local_auth,
            route: Route::Gateway,
            upstream: Upstream {
                host: upstream.ip().to_string(),
                port: upstream.port(),
                server_name: ServerName::try_from("upstream.test").unwrap(),
                roots: RootCertStore::empty(),
            },
            tls_mode: TlsMode::default(),
            client_certificate: None,
            limits: Limits {
                handshake_timeout: handshake,
                reject_linger: Duration::ZERO,
                ..Limits::default()
            },
            os_user_job: None,
        }
    }

    async fn start(local_auth: LocalAuth, owners: Arc<Fake>, handshake: Duration) -> Proxy {
        assert!(local_auth.os_user);
        let without = LocalAuth {
            os_user: false,
            ..local_auth
        };
        let mut proxy = Proxy::bind(config(without, handshake).await).await.unwrap();
        let shared = Arc::get_mut(&mut proxy.shared).unwrap();
        let auth = std::mem::replace(&mut shared.auth, Authenticator::new(None, None));
        shared.auth = auth.with_owners(owners as Arc<dyn Owners>);
        proxy
    }

    #[tokio::test]
    async fn the_upstream_address_brackets_ipv6_hosts() {
        let mut upstream = config(LocalAuth::NONE, Duration::from_secs(5))
            .await
            .upstream;
        upstream.host = "proxy.example".to_owned();
        upstream.port = 443;
        assert_eq!(upstream.address(), "proxy.example:443");
        upstream.host = "::1".to_owned();
        assert_eq!(upstream.address(), "[::1]:443");
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn binding_with_os_user_fails_outside_windows() {
        for local_auth in [
            LocalAuth::OS_USER,
            LocalAuth {
                os_user: true,
                session_credentials: true,
            },
        ] {
            let config = config(local_auth, Duration::from_secs(5)).await;
            match Proxy::bind(config).await {
                Err(Error::OsUser(error)) => {
                    assert_eq!(error.kind(), io::ErrorKind::Unsupported, "{error}");
                }
                Err(other) => panic!("unexpected error: {other}"),
                Ok(_) => panic!("os_user was accepted outside Windows"),
            }
        }
    }

    async fn exchange(proxy: Proxy, request: &[u8]) -> (String, TcpStream) {
        let addr = proxy.local_addr();
        tokio::spawn(proxy.run());
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(request).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        (String::from_utf8(response).unwrap(), client)
    }

    const CONNECT: &[u8] = b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n";

    const OS_USER: LocalAuth = LocalAuth {
        os_user: true,
        session_credentials: false,
    };

    const BOTH: LocalAuth = LocalAuth {
        os_user: true,
        session_credentials: true,
    };

    #[tokio::test]
    async fn a_connection_from_the_same_user_opens_a_tunnel_without_credentials() {
        let owners = fake(Ok(()));
        let proxy = start(BOTH, owners.clone(), Duration::from_secs(5)).await;
        let (response, client) = exchange(proxy, CONNECT).await;
        assert!(response.starts_with("HTTP/1.1 502 "), "{response}");
        assert_eq!(
            *owners.seen.lock().unwrap(),
            [(client.local_addr().unwrap(), client.peer_addr().unwrap())]
        );
    }

    #[tokio::test]
    async fn a_connection_from_another_user_is_forbidden_without_session_credentials() {
        let proxy = start(
            OS_USER,
            fake(Err(Denial::OtherUser)),
            Duration::from_secs(5),
        )
        .await;
        let (response, _) = exchange(proxy, CONNECT).await;
        assert_eq!(
            response,
            "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn a_denied_connection_is_challenged_when_session_credentials_are_offered() {
        let proxy = start(BOTH, fake(Err(Denial::NotFound)), Duration::from_secs(5)).await;
        let realm = proxy.realm().unwrap().to_owned();
        let (response, _) = exchange(proxy, CONNECT).await;
        assert_eq!(
            response,
            Status::ProxyAuthenticationRequired.response_in(&realm)
        );
    }

    #[tokio::test]
    async fn a_slow_owner_lookup_is_bounded_by_the_handshake_timeout() {
        let owners = slow(Ok(()), Duration::from_secs(1));
        let proxy = start(OS_USER, owners, Duration::from_millis(50)).await;
        let started = Instant::now();
        let (response, _) = exchange(proxy, CONNECT).await;
        assert!(response.starts_with("HTTP/1.1 408 "), "{response}");
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn refused_negotiation_answers_bad_gateway() {
        let error = UpstreamError::Negotiation(NegotiationError::KeyExchangeGroup {
            mode: TlsMode::HybridRequired,
            negotiated: Some(NamedGroup::X25519),
        });
        assert!(
            error.local_status().response().starts_with("HTTP/1.1 502 "),
            "{}",
            error.local_status().response()
        );
    }
}
