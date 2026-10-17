use std::fmt;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::RootCertStore;
use rustls::pki_types::{ServerName, UnixTime};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tracing::{Instrument, debug, info, info_span, warn};

use crate::http::{
    Authority, DEFAULT_MAX_HEADER_BYTES, ParseError, ParseResult, parse_connect_request,
    parse_response,
};
use crate::identity::certificates::ExpiredCertificate;
use crate::identity::client_cert::ClientCertificate;
use crate::tls::{self, NegotiationError, TlsMode};

mod basic_tofu;
#[doc(hidden)]
pub mod fuzzing;
mod relay;

pub use basic_tofu::FailureLimit;
use basic_tofu::{BasicTofu, Verdict};

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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalAuth {
    #[default]
    None,
    BasicTofu,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub allow_non_loopback: bool,
    pub local_auth: LocalAuth,
    pub upstream: Upstream,
    pub tls_mode: TlsMode,
    pub client_certificate: Option<ClientCertificate>,
    pub limits: Limits,
}

#[derive(Debug)]
pub enum Error {
    NonLoopbackListen(SocketAddr),
    Random,
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
            Self::Random => f.write_str("the system random number generator failed"),
            Self::Tls(error) => write!(f, "invalid upstream TLS configuration: {error}"),
            Self::Io(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for Error {}

pub struct Proxy {
    listener: TcpListener,
    shared: Arc<Shared>,
}

pub(crate) struct Endpoint {
    connector: TlsConnector,
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
            connector: TlsConnector::from(Arc::new(config)),
            client_certificate,
            host: upstream.host,
            port: upstream.port,
            server_name: upstream.server_name,
            tls_mode,
        })
    }

    pub(crate) async fn connect(&self) -> Result<TlsStream<TcpStream>, UpstreamError> {
        self.client_certificate
            .check_required(UnixTime::now())
            .map_err(UpstreamError::ClientCertificate)?;
        let tcp = TcpStream::connect((self.host.as_str(), self.port))
            .await
            .map_err(UpstreamError::Connect)?;
        let _ = tcp.set_nodelay(true);
        let tls = self
            .connector
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
    basic_tofu: Option<BasicTofu>,
    limits: Limits,
    tunnels: Arc<Semaphore>,
    rejects: Arc<Semaphore>,
}

impl Proxy {
    pub async fn bind(config: Config) -> Result<Self, Error> {
        if !config.listen.ip().is_loopback() && !config.allow_non_loopback {
            return Err(Error::NonLoopbackListen(config.listen));
        }
        let endpoint = Endpoint::new(
            config.upstream,
            config.tls_mode,
            Arc::new(tls::ClientCertificateResolver::new(
                config.client_certificate,
            )),
        )
        .map_err(Error::Tls)?;
        let basic_tofu = match config.local_auth {
            LocalAuth::None => None,
            LocalAuth::BasicTofu => {
                Some(BasicTofu::new(config.limits.local_auth_failures).map_err(|_| Error::Random)?)
            }
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
            basic_tofu,
            limits: config.limits,
            tunnels,
            rejects,
        };
        Ok(Self {
            listener,
            shared: Arc::new(shared),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.listener
            .local_addr()
            .expect("a bound listener has a local address")
    }

    pub fn realm(&self) -> Option<&str> {
        self.shared.basic_tofu.as_ref().map(BasicTofu::realm)
    }

    pub async fn run(self) {
        self.run_until(std::future::pending()).await;
    }

    pub async fn run_until(self, shutdown: impl Future<Output = ()>) {
        info!(local_addr = %self.local_addr(), "listening");
        let Self { listener, shared } = self;
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
        let request = read_head(&mut client, limits.max_header_bytes, parse_connect_request);
        let (request, client_early) = match timeout(limits.handshake_timeout, request).await {
            Err(_) => {
                return reject(client, Status::RequestTimeout, limits.reject_linger).await;
            }
            Ok(Err(error)) => {
                debug!(?error, "invalid request");
                return reject(client, error.local_status(), limits.reject_linger).await;
            }
            Ok(Ok(request)) => request,
        };
        if let Some(tofu) = &self.basic_tofu {
            let authorization = request.proxy_authorization.as_deref();
            if let Err(status) = authorize(tofu, authorization, Instant::now()) {
                debug!(?status, "rejecting");
                let response = status.response_in(tofu.realm());
                return reject_with(client, &response, limits.reject_linger).await;
            }
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
    ) -> Result<(TlsStream<TcpStream>, Vec<u8>), UpstreamError> {
        let mut tls = self.endpoint.connect().await?;
        let (status, early) = request_tunnel(
            &mut tls,
            target,
            self.limits.max_header_bytes,
            parse_response,
        )
        .await?;
        if (200..300).contains(&status) {
            Ok((tls, early))
        } else {
            Err(UpstreamError::Status(status))
        }
    }
}

fn authorize(tofu: &BasicTofu, authorization: Option<&[u8]>, now: Instant) -> Result<bool, Status> {
    match tofu.check(authorization, now) {
        Verdict::Bound => {
            info!("bound the first local proxy credential to this session");
            Ok(true)
        }
        Verdict::Accepted => Ok(false),
        Verdict::Challenge => Err(Status::ProxyAuthenticationRequired),
        Verdict::Rejected => {
            warn!("local proxy credential differs from the one bound to this session");
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

    use super::*;

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
