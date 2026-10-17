use std::fmt;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use rustls::client::ResolvesClientCert;
use rustls::pki_types::ServerName;
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore, SignatureScheme};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tracing::{Instrument, debug, info, info_span, warn};

use crate::http::{
    Authority, DEFAULT_MAX_HEADER_BYTES, ParseError, ParseResult, parse_connect_request,
    parse_response,
};
use crate::tls;

mod relay;

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

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub allow_non_loopback: bool,
    pub upstream: Upstream,
    pub client_certificate: Option<Arc<CertifiedKey>>,
    pub limits: Limits,
}

#[derive(Debug)]
struct FixedClientCertificate(Arc<CertifiedKey>);

impl ResolvesClientCert for FixedClientCertificate {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[derive(Debug)]
pub enum Error {
    NonLoopbackListen(SocketAddr),
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

struct Shared {
    connector: TlsConnector,
    upstream_host: String,
    upstream_port: u16,
    server_name: ServerName<'static>,
    limits: Limits,
    tunnels: Arc<Semaphore>,
    rejects: Arc<Semaphore>,
}

impl Proxy {
    pub async fn bind(config: Config) -> Result<Self, Error> {
        if !config.listen.ip().is_loopback() && !config.allow_non_loopback {
            return Err(Error::NonLoopbackListen(config.listen));
        }
        let tls = ClientConfig::builder_with_provider(Arc::new(tls::crypto_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(Error::Tls)?
            .with_root_certificates(config.upstream.roots);
        let tls = match config.client_certificate {
            Some(certified_key) => {
                tls.with_client_cert_resolver(Arc::new(FixedClientCertificate(certified_key)))
            }
            None => tls.with_no_client_auth(),
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
            connector: TlsConnector::from(Arc::new(tls)),
            upstream_host: config.upstream.host,
            upstream_port: config.upstream.port,
            server_name: config.upstream.server_name,
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

    pub async fn run(self) {
        info!(local_addr = %self.local_addr(), "listening");
        loop {
            let (stream, peer) = match self.listener.accept().await {
                Ok(accepted) => accepted,
                Err(error) => {
                    warn!(%error, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let span = info_span!("connection", %peer);
            match self.shared.tunnels.clone().try_acquire_owned() {
                Ok(permit) => {
                    let shared = self.shared.clone();
                    tokio::spawn(
                        async move {
                            shared.handle(stream).await;
                            drop(permit);
                        }
                        .instrument(span),
                    );
                }
                Err(_) => match self.shared.rejects.clone().try_acquire_owned() {
                    Ok(permit) => {
                        let linger = self.shared.limits.reject_linger;
                        tokio::spawn(
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
    }
}

impl Shared {
    async fn handle(&self, mut client: TcpStream) {
        let _ = client.set_nodelay(true);
        let limits = &self.limits;
        let request = read_head(&mut client, limits.max_header_bytes, parse_connect_request);
        let (target, client_early) = match timeout(limits.handshake_timeout, request).await {
            Err(_) => return reject(client, Status::RequestTimeout, limits.reject_linger).await,
            Ok(Err(error)) => {
                debug!(?error, "invalid request");
                return reject(client, error.local_status(), limits.reject_linger).await;
            }
            Ok(Ok(request)) => request,
        };
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
        let tcp = TcpStream::connect((self.upstream_host.as_str(), self.upstream_port))
            .await
            .map_err(UpstreamError::Connect)?;
        let _ = tcp.set_nodelay(true);
        let mut tls = self
            .connector
            .connect(self.server_name.clone(), tcp)
            .await
            .map_err(UpstreamError::Tls)?;
        let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
        tls.write_all(request.as_bytes())
            .await
            .map_err(UpstreamError::Request)?;
        tls.flush().await.map_err(UpstreamError::Request)?;
        let (status, early) = read_head(&mut tls, self.limits.max_header_bytes, parse_response)
            .await
            .map_err(UpstreamError::Head)?;
        if (200..300).contains(&status) {
            Ok((tls, early))
        } else {
            Err(UpstreamError::Status(status))
        }
    }
}

#[derive(Debug)]
enum HeadError {
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
enum UpstreamError {
    Connect(io::Error),
    Tls(io::Error),
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
            Self::Connect(error) => write!(f, "connect failed: {error}"),
            Self::Tls(error) => write!(f, "TLS handshake failed: {error}"),
            Self::Request(error) => write!(f, "sending CONNECT failed: {error}"),
            Self::Head(error) => write!(f, "invalid CONNECT response: {error}"),
            Self::Status(status) => write!(f, "CONNECT answered with status {status}"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Status {
    BadRequest,
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
        let (code, reason) = match self {
            Self::BadRequest => (400, "Bad Request"),
            Self::Forbidden => (403, "Forbidden"),
            Self::MethodNotAllowed => (405, "Method Not Allowed"),
            Self::RequestTimeout => (408, "Request Timeout"),
            Self::HeaderFieldsTooLarge => (431, "Request Header Fields Too Large"),
            Self::BadGateway => (502, "Bad Gateway"),
            Self::ServiceUnavailable => (503, "Service Unavailable"),
            Self::GatewayTimeout => (504, "Gateway Timeout"),
        };
        let allow = match self {
            Self::MethodNotAllowed => "Allow: CONNECT\r\n",
            _ => "",
        };
        format!("HTTP/1.1 {code} {reason}\r\n{allow}Connection: close\r\nContent-Length: 0\r\n\r\n")
    }
}

const LINGER_BYTES: usize = 64 * 1024;

async fn reject(mut stream: TcpStream, status: Status, linger: Duration) {
    debug!(?status, "rejecting");
    if stream
        .write_all(status.response().as_bytes())
        .await
        .is_err()
        || stream.shutdown().await.is_err()
    {
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
