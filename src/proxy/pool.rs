use std::convert::Infallible;
use std::io;
use std::sync::Arc;

use bytes::Bytes;
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::client::TlsStream;

use super::{Endpoint, Limits, UpstreamError, h2, request_tunnel};
use crate::http::{Authority, parse_response};
use crate::tls::ClientCertificateResolver;

pub(super) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub(super) type Tunnel = Box<dyn Io>;

struct Connection {
    sender: ::h2::client::SendRequest<Bytes>,
    liveness: h2::Liveness,
    certificate: Option<CertificateDer<'static>>,
    resolver: Arc<ClientCertificateResolver>,
}

impl Connection {
    fn certificate_changed(&self) -> Result<bool, UpstreamError> {
        self.resolver
            .refresh_connection_certificate()
            .map(|certificate| certificate != self.certificate)
            .map_err(UpstreamError::ClientCertificate)
    }
}

#[derive(Default)]
struct State {
    legacy: bool,
    current: Option<Connection>,
    drivers: Vec<h2::Driver>,
}

impl State {
    async fn register(
        &mut self,
        tls: TlsStream<TcpStream>,
        resolver: Arc<ClientCertificateResolver>,
        limits: &Limits,
    ) -> Result<Option<TlsStream<TcpStream>>, UpstreamError> {
        if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
            self.legacy = true;
            return Ok(Some(tls));
        }
        let certificate = resolver.connection_certificate();
        let (sender, driver, liveness) =
            h2::connect(tls, limits.max_header_bytes, limits.max_tunnels).await?;
        self.drivers.push(driver);
        self.current = Some(Connection {
            sender,
            liveness,
            certificate,
            resolver,
        });
        self.legacy = false;
        Ok(None)
    }
}

#[derive(Default)]
pub(super) struct Pool(Mutex<State>);

impl Pool {
    pub(super) async fn open(
        &self,
        endpoint: &Endpoint,
        target: &Authority,
        limits: &Limits,
    ) -> Result<(Tunnel, Vec<u8>), UpstreamError> {
        let max_header_bytes = limits.max_header_bytes;
        let mut state = self.0.lock().await;
        state.drivers.retain(|driver| !driver.finished());
        let mut connected = false;
        if state.legacy && state.current.is_none() {
            drop(state);
            let resolver = Arc::new(endpoint.client_certificate.fresh());
            let tls = endpoint.connect_with(resolver.clone()).await?;
            connected = true;
            state = self.0.lock().await;
            if state.current.is_none()
                && let Some(tls) = state.register(tls, resolver, limits).await?
            {
                drop(state);
                return Self::legacy(tls, target, max_header_bytes).await;
            }
        }
        let probe_deadline = limits.handshake_timeout / 4;
        loop {
            if let Some(current) = &state.current
                && (current.liveness.dead() || current.certificate_changed()?)
            {
                state.current = None;
            }
            if let Some(current) = &state.current
                && current.liveness.quiet_for() >= limits.handshake_timeout
                && !current.liveness.check(probe_deadline).await
            {
                state.current = None;
            }
            if let Some(current) = &mut state.current {
                if let Err(error) = h2::ready(&mut current.sender).await {
                    state.current = None;
                    if connected {
                        return Err(UpstreamError::Http2(error));
                    }
                    continue;
                }
                if current.certificate_changed()? {
                    state.current = None;
                    continue;
                }
                match h2::request(&mut current.sender, target) {
                    Ok(pending) => {
                        let liveness = current.liveness.clone();
                        drop(state);
                        let watchdog = async {
                            tokio::time::sleep(probe_deadline).await;
                            liveness.check(probe_deadline).await;
                            std::future::pending::<Infallible>().await
                        };
                        let (status, stream) = tokio::select! {
                            response = pending.response() => response?,
                            never = watchdog => match never {},
                        };
                        liveness.answered();
                        return if (200..300).contains(&status) {
                            Ok((Box::new(stream), Vec::new()))
                        } else {
                            Err(UpstreamError::Status(status))
                        };
                    }
                    Err(error) => {
                        state.current = None;
                        if connected {
                            return Err(error);
                        }
                        continue;
                    }
                }
            }
            if connected {
                return Err(UpstreamError::Request(io::Error::other(
                    "upstream connection changed before CONNECT could be submitted",
                )));
            }
            connected = true;
            let resolver = Arc::new(endpoint.client_certificate.fresh());
            let tls = endpoint.connect_with(resolver.clone()).await?;
            if let Some(tls) = state.register(tls, resolver, limits).await? {
                drop(state);
                return Self::legacy(tls, target, max_header_bytes).await;
            }
        }
    }

    async fn legacy(
        mut tls: TlsStream<TcpStream>,
        target: &Authority,
        max_header_bytes: usize,
    ) -> Result<(Tunnel, Vec<u8>), UpstreamError> {
        let (status, early) =
            request_tunnel(&mut tls, target, max_header_bytes, parse_response).await?;
        if (200..300).contains(&status) {
            Ok((Box::new(tls), early))
        } else {
            Err(UpstreamError::Status(status))
        }
    }
}
