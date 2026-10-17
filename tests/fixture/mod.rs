use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gateinto::identity::certificates::{DeviceSigner, SelfSignedCertificates};
use gateinto::identity::x509::parse_certificate;
use gateinto::proxy::{Config, Limits, Proxy, Upstream};
use gateinto::tls::TlsMode;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PublicKeyData,
};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::aws_lc_rs::{self, kx_group};
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::sign::{Signer, SigningKey};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, NamedGroup,
    RootCertStore, ServerConfig, SignatureAlgorithm, SignatureScheme,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;
pub const PROXY_NAME: &str = "proxy.test";
pub const SECRET: &str = "fixture-secret-realm";
pub const HYBRID_GROUPS: &[&dyn SupportedKxGroup] = &[kx_group::X25519MLKEM768, kx_group::X25519];
pub const CLASSICAL_GROUPS: &[&dyn SupportedKxGroup] = &[kx_group::X25519];

pub struct TestCa {
    certificate: CertificateDer<'static>,
    pem: String,
    issuer: Issuer<'static, KeyPair>,
}

impl TestCa {
    pub fn new() -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key).unwrap();
        Self {
            certificate: certificate.der().clone(),
            pem: certificate.pem(),
            issuer: Issuer::new(params, key),
        }
    }

    pub fn pem(&self) -> &str {
        &self.pem
    }

    pub fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(self.certificate.clone()).unwrap();
        roots
    }

    pub fn server_config(&self, name: &str) -> Arc<ServerConfig> {
        self.server_config_with_client_ca(name, None, HYBRID_GROUPS)
    }

    pub fn server_config_with_groups(
        &self,
        name: &str,
        groups: &[&'static dyn SupportedKxGroup],
    ) -> Arc<ServerConfig> {
        self.server_config_with_client_ca(name, None, groups)
    }

    pub fn server_config_requiring_client_certificates(
        &self,
        name: &str,
        client_ca: &TestCa,
    ) -> Arc<ServerConfig> {
        self.server_config_with_client_ca(name, Some((client_ca, true)), HYBRID_GROUPS)
    }

    pub fn server_config_requesting_client_certificates(
        &self,
        name: &str,
        client_ca: &TestCa,
    ) -> Arc<ServerConfig> {
        self.server_config_with_client_ca(name, Some((client_ca, false)), HYBRID_GROUPS)
    }

    pub fn server_config_trusting_client_spki(
        &self,
        name: &str,
        spki: Vec<u8>,
    ) -> Arc<ServerConfig> {
        let provider = Arc::new(aws_lc_rs::default_provider());
        let verifier = Arc::new(SpkiClientVerifier { spki, provider });
        self.server_config_with_verifier(name, Some(verifier), HYBRID_GROUPS)
    }

    fn server_config_with_client_ca(
        &self,
        name: &str,
        client_ca: Option<(&TestCa, bool)>,
        groups: &[&'static dyn SupportedKxGroup],
    ) -> Arc<ServerConfig> {
        let verifier = client_ca.map(|(client_ca, required)| {
            let verifier = WebPkiClientVerifier::builder_with_provider(
                Arc::new(client_ca.roots()),
                Arc::new(provider(groups)),
            );
            let verifier = if required {
                verifier
            } else {
                verifier.allow_unauthenticated()
            };
            verifier.build().unwrap()
        });
        self.server_config_with_verifier(name, verifier, groups)
    }

    fn server_config_with_verifier(
        &self,
        name: &str,
        verifier: Option<Arc<dyn ClientCertVerifier>>,
        groups: &[&'static dyn SupportedKxGroup],
    ) -> Arc<ServerConfig> {
        let key = KeyPair::generate().unwrap();
        let certificate = CertificateParams::new(vec![name.to_owned()])
            .unwrap()
            .signed_by(&key, &self.issuer)
            .unwrap();
        let builder = ServerConfig::builder_with_provider(Arc::new(provider(groups)))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap();
        let builder = match verifier {
            Some(verifier) => builder.with_client_cert_verifier(verifier),
            None => builder.with_no_client_auth(),
        };
        let config = builder
            .with_single_cert(
                vec![certificate.der().clone()],
                PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
            .unwrap();
        Arc::new(config)
    }

    pub fn issue_client_certificate(&self, public_key: &impl PublicKeyData) -> IssuedCertificate {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "gateinto-test-client");
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let certificate = params.signed_by(public_key, &self.issuer).unwrap();
        IssuedCertificate {
            der: certificate.der().clone(),
            pem: certificate.pem(),
        }
    }

    pub fn client_config(&self) -> Arc<ClientConfig> {
        let config = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(self.roots())
            .with_no_client_auth();
        Arc::new(config)
    }
}

fn provider(groups: &[&'static dyn SupportedKxGroup]) -> CryptoProvider {
    CryptoProvider {
        kx_groups: groups.to_vec(),
        ..aws_lc_rs::default_provider()
    }
}

#[derive(Debug)]
pub struct SpkiClientVerifier {
    spki: Vec<u8>,
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for SpkiClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let parsed = parse_certificate(end_entity)
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        if parsed.spki != self.spki {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        let mut itself = RootCertStore::empty();
        itself.add(end_entity.clone().into_owned())?;
        WebPkiClientVerifier::builder_with_provider(Arc::new(itself), self.provider.clone())
            .build()
            .map_err(|error| rustls::Error::General(error.to_string()))?
            .verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub fn software_signer(key: &KeyPair) -> DeviceSigner {
    let der = PrivatePkcs8KeyDer::from(key.serialize_der()).into();
    DeviceSigner::new(
        key.public_key_raw().try_into().unwrap(),
        aws_lc_rs::sign::any_ecdsa_type(&der).unwrap(),
    )
}

#[derive(Debug)]
struct FailingAfterIssueKey {
    inner: Arc<dyn SigningKey>,
    failing: Arc<AtomicBool>,
}

impl SigningKey for FailingAfterIssueKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if self.failing.load(Ordering::Relaxed) {
            return None;
        }
        self.inner.choose_scheme(offered)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.inner.algorithm()
    }
}

pub fn expired_self_signed_certificates(key: &KeyPair) -> Arc<SelfSignedCertificates> {
    let failing = Arc::new(AtomicBool::new(false));
    let signer = DeviceSigner::new(
        key.public_key_raw().try_into().unwrap(),
        Arc::new(FailingAfterIssueKey {
            inner: software_signer(key).key(),
            failing: failing.clone(),
        }),
    );
    let issued_at =
        UnixTime::since_unix_epoch(Duration::from_secs(UnixTime::now().as_secs() - 2 * 60 * 60));
    let certificates = SelfSignedCertificates::new(signer, issued_at).unwrap();
    failing.store(true, Ordering::Relaxed);
    Arc::new(certificates)
}

pub struct IssuedCertificate {
    pub der: CertificateDer<'static>,
    pub pem: String,
}

#[derive(Clone)]
pub enum Behavior {
    Tunnel,
    TunnelWithBanner(&'static [u8]),
    Status(u16),
    Hang,
    Close,
}

pub struct UpstreamProxy {
    pub addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<String>>>,
    client_certificates: Arc<Mutex<Vec<Vec<CertificateDer<'static>>>>>,
    negotiated_groups: Arc<Mutex<Vec<NamedGroup>>>,
    handshake_errors: Arc<Mutex<Vec<String>>>,
}

impl UpstreamProxy {
    pub async fn start(config: Arc<ServerConfig>, behavior: Behavior) -> Self {
        let listener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
        Self::serve(listener, config, behavior)
    }

    pub fn serve(listener: TcpListener, config: Arc<ServerConfig>, behavior: Behavior) -> Self {
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let acceptor = TlsAcceptor::from(config);
        let client_certificates = Arc::new(Mutex::new(Vec::new()));
        let negotiated_groups = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let presented = client_certificates.clone();
        let negotiated = negotiated_groups.clone();
        let handshake_errors = Arc::new(Mutex::new(Vec::new()));
        let failed = handshake_errors.clone();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counted = accepted.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                counted.fetch_add(1, Ordering::Relaxed);
                let acceptor = acceptor.clone();
                let behavior = behavior.clone();
                let recorded = recorded.clone();
                let presented = presented.clone();
                let negotiated = negotiated.clone();
                let failed = failed.clone();
                tokio::spawn(async move {
                    let mut tls = match acceptor.accept(stream).await {
                        Ok(tls) => tls,
                        Err(error) => {
                            failed.lock().unwrap().push(error.to_string());
                            return;
                        }
                    };
                    if let Some(group) = tls.get_ref().1.negotiated_key_exchange_group() {
                        negotiated.lock().unwrap().push(group.name());
                    }
                    if let Some(chain) = tls.get_ref().1.peer_certificates() {
                        presented.lock().unwrap().push(chain.to_vec());
                    }
                    let (head, rest) = read_head(&mut tls).await;
                    if head.is_empty() {
                        return;
                    }
                    recorded.lock().unwrap().push(head.clone());
                    match behavior {
                        Behavior::Tunnel => tunnel(tls, &head, &rest, b"").await,
                        Behavior::TunnelWithBanner(banner) => {
                            tunnel(tls, &head, &rest, banner).await
                        }
                        Behavior::Status(code) => {
                            let response = format!(
                                "HTTP/1.1 {code} Fixture\r\nProxy-Authenticate: Basic realm=\"{SECRET}\"\r\nContent-Length: {}\r\n\r\n{SECRET}",
                                SECRET.len()
                            );
                            let _ = tls.write_all(response.as_bytes()).await;
                            let _ = tls.shutdown().await;
                        }
                        Behavior::Hang => {
                            tokio::time::sleep(Duration::from_secs(3600)).await;
                            drop(tls);
                        }
                        Behavior::Close => drop(tls),
                    }
                });
            }
        });
        Self {
            addr,
            accepted,
            requests,
            client_certificates,
            negotiated_groups,
            handshake_errors,
        }
    }

    pub async fn wait_for_handshake_errors(&self, count: usize) -> Vec<String> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let errors = self.handshake_errors.lock().unwrap().clone();
            if errors.len() >= count {
                return errors;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "expected {count} failed handshakes, got {errors:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    pub fn accepted(&self) -> usize {
        self.accepted.load(Ordering::Relaxed)
    }

    pub fn negotiated_groups(&self) -> Vec<NamedGroup> {
        self.negotiated_groups.lock().unwrap().clone()
    }

    pub fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }

    pub fn client_certificates(&self) -> Vec<Vec<CertificateDer<'static>>> {
        self.client_certificates.lock().unwrap().clone()
    }
}

async fn tunnel<S>(mut upstream: S, head: &str, rest: &[u8], banner: &[u8])
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let target = head.split(' ').nth(1).unwrap().to_owned();
    let mut target = TcpStream::connect(target).await.unwrap();
    let mut response = b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec();
    response.extend_from_slice(banner);
    upstream.write_all(&response).await.unwrap();
    target.write_all(rest).await.unwrap();
    let _ = tokio::io::copy_bidirectional(&mut upstream, &mut target).await;
}

pub async fn read_head<S>(stream: &mut S) -> (String, Vec<u8>)
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(end + 4);
            return (String::from_utf8(buf).unwrap(), rest);
        }
        let n = stream.read(&mut chunk).await.unwrap_or(0);
        if n == 0 {
            return (String::from_utf8_lossy(&buf).into_owned(), Vec::new());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

pub async fn echo_server() -> SocketAddr {
    serve(|mut stream| async move {
        let (mut reader, mut writer) = stream.split();
        let _ = tokio::io::copy(&mut reader, &mut writer).await;
        let _ = writer.shutdown().await;
    })
    .await
}

pub async fn reply_after_eof_server() -> SocketAddr {
    serve(|mut stream| async move {
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        received.reverse();
        stream.write_all(&received).await.unwrap();
        stream.shutdown().await.unwrap();
    })
    .await
}

pub async fn drip_server(chunk: &'static [u8], count: usize, every: Duration) -> SocketAddr {
    serve(move |mut stream| async move {
        for _ in 0..count {
            tokio::time::sleep(every).await;
            stream.write_all(chunk).await.unwrap();
        }
        stream.shutdown().await.unwrap();
    })
    .await
}

pub async fn silent_server() -> SocketAddr {
    serve(|stream| async move {
        tokio::time::sleep(Duration::from_secs(3600)).await;
        drop(stream);
    })
    .await
}

pub async fn tls_echo_origin(config: Arc<ServerConfig>) -> SocketAddr {
    let acceptor = TlsAcceptor::from(config);
    serve(move |stream| {
        let acceptor = acceptor.clone();
        async move {
            let Ok(tls) = acceptor.accept(stream).await else {
                return;
            };
            let (mut reader, mut writer) = tokio::io::split(tls);
            let _ = tokio::io::copy(&mut reader, &mut writer).await;
            let _ = writer.shutdown().await;
        }
    })
    .await
}

async fn serve<F, Fut>(handler: F) -> SocketAddr
where
    F: Fn(TcpStream) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(handler(stream));
        }
    });
    addr
}

pub async fn unused_port() -> SocketAddr {
    let listener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
    listener.local_addr().unwrap()
}

pub fn agent_config(upstream: SocketAddr, roots: RootCertStore, server_name: &str) -> Config {
    Config {
        listen: SocketAddr::from((LOOPBACK, 0)),
        allow_non_loopback: false,
        upstream: Upstream {
            host: upstream.ip().to_string(),
            port: upstream.port(),
            server_name: ServerName::try_from(server_name.to_owned()).unwrap(),
            roots,
        },
        tls_mode: TlsMode::default(),
        client_certificate: None,
        limits: Limits::default(),
    }
}

pub async fn start_agent(config: Config) -> SocketAddr {
    let proxy = Proxy::bind(config).await.unwrap();
    let addr = proxy.local_addr();
    tokio::spawn(proxy.run());
    addr
}

pub struct Response {
    pub status: u16,
    pub head: String,
    pub rest: Vec<u8>,
}

pub async fn send(agent: SocketAddr, request: &[u8]) -> (TcpStream, Response) {
    let mut stream = TcpStream::connect(agent).await.unwrap();
    stream.write_all(request).await.unwrap();
    let response = read_response(&mut stream).await;
    (stream, response)
}

pub async fn read_response(stream: &mut TcpStream) -> Response {
    let (head, rest) = read_head(stream).await;
    let status = head
        .strip_prefix("HTTP/1.1 ")
        .and_then(|rest| rest.get(..3))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    Response { status, head, rest }
}

pub fn connect_request(target: &str) -> Vec<u8> {
    format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").into_bytes()
}

pub async fn open_tunnel(agent: SocketAddr, target: SocketAddr) -> TcpStream {
    let (stream, response) = send(agent, &connect_request(&target.to_string())).await;
    assert_eq!(response.status, 200, "{}", response.head);
    assert!(response.rest.is_empty());
    stream
}

pub async fn inner_tls(
    stream: TcpStream,
    config: Arc<ClientConfig>,
    name: &str,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    TlsConnector::from(config)
        .connect(ServerName::try_from(name.to_owned()).unwrap(), stream)
        .await
        .unwrap()
}

pub fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 7 + i / 256) % 256) as u8).collect()
}

pub async fn read_to_end_within(stream: &mut TcpStream, limit: Duration) -> Vec<u8> {
    let mut received = Vec::new();
    let result = tokio::time::timeout(limit, stream.read_to_end(&mut received))
        .await
        .unwrap_or_else(|_| panic!("connection was not closed in time, received {received:?}"));
    if let Err(error) = result {
        panic!("read failed after receiving {received:?}: {error}");
    }
    received
}
