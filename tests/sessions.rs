#[allow(dead_code)]
mod fixture;

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fixture::*;
use gateinto::clock::unix_now;
use gateinto::config::GatewayName;
use gateinto::identity::certificates::SelfSignedCertificates;
use gateinto::identity::client_cert::ClientCertificate;
use gateinto::identity::encoding::sha256_fingerprint;
use gateinto::identity::x509::parse_certificate;
use gateinto::ipc::{BrowserKind, SessionAuth, SessionInfo, SessionRoute};
use gateinto::proxy::Config;
use gateinto::sessions::{SessionConfig, SessionError, SessionId, SessionKind, SessionManager};
use rcgen::{KeyPair, PublicKeyData};
use rustls::pki_types::{CertificateDer, UnixTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const CLOSE_WITHIN: Duration = Duration::from_secs(5);
const ROUNDS: usize = 3;

fn gateway(name: &str) -> GatewayName {
    name.parse().unwrap()
}

fn device_session(name: &str, proxy: Config) -> SessionConfig {
    SessionConfig {
        kind: SessionKind::Device,
        gateway: gateway(name),
        proxy,
    }
}

fn self_signed(key: &KeyPair, required: bool) -> ClientCertificate {
    let certificates = SelfSignedCertificates::new(software_signer(key), UnixTime::now()).unwrap();
    ClientCertificate::SelfSigned {
        certificates: Arc::new(certificates),
        required,
    }
}

struct SpkiUpstream {
    ca: TestCa,
    upstream: UpstreamProxy,
}

impl SpkiUpstream {
    async fn start(key: &KeyPair) -> Self {
        let ca = TestCa::new();
        let upstream = UpstreamProxy::start(
            ca.server_config_trusting_client_spki(PROXY_NAME, key.subject_public_key_info()),
            Behavior::Tunnel,
        )
        .await;
        Self { ca, upstream }
    }

    fn config(&self, certificate: &ClientCertificate) -> Config {
        let mut config = agent_config(self.upstream.addr, self.ca.roots(), PROXY_NAME);
        config.client_certificate = Some(certificate.clone());
        config
    }
}

fn local_addr(sessions: &SessionManager, id: SessionId) -> SocketAddr {
    sessions.session(id).unwrap().local_addr()
}

async fn echo_once(agent: SocketAddr, target: SocketAddr, message: &[u8]) {
    let mut stream = open_tunnel(agent, target).await;
    stream.write_all(message).await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(read_to_end_within(&mut stream, CLOSE_WITHIN).await, message);
}

async fn echo_open(stream: &mut TcpStream, message: &[u8]) {
    stream.write_all(message).await.unwrap();
    let mut echoed = vec![0; message.len()];
    tokio::time::timeout(CLOSE_WITHIN, stream.read_exact(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(echoed, message);
}

async fn assert_closed(stream: &mut TcpStream) {
    let mut buf = [0; 64];
    match tokio::time::timeout(CLOSE_WITHIN, stream.read(&mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("closed tunnel still delivered {:?}", &buf[..n]),
        Err(_) => panic!("tunnel was not closed in time"),
    }
}

async fn assert_refused(addr: SocketAddr) {
    let error = TcpStream::connect(addr).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ConnectionRefused, "{error}");
}

fn last_certificate(upstream: &UpstreamProxy) -> CertificateDer<'static> {
    let presented = upstream.client_certificates();
    let chain = presented.last().expect("no client certificate presented");
    assert_eq!(chain.len(), 1);
    chain[0].clone()
}

#[tokio::test(flavor = "multi_thread")]
async fn sessions_on_one_gateway_present_their_own_self_signed_certificates() {
    let key = KeyPair::generate().unwrap();
    let source = self_signed(&key, true);
    let ClientCertificate::SelfSigned { certificates, .. } = &source else {
        unreachable!()
    };
    let source_sha256 = sha256_fingerprint(&certificates.current().cert[0]);
    let setup = SpkiUpstream::start(&key).await;
    let target = echo_server().await;
    let mut sessions = SessionManager::new();
    let first = sessions
        .start(device_session("office", setup.config(&source)))
        .await
        .unwrap();
    let second = sessions
        .start(device_session("office", setup.config(&source)))
        .await
        .unwrap();
    assert_ne!(first, second);
    assert_ne!(local_addr(&sessions, first), local_addr(&sessions, second));

    let mut seen = Vec::new();
    for _ in 0..ROUNDS {
        for id in [first, second, second, first] {
            echo_once(local_addr(&sessions, id), target, b"isolated").await;
            seen.push((id, sha256_fingerprint(&last_certificate(&setup.upstream))));
        }
    }

    let fingerprint = |session| {
        let mut fingerprints: Vec<&String> = seen
            .iter()
            .filter(|(id, _)| *id == session)
            .map(|(_, fingerprint)| fingerprint)
            .collect();
        fingerprints.dedup();
        assert_eq!(fingerprints.len(), 1, "{session} swapped certificates");
        fingerprints[0].clone()
    };
    let (first_sha256, second_sha256) = (fingerprint(first), fingerprint(second));
    assert_ne!(first_sha256, second_sha256);
    assert_ne!(first_sha256, source_sha256);
    assert_ne!(second_sha256, source_sha256);
    let spki = key.subject_public_key_info();
    for chain in setup.upstream.client_certificates() {
        assert_eq!(parse_certificate(&chain[0]).unwrap().spki, spki);
    }
    assert_eq!(setup.upstream.requests().len(), 4 * ROUNDS);
}

#[tokio::test(flavor = "multi_thread")]
async fn sessions_on_two_gateways_reach_only_their_own_upstream() {
    let key = KeyPair::generate().unwrap();
    let source = self_signed(&key, true);
    let office = SpkiUpstream::start(&key).await;
    let home = SpkiUpstream::start(&key).await;
    let target = echo_server().await;
    let mut sessions = SessionManager::new();
    let to_office = sessions
        .start(device_session("office", office.config(&source)))
        .await
        .unwrap();
    let to_home = sessions
        .start(device_session("home", home.config(&source)))
        .await
        .unwrap();
    assert_eq!(
        sessions.session(to_office).unwrap().gateway(),
        &gateway("office")
    );
    assert_eq!(
        sessions.session(to_home).unwrap().gateway(),
        &gateway("home")
    );
    assert_eq!(
        sessions.session(to_home).unwrap().kind(),
        SessionKind::Device
    );

    for _ in 0..ROUNDS {
        echo_once(local_addr(&sessions, to_office), target, b"office").await;
        echo_once(local_addr(&sessions, to_home), target, b"home").await;
    }

    assert_eq!(office.upstream.requests().len(), ROUNDS);
    assert_eq!(home.upstream.requests().len(), ROUNDS);
    let office_sha256 = sha256_fingerprint(&last_certificate(&office.upstream));
    let home_sha256 = sha256_fingerprint(&last_certificate(&home.upstream));
    assert_ne!(office_sha256, home_sha256);
    for (upstream, expected) in [(&office, &office_sha256), (&home, &home_sha256)] {
        for chain in upstream.upstream.client_certificates() {
            assert_eq!(&sha256_fingerprint(&chain[0]), expected);
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn closing_a_session_refuses_its_port_while_the_other_keeps_working() {
    let key = KeyPair::generate().unwrap();
    let source = self_signed(&key, true);
    let setup = SpkiUpstream::start(&key).await;
    let target = echo_server().await;
    let mut sessions = SessionManager::new();
    let closing = sessions
        .start(device_session("office", setup.config(&source)))
        .await
        .unwrap();
    let staying = sessions
        .start(device_session("office", setup.config(&source)))
        .await
        .unwrap();
    let closing_addr = local_addr(&sessions, closing);
    echo_once(closing_addr, target, b"before").await;
    let closed_sha256 = sha256_fingerprint(&last_certificate(&setup.upstream));

    assert!(sessions.close(closing).await);

    assert!(sessions.session(closing).is_none());
    assert!(!sessions.close(closing).await);
    let accepted = setup.upstream.accepted();
    assert_refused(closing_addr).await;
    assert_eq!(setup.upstream.accepted(), accepted);
    for _ in 0..ROUNDS {
        echo_once(local_addr(&sessions, staying), target, b"after").await;
        let sha256 = sha256_fingerprint(&last_certificate(&setup.upstream));
        assert_ne!(sha256, closed_sha256);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn closing_a_session_aborts_its_established_tunnels() {
    let key = KeyPair::generate().unwrap();
    let source = self_signed(&key, true);
    let setup = SpkiUpstream::start(&key).await;
    let target = echo_server().await;
    let mut sessions = SessionManager::new();
    let closing = sessions
        .start(device_session("office", setup.config(&source)))
        .await
        .unwrap();
    let staying = sessions
        .start(device_session("office", setup.config(&source)))
        .await
        .unwrap();
    let mut doomed = open_tunnel(local_addr(&sessions, closing), target).await;
    let mut surviving = open_tunnel(local_addr(&sessions, staying), target).await;
    echo_open(&mut doomed, b"open").await;
    echo_open(&mut surviving, b"open").await;

    sessions.close(closing).await;

    assert_closed(&mut doomed).await;
    echo_open(&mut surviving, b"still open").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn closing_every_session_refuses_every_port() {
    let ca = TestCa::new();
    let upstream = UpstreamProxy::start(ca.server_config(PROXY_NAME), Behavior::Tunnel).await;
    let mut sessions = SessionManager::new();
    let mut addrs = Vec::new();
    for _ in 0..2 {
        let config = agent_config(upstream.addr, ca.roots(), PROXY_NAME);
        let id = sessions
            .start(device_session("office", config))
            .await
            .unwrap();
        addrs.push(local_addr(&sessions, id));
    }

    sessions.close_all().await;

    for addr in addrs {
        assert_refused(addr).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_required_self_signed_certificate_that_cannot_be_issued_stops_the_session_start() {
    let key = KeyPair::generate().unwrap();
    let setup = SpkiUpstream::start(&key).await;
    let mut sessions = SessionManager::new();
    let source = ClientCertificate::SelfSigned {
        certificates: expired_self_signed_certificates(&key),
        required: true,
    };

    let error = sessions
        .start(device_session("office", setup.config(&source)))
        .await
        .unwrap_err();

    assert!(matches!(error, SessionError::Certificate(_)), "{error}");
    assert!(
        error
            .to_string()
            .contains("issuing the session's self-signed client certificate failed"),
        "{error}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_optional_self_signed_certificate_that_cannot_be_issued_starts_without_one() {
    let key = KeyPair::generate().unwrap();
    let ca = TestCa::new();
    let client_ca = TestCa::new();
    let upstream = UpstreamProxy::start(
        ca.server_config_requesting_client_certificates(PROXY_NAME, &client_ca),
        Behavior::Tunnel,
    )
    .await;
    let mut config = agent_config(upstream.addr, ca.roots(), PROXY_NAME);
    config.client_certificate = Some(ClientCertificate::SelfSigned {
        certificates: expired_self_signed_certificates(&key),
        required: false,
    });
    let mut sessions = SessionManager::new();

    let id = sessions
        .start(device_session("office", config))
        .await
        .unwrap();
    echo_once(
        local_addr(&sessions, id),
        echo_server().await,
        b"no client auth",
    )
    .await;

    assert!(upstream.client_certificates().is_empty());
    assert_eq!(upstream.requests().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_refuses_a_non_loopback_listen_address() {
    let ca = TestCa::new();
    let mut config = agent_config(unused_port().await, ca.roots(), PROXY_NAME);
    config.listen = "0.0.0.0:0".parse().unwrap();
    let mut sessions = SessionManager::new();

    let error = sessions
        .start(device_session("office", config))
        .await
        .unwrap_err();

    assert!(matches!(error, SessionError::Proxy(_)), "{error}");
    assert!(
        error
            .to_string()
            .contains("--unsafe-allow-non-loopback-listen"),
        "{error}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_describes_itself_for_the_list_with_its_open_tunnels() {
    let ca = TestCa::new();
    let upstream = UpstreamProxy::start(ca.server_config(PROXY_NAME), Behavior::Tunnel).await;
    let target = echo_server().await;
    let before = unix_now();
    let mut sessions = SessionManager::new();
    let id = sessions
        .start(device_session(
            "office",
            agent_config(upstream.addr, ca.roots(), PROXY_NAME),
        ))
        .await
        .unwrap();
    let session = sessions.session(id).unwrap();

    let info = session.info(Some(BrowserKind::Edge));
    assert!((before..=unix_now()).contains(&info.started), "{info:?}");
    assert_eq!(
        info,
        SessionInfo {
            id: id.to_string().parse().unwrap(),
            kind: SessionKind::Device,
            gateway: "office".to_owned(),
            upstream: upstream.addr.to_string(),
            listen: session.local_addr(),
            route: SessionRoute::All,
            auth: SessionAuth::None,
            started: info.started,
            tunnels: 0,
            browser: Some(BrowserKind::Edge),
        }
    );
    let mut stream = open_tunnel(session.local_addr(), target).await;
    echo_open(&mut stream, b"open").await;
    assert_eq!(session.info(None).tunnels, 1);
    stream.shutdown().await.unwrap();
    assert_eq!(read_to_end_within(&mut stream, CLOSE_WITHIN).await, b"");
    let deadline = Instant::now() + CLOSE_WITHIN;
    while session.info(None).tunnels != 0 {
        assert!(Instant::now() < deadline, "the tunnel is still counted");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
