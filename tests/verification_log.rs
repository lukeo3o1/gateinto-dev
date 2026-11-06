#[allow(dead_code)]
mod fixture;
#[allow(dead_code)]
mod h2_fixture;

use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fixture::*;
use gateinto::identity::client_cert::ClientCertificate;
use gateinto::identity::encoding::sha256_fingerprint;
use gateinto::ipc::Response;
use gateinto::logbook::Logbook;
use gateinto::sessions::{SessionConfig, SessionId, SessionKind, SessionManager};
use rcgen::KeyPair;
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::sign::CertifiedKey;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::{Layer, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn fixed(certificate: &IssuedCertificate, key: &KeyPair) -> ClientCertificate {
    let der = PrivatePkcs8KeyDer::from(key.serialize_der()).into();
    let signer = rustls::crypto::aws_lc_rs::sign::any_ecdsa_type(&der).unwrap();
    Arc::new(CertifiedKey::new(vec![certificate.der.clone()], signer)).into()
}

async fn start(
    sessions: &mut SessionManager,
    upstream: SocketAddr,
    ca: &TestCa,
    certificate: &ClientCertificate,
) -> SessionId {
    let mut config = agent_config(upstream, ca.roots(), PROXY_NAME);
    config.client_certificate = Some(certificate.clone());
    sessions
        .start(SessionConfig {
            kind: SessionKind::Browser,
            gateway: "office".parse().unwrap(),
            proxy: config,
        })
        .await
        .unwrap()
}

async fn refused(sessions: &SessionManager, id: SessionId, target: &str) -> String {
    let session = sessions.session(id).unwrap();
    let (mut stream, response) = send(session.local_addr(), &connect_request(target)).await;
    assert_eq!(response.status, 502, "{}", response.head);
    let rest = read_to_end_within(&mut stream, Duration::from_secs(5)).await;
    assert!(session.info(None).verification);
    let verification = session.verifications().get().unwrap();
    assert!(
        CHALLENGE_CODES.contains(&verification.user_code.as_str()),
        "{verification:?}"
    );
    format!("{}{}", response.head, String::from_utf8_lossy(&rest))
}

#[tokio::test(flavor = "multi_thread")]
async fn logs_never_contain_the_verification_link_code_or_challenge() {
    let captured = Captured::default();
    let writer = captured.clone();
    let logbook = Logbook::default();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .with_filter(LevelFilter::TRACE),
        )
        .with(logbook.layer())
        .init();
    let ca = TestCa::new();
    let client_ca = TestCa::new();
    let key = KeyPair::generate().unwrap();
    let issued = client_ca.issue_client_certificate(&key);
    let certificate = fixed(&issued, &key);
    let fingerprint = sha256_fingerprint(&issued.der);
    let http1 = UpstreamProxy::start(
        ca.server_config_requesting_client_certificates(PROXY_NAME, &client_ca),
        Behavior::Challenge(CHALLENGE_CODES[0]),
    )
    .await;
    let http2 = h2_fixture::Server::start(
        ca.server_config_requesting_client_certificates(PROXY_NAME, &client_ca),
        10,
    )
    .await;
    let mut sessions = SessionManager::new();
    let over_http1 = start(&mut sessions, http1.addr, &ca, &certificate).await;
    let over_http2 = start(&mut sessions, http2.addr, &ca, &certificate).await;

    let mut answers = vec![refused(&sessions, over_http1, "example.test:443").await];
    for _ in 0..2 {
        answers.push(refused(&sessions, over_http2, "challenge.example.test:443").await);
    }
    assert_eq!(http2.accepted.load(std::sync::atomic::Ordering::SeqCst), 1);
    sessions.close_all().await;

    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    for expected in [
        "gateway asks for interactive verification",
        "verification challenge stored",
    ] {
        assert!(logs.contains(expected), "{expected} missing from\n{logs}");
    }
    assert!(logs.contains(" h2::"), "no h2 trace in\n{logs}");
    let Response::Ok(page) = logbook.response(0) else {
        panic!("a log response is ok");
    };
    let page = page.join("\n");
    let values: Vec<String> = CHALLENGE_CODES
        .iter()
        .map(|code| challenge_value(&issued.der, code))
        .collect();
    let mut secrets = vec![
        CHALLENGE_URI,
        "verify.test",
        "Gateinto auth_uri",
        "user_code=",
        SECRET,
        fingerprint.as_str(),
    ];
    secrets.extend(CHALLENGE_CODES);
    secrets.extend(values.iter().map(String::as_str));
    for secret in secrets {
        assert!(!logs.contains(secret), "{secret} leaked into\n{logs}");
        assert!(!page.contains(secret), "{secret} reached the log page");
        for answer in &answers {
            assert!(!answer.contains(secret), "{secret} reached the client");
        }
    }
}
