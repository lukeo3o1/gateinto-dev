#[allow(dead_code)]
mod fixture;

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use fixture::*;
use gateinto::identity::certificates::SelfSignedCertificates;
use gateinto::identity::client_cert::ClientCertificate;
use gateinto::identity::encoding::sha256_fingerprint;
use gateinto::proxy::{Config, FailureLimit, LocalAuth};
use gateinto::sessions::{SessionConfig, SessionId, SessionKind, SessionManager};
use rcgen::{KeyPair, PublicKeyData};
use rustls::pki_types::UnixTime;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

const CLOSE_WITHIN: Duration = Duration::from_secs(5);

struct Setup {
    ca: TestCa,
    upstream: UpstreamProxy,
    target: SocketAddr,
}

impl Setup {
    async fn start() -> Self {
        let ca = TestCa::new();
        let upstream = UpstreamProxy::start(ca.server_config(PROXY_NAME), Behavior::Tunnel).await;
        Self {
            ca,
            upstream,
            target: echo_server().await,
        }
    }

    fn config(&self, local_auth: LocalAuth) -> Config {
        let mut config = agent_config(self.upstream.addr, self.ca.roots(), PROXY_NAME);
        config.local_auth = local_auth;
        config
    }

    fn browser(&self) -> SessionConfig {
        session(SessionKind::Browser, self.config(LocalAuth::BasicTofu))
    }

    fn browser_limited(&self, max_failures: u32) -> SessionConfig {
        let mut config = self.config(LocalAuth::BasicTofu);
        config.limits.local_auth_failures = FailureLimit {
            max_failures,
            window: Duration::from_secs(600),
        };
        session(SessionKind::Browser, config)
    }

    fn connect(&self, authorization: Option<&str>) -> Vec<u8> {
        connect_with(&self.target.to_string(), authorization)
    }
}

fn session(kind: SessionKind, proxy: Config) -> SessionConfig {
    SessionConfig {
        kind,
        gateway: "office".parse().unwrap(),
        proxy,
    }
}

fn addr(sessions: &SessionManager, id: SessionId) -> SocketAddr {
    sessions.session(id).unwrap().local_addr()
}

fn realm(sessions: &SessionManager, id: SessionId) -> String {
    sessions.session(id).unwrap().realm().unwrap().to_owned()
}

async fn status(agent: SocketAddr, request: &[u8]) -> u16 {
    send(agent, request).await.1.status
}

async fn echo_through(agent: SocketAddr, request: &[u8], message: &[u8]) {
    let (mut stream, response) = send(agent, request).await;
    assert_eq!(response.status, 200, "{}", response.head);
    stream.write_all(message).await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(read_to_end_within(&mut stream, CLOSE_WITHIN).await, message);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_connect_without_credentials_is_challenged_with_the_session_realm() {
    let setup = Setup::start().await;
    let mut sessions = SessionManager::new();
    let id = sessions.start(setup.browser()).await.unwrap();
    let realm = realm(&sessions, id);
    assert!(realm.starts_with("Gateinto "), "{realm}");

    let (mut stream, response) = send(addr(&sessions, id), &setup.connect(None)).await;

    assert_eq!(
        response.head,
        format!(
            "HTTP/1.1 407 Proxy Authentication Required\r\n\
             Proxy-Authenticate: Basic realm=\"{realm}\", charset=\"UTF-8\"\r\n\
             Connection: close\r\nContent-Length: 0\r\n\r\n"
        )
    );
    assert!(
        read_to_end_within(&mut stream, CLOSE_WITHIN)
            .await
            .is_empty()
    );
    assert_eq!(setup.upstream.accepted(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_first_credential_binds_and_keeps_working_across_many_tunnels() {
    let setup = Setup::start().await;
    let mut sessions = SessionManager::new();
    let id = sessions.start(setup.browser()).await.unwrap();
    let agent = addr(&sessions, id);
    let credential = basic("alice", "correct horse");

    for round in 0..10 {
        echo_through(agent, &setup.connect(Some(&credential)), b"hello").await;
        assert_eq!(setup.upstream.requests().len(), round + 1);
    }
    let concurrent: Vec<_> = (0..8)
        .map(|_| {
            let request = setup.connect(Some(&credential));
            tokio::spawn(async move { echo_through(agent, &request, b"parallel").await })
        })
        .collect();
    for task in concurrent {
        task.await.unwrap();
    }

    for request in setup.upstream.requests() {
        assert!(
            !request.to_ascii_lowercase().contains("proxy-authorization"),
            "{request}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_different_credential_is_challenged_after_binding() {
    let setup = Setup::start().await;
    let mut sessions = SessionManager::new();
    let id = sessions.start(setup.browser()).await.unwrap();
    let agent = addr(&sessions, id);
    echo_through(agent, &setup.connect(Some(&basic("alice", "pw"))), b"bound").await;
    let accepted = setup.upstream.accepted();

    for other in [
        basic("alice", "other"),
        basic("bob", "pw"),
        basic("alice", "pw "),
        basic("Alice", "pw"),
    ] {
        let (_, response) = send(agent, &setup.connect(Some(&other))).await;
        assert_eq!(response.status, 407, "{other}");
        assert!(
            response
                .head
                .contains(&format!("realm=\"{}\"", realm(&sessions, id))),
            "{}",
            response.head
        );
    }
    assert_eq!(setup.upstream.accepted(), accepted);
    echo_through(agent, &setup.connect(Some(&basic("alice", "pw"))), b"still").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_credentials_are_bad_requests_and_bind_nothing() {
    let setup = Setup::start().await;
    let mut sessions = SessionManager::new();
    let id = sessions.start(setup.browser_limited(100)).await.unwrap();
    let agent = addr(&sessions, id);
    let target = setup.target.to_string();
    let too_long = basic("u", &"p".repeat(1024));

    for value in [
        "Basic",
        "Basic !!!!",
        "Basic dTpw=",
        "Basic dXNlcg==",
        "Basic dTo=",
        "Basic dTpwAA==",
        too_long.as_str(),
    ] {
        assert_eq!(
            status(agent, &setup.connect(Some(value))).await,
            400,
            "{value}"
        );
    }
    let duplicate = format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: {0}\r\nProxy-Authorization: {0}\r\n\r\n",
        basic("u", "p")
    );
    assert_eq!(status(agent, duplicate.as_bytes()).await, 400);
    assert_eq!(status(agent, &setup.connect(Some("Bearer abc"))).await, 407);
    assert_eq!(setup.upstream.accepted(), 0);

    echo_through(agent, &setup.connect(Some(&basic("u", "p"))), b"first").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_first_credentials_bind_exactly_one() {
    const CLIENTS: usize = 32;
    let setup = Setup::start().await;
    let mut sessions = SessionManager::new();
    let id = sessions
        .start(setup.browser_limited(10 * CLIENTS as u32))
        .await
        .unwrap();
    let agent = addr(&sessions, id);
    let credentials: Vec<String> = (0..CLIENTS)
        .map(|i| basic("racer", &format!("pw{i}")))
        .collect();

    let mut streams = Vec::new();
    for credential in &credentials {
        let stream = TcpStream::connect(agent).await.unwrap();
        streams.push((stream, setup.connect(Some(credential))));
    }
    let barrier = Arc::new(tokio::sync::Barrier::new(CLIENTS));
    let racing: Vec<_> = streams
        .into_iter()
        .map(|(mut stream, request)| {
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                stream.write_all(&request).await.unwrap();
                read_response(&mut stream).await.status
            })
        })
        .collect();
    let mut statuses = Vec::new();
    for task in racing {
        statuses.push(task.await.unwrap());
    }

    let winners: Vec<usize> = (0..CLIENTS).filter(|&i| statuses[i] == 200).collect();
    assert_eq!(winners.len(), 1, "{statuses:?}");
    assert!(
        statuses
            .iter()
            .all(|&status| status == 200 || status == 407),
        "{statuses:?}"
    );
    for (i, credential) in credentials.iter().enumerate() {
        let expected = if i == winners[0] { 200 } else { 407 };
        assert_eq!(
            status(agent, &setup.connect(Some(credential))).await,
            expected
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn repeated_failures_are_rate_limited() {
    let setup = Setup::start().await;
    let mut sessions = SessionManager::new();
    let id = sessions.start(setup.browser_limited(3)).await.unwrap();
    let agent = addr(&sessions, id);
    let right = basic("alice", "right");
    echo_through(agent, &setup.connect(Some(&right)), b"bound").await;

    assert_eq!(status(agent, &setup.connect(None)).await, 407);
    for wrong in ["one", "two"] {
        assert_eq!(
            status(agent, &setup.connect(Some(&basic("alice", wrong)))).await,
            407
        );
    }
    assert_eq!(status(agent, &setup.connect(Some("Basic !"))).await, 400);

    for request in [
        setup.connect(Some(&right)),
        setup.connect(Some(&basic("alice", "four"))),
        setup.connect(None),
    ] {
        let (_, response) = send(agent, &request).await;
        assert_eq!(response.status, 429, "{}", response.head);
        let retry_after: u64 = response
            .head
            .lines()
            .find_map(|line| line.strip_prefix("Retry-After: "))
            .unwrap()
            .parse()
            .unwrap();
        assert!((1..=600).contains(&retry_after), "{retry_after}");
    }
    assert_eq!(setup.upstream.requests().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_session_after_close_starts_with_fresh_state() {
    let setup = Setup::start().await;
    let mut sessions = SessionManager::new();
    let taken = sessions.start(setup.browser()).await.unwrap();
    let (taken_addr, taken_realm) = (addr(&sessions, taken), realm(&sessions, taken));
    echo_through(
        taken_addr,
        &setup.connect(Some(&basic("intruder", "first"))),
        b"taken",
    )
    .await;
    assert_eq!(
        status(taken_addr, &setup.connect(Some(&basic("me", "mine")))).await,
        407
    );

    assert!(sessions.close(taken).await);
    let fresh = sessions.start(setup.browser()).await.unwrap();

    let fresh_addr = addr(&sessions, fresh);
    assert_ne!(fresh, taken);
    assert_ne!(fresh_addr, taken_addr);
    assert_ne!(realm(&sessions, fresh), taken_realm);
    let error = TcpStream::connect(taken_addr).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ConnectionRefused, "{error}");
    echo_through(
        fresh_addr,
        &setup.connect(Some(&basic("me", "mine"))),
        b"mine",
    )
    .await;
    assert_eq!(
        status(
            fresh_addr,
            &setup.connect(Some(&basic("intruder", "first")))
        )
        .await,
        407
    );
}

fn self_signed(key: &KeyPair) -> ClientCertificate {
    let certificates = SelfSignedCertificates::new(software_signer(key), UnixTime::now()).unwrap();
    ClientCertificate::SelfSigned {
        certificates: Arc::new(certificates),
        required: true,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn browser_and_device_sessions_share_neither_certificates_nor_auth_state() {
    let key = KeyPair::generate().unwrap();
    let source = self_signed(&key);
    let ca = TestCa::new();
    let upstream = UpstreamProxy::start(
        ca.server_config_trusting_client_spki(PROXY_NAME, key.subject_public_key_info()),
        Behavior::Tunnel,
    )
    .await;
    let target = echo_server().await.to_string();
    let config = |local_auth| {
        let mut config = agent_config(upstream.addr, ca.roots(), PROXY_NAME);
        config.client_certificate = Some(source.clone());
        config.local_auth = local_auth;
        config
    };
    let mut sessions = SessionManager::new();
    let device = sessions
        .start(session(SessionKind::Device, config(LocalAuth::None)))
        .await
        .unwrap();
    let first = sessions
        .start(session(SessionKind::Browser, config(LocalAuth::BasicTofu)))
        .await
        .unwrap();
    let second = sessions
        .start(session(SessionKind::Browser, config(LocalAuth::BasicTofu)))
        .await
        .unwrap();
    assert_eq!(sessions.session(device).unwrap().realm(), None);
    assert_eq!(
        sessions.session(first).unwrap().kind(),
        SessionKind::Browser
    );
    assert_ne!(realm(&sessions, first), realm(&sessions, second));

    let last_fingerprint = || {
        let chains = upstream.client_certificates();
        sha256_fingerprint(&chains.last().unwrap()[0])
    };
    let one = basic("one", "pw");
    let two = basic("two", "pw");
    echo_through(
        addr(&sessions, first),
        &connect_with(&target, Some(&one)),
        b"1",
    )
    .await;
    let first_sha256 = last_fingerprint();
    echo_through(
        addr(&sessions, second),
        &connect_with(&target, Some(&two)),
        b"2",
    )
    .await;
    let second_sha256 = last_fingerprint();
    echo_through(addr(&sessions, device), &connect_with(&target, None), b"d").await;
    let device_sha256 = last_fingerprint();
    echo_through(
        addr(&sessions, device),
        &connect_with(&target, Some(&one)),
        b"d",
    )
    .await;

    assert_ne!(first_sha256, second_sha256);
    assert_ne!(first_sha256, device_sha256);
    assert_ne!(second_sha256, device_sha256);
    assert_eq!(
        status(addr(&sessions, first), &connect_with(&target, Some(&two))).await,
        407
    );
    assert_eq!(
        status(addr(&sessions, second), &connect_with(&target, Some(&one))).await,
        407
    );
    assert_eq!(
        status(addr(&sessions, first), &connect_with(&target, None)).await,
        407
    );
}
