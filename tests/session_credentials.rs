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
use gateinto::proxy::{Config, FailureLimit, LocalAuth, Proxy, Route, SessionCredentials};
use gateinto::sessions::{SessionConfig, SessionId, SessionKind, SessionManager};
use rcgen::{KeyPair, PublicKeyData};
use rustls::pki_types::UnixTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

    fn config(&self) -> Config {
        let mut config = agent_config(self.upstream.addr, self.ca.roots(), PROXY_NAME);
        config.local_auth = LocalAuth::SESSION_CREDENTIALS;
        config
    }

    fn browser(&self) -> SessionConfig {
        session(self.config())
    }

    fn browser_limited(&self, max_failures: u32) -> SessionConfig {
        let mut config = self.config();
        config.limits.local_auth_failures = FailureLimit {
            max_failures,
            window: Duration::from_secs(600),
        };
        session(config)
    }

    fn connect(&self, authorization: Option<&str>) -> Vec<u8> {
        connect_with(&self.target.to_string(), authorization)
    }
}

fn session(proxy: Config) -> SessionConfig {
    SessionConfig {
        kind: SessionKind::Browser,
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

fn issued(sessions: &SessionManager, id: SessionId) -> SessionCredentials {
    sessions.session(id).unwrap().credentials().unwrap().clone()
}

fn header(credentials: &SessionCredentials) -> String {
    basic(credentials.username(), credentials.password())
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
async fn the_proxy_issues_credentials_only_in_session_credentials_mode() {
    let setup = Setup::start().await;
    let issuing = Proxy::bind(setup.config()).await.unwrap();
    assert!(issuing.credentials().is_some());
    assert!(issuing.realm().is_some());
    let plain = Proxy::bind(agent_config(
        setup.upstream.addr,
        setup.ca.roots(),
        PROXY_NAME,
    ))
    .await
    .unwrap();
    assert!(plain.credentials().is_none());
    assert!(plain.realm().is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_connect_without_credentials_is_challenged_with_the_session_realm() {
    let setup = Setup::start().await;
    let mut sessions = SessionManager::new();
    let id = sessions.start(setup.browser()).await.unwrap();
    let realm = realm(&sessions, id);

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
async fn the_issued_credentials_open_many_tunnels_without_reaching_the_gateway() {
    let setup = Setup::start().await;
    let mut sessions = SessionManager::new();
    let id = sessions.start(setup.browser()).await.unwrap();
    let agent = addr(&sessions, id);
    let credential = header(&issued(&sessions, id));

    for round in 0..5 {
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
async fn an_unknown_credential_is_challenged_and_never_binds() {
    let setup = Setup::start().await;
    let mut sessions = SessionManager::new();
    let id = sessions.start(setup.browser_limited(100)).await.unwrap();
    let agent = addr(&sessions, id);
    let credentials = issued(&sessions, id);
    let (user, pass) = (credentials.username(), credentials.password());
    let intruder = basic("intruder", "first");

    for other in [
        intruder.clone(),
        intruder.clone(),
        basic(user, "other"),
        basic("other", pass),
        basic(&user.to_uppercase(), pass),
        basic(user, &pass.replace('-', "")),
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
    assert_eq!(setup.upstream.accepted(), 0);
    echo_through(agent, &setup.connect(Some(&header(&credentials))), b"mine").await;
    assert_eq!(status(agent, &setup.connect(Some(&intruder))).await, 407);
}

#[tokio::test(flavor = "multi_thread")]
async fn authentication_comes_before_dns_routing_and_the_gateway() {
    let setup = Setup::start().await;
    let mut config = setup.config();
    config.route = Route::Mixed;
    let mut sessions = SessionManager::new();
    let id = sessions.start(session(config)).await.unwrap();
    let agent = addr(&sessions, id);

    for target in ["unresolvable.invalid:443", &setup.target.to_string()] {
        for authorization in [None, Some(basic("intruder", "first"))] {
            let request = connect_with(target, authorization.as_deref());
            assert_eq!(status(agent, &request).await, 407, "{target}");
        }
    }
    assert_eq!(setup.upstream.accepted(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_credentials_are_bad_requests() {
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
    let right = header(&issued(&sessions, id));
    let duplicate = format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: {right}\r\nProxy-Authorization: {right}\r\n\r\n",
    );
    assert_eq!(status(agent, duplicate.as_bytes()).await, 400);
    assert_eq!(status(agent, &setup.connect(Some("Bearer abc"))).await, 407);
    assert_eq!(setup.upstream.accepted(), 0);

    echo_through(agent, &setup.connect(Some(&right)), b"first").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn credentials_in_a_head_one_byte_past_the_limit_are_431() {
    const LIMIT: usize = 512;
    let setup = Setup::start().await;
    let mut config = setup.config();
    config.limits.max_header_bytes = LIMIT;
    let mut sessions = SessionManager::new();
    let id = sessions.start(session(config)).await.unwrap();
    let agent = addr(&sessions, id);
    let right = setup.connect(Some(&header(&issued(&sessions, id))));

    assert_eq!(status(agent, &pad_head(&right, LIMIT + 1)).await, 431);
    assert_eq!(setup.upstream.accepted(), 0);
    echo_through(agent, &pad_head(&right, LIMIT), b"at the limit").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn repeated_failures_are_rate_limited_even_for_the_issued_credentials() {
    let setup = Setup::start().await;
    let mut sessions = SessionManager::new();
    let id = sessions.start(setup.browser_limited(3)).await.unwrap();
    let agent = addr(&sessions, id);
    let right = header(&issued(&sessions, id));
    echo_through(agent, &setup.connect(Some(&right)), b"in").await;

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
async fn sessions_issue_distinct_credentials_that_work_only_on_their_own_proxy() {
    let key = KeyPair::generate().unwrap();
    let certificates = SelfSignedCertificates::new(software_signer(&key), UnixTime::now()).unwrap();
    let source = ClientCertificate::SelfSigned {
        certificates: Arc::new(certificates),
        required: true,
    };
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
        .start(SessionConfig {
            kind: SessionKind::Device,
            gateway: "office".parse().unwrap(),
            proxy: config(LocalAuth::NONE),
        })
        .await
        .unwrap();
    let first = sessions
        .start(session(config(LocalAuth::SESSION_CREDENTIALS)))
        .await
        .unwrap();
    let second = sessions
        .start(session(config(LocalAuth::SESSION_CREDENTIALS)))
        .await
        .unwrap();
    assert!(sessions.session(device).unwrap().credentials().is_none());
    let (one, two) = (issued(&sessions, first), issued(&sessions, second));
    assert_eq!(one.username(), two.username());
    assert_ne!(one.password(), two.password());
    assert_ne!(realm(&sessions, first), realm(&sessions, second));

    let last_fingerprint = || {
        let chains = upstream.client_certificates();
        sha256_fingerprint(&chains.last().unwrap()[0])
    };
    let (one, two) = (header(&one), header(&two));
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
}

#[tokio::test(flavor = "multi_thread")]
async fn closing_a_session_revokes_its_credentials_and_ends_its_tunnels() {
    let setup = Setup::start().await;
    let mut sessions = SessionManager::new();
    let closed = sessions.start(setup.browser()).await.unwrap();
    let closed_addr = addr(&sessions, closed);
    let cached = header(&issued(&sessions, closed));
    let (mut tunnel, response) = send(closed_addr, &setup.connect(Some(&cached))).await;
    assert_eq!(response.status, 200, "{}", response.head);
    tunnel.write_all(b"open").await.unwrap();
    let mut echoed = [0; 4];
    tokio::time::timeout(CLOSE_WITHIN, tunnel.read_exact(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&echoed, b"open");

    assert!(sessions.close(closed).await);

    let mut rest = [0; 16];
    match tokio::time::timeout(CLOSE_WITHIN, tunnel.read(&mut rest)).await {
        Ok(Ok(0) | Err(_)) => {}
        Ok(Ok(n)) => panic!("the closed session's tunnel delivered {:?}", &rest[..n]),
        Err(_) => panic!("the closed session's tunnel stayed open"),
    }
    let error = TcpStream::connect(closed_addr).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ConnectionRefused, "{error}");
    let fresh = sessions.start(setup.browser()).await.unwrap();
    let fresh_addr = addr(&sessions, fresh);
    let fresh_header = header(&issued(&sessions, fresh));
    assert_ne!(fresh_header, cached);
    assert_eq!(status(fresh_addr, &setup.connect(Some(&cached))).await, 407);
    echo_through(fresh_addr, &setup.connect(Some(&fresh_header)), b"fresh").await;
    assert_eq!(setup.upstream.requests().len(), 2);
}
