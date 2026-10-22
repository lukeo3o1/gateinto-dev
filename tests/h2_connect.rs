#[allow(dead_code)]
mod fixture;
mod h2_fixture;

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;

use fixture::*;
use gateinto::proxy::Proxy;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

async fn tunnel(agent: SocketAddr, target: &str) -> TcpStream {
    let (stream, response) = send(agent, &connect_request(target)).await;
    assert_eq!(response.status, 200, "{}", response.head);
    assert!(response.rest.is_empty());
    stream
}

async fn tunnel_with_data(agent: SocketAddr, target: &str) -> TcpStream {
    let (stream, response) = send(agent, &connect_request(target)).await;
    assert_eq!(response.status, 200, "{}", response.head);
    stream
}

async fn echo(stream: &mut TcpStream, message: &[u8]) {
    stream.write_all(message).await.unwrap();
    let mut received = vec![0; message.len()];
    timeout(Duration::from_secs(5), stream.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, message);
}

#[tokio::test]
async fn mixed_gateway_routes_and_direct_failures_share_the_http2_pool() {
    let ca = TestCa::new();
    let server = h2_fixture::Server::start(ca.server_config(PROXY_NAME), 10).await;
    let mut config = agent_config(server.addr, ca.roots(), PROXY_NAME);
    config.route = gateinto::proxy::Route::Mixed;
    let proxy = Proxy::bind(config).await.unwrap();
    let agent = proxy.local_addr();
    let running = tokio::spawn(proxy.run());
    for _ in 0..2 {
        echo(&mut tunnel(agent, "127.0.0.1:443").await, b"matching IP").await;
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.2:0").await.unwrap();
    let unavailable = listener.local_addr().unwrap();
    drop(listener);
    echo(
        &mut tunnel(agent, &unavailable.to_string()).await,
        b"fallback",
    )
    .await;
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
    assert_eq!(server.requests.lock().unwrap().len(), 3);
    running.abort();
}

#[tokio::test]
async fn sequential_and_concurrent_tunnels_share_one_lazy_http2_connection() {
    let ca = TestCa::new();
    let server = h2_fixture::Server::start(ca.server_config(PROXY_NAME), 100).await;
    let proxy = Proxy::bind(agent_config(server.addr, ca.roots(), PROXY_NAME))
        .await
        .unwrap();
    assert_eq!(server.accepted.load(Ordering::SeqCst), 0);
    let agent = proxy.local_addr();
    let running = tokio::spawn(proxy.run());
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..8 {
        tasks.spawn(async move {
            let mut stream = tunnel(agent, "echo.test:443").await;
            echo(&mut stream, b"concurrent").await;
            stream.shutdown().await.unwrap();
            assert_eq!(
                read_to_end_within(&mut stream, Duration::from_secs(5)).await,
                b""
            );
        });
    }
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }
    for _ in 0..3 {
        echo(&mut tunnel(agent, "echo.test:443").await, b"sequential").await;
    }
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
    assert_eq!(server.requests.lock().unwrap().len(), 11);
    running.abort();
}

#[tokio::test]
async fn selected_http11_and_absent_alpn_keep_one_tls_connection_per_tunnel() {
    for selected in [false, true] {
        let ca = TestCa::new();
        let mut config = ca.server_config(PROXY_NAME);
        if selected {
            std::sync::Arc::make_mut(&mut config).alpn_protocols = vec![b"http/1.1".to_vec()];
        }
        let upstream = UpstreamProxy::start(config, Behavior::Tunnel).await;
        let agent = start_agent(agent_config(upstream.addr, ca.roots(), PROXY_NAME)).await;
        let target = echo_server().await;
        for _ in 0..3 {
            let mut stream = open_tunnel(agent, target).await;
            echo(&mut stream, b"legacy").await;
        }
        assert_eq!(upstream.accepted(), 3);
    }
}

#[tokio::test]
async fn check_upstream_uses_http2_and_reports_alpn_and_status_without_body() {
    let ca = TestCa::new();
    let server = h2_fixture::Server::start(ca.server_config(PROXY_NAME), 10).await;
    for (target, status) in [("echo.test:443", 200), ("407.test:443", 407)] {
        let config = agent_config(server.addr, ca.roots(), PROXY_NAME);
        let report = gateinto::check::check_upstream(gateinto::check::CheckOptions {
            upstream: config.upstream,
            tls_mode: config.tls_mode,
            client_certificate: None,
            target: Some(target.parse().unwrap()),
            timeout: Duration::from_secs(2),
            max_header_bytes: 16384,
        })
        .await
        .unwrap();
        assert!(report.to_string().contains("alpn: h2\n"));
        assert_eq!(
            report.connect_status,
            Some((status, format!("HTTP/2 {status}")))
        );
        assert_eq!(report.connect_refused(), (status != 200).then_some(status));
    }
}

#[tokio::test]
async fn statuses_resets_and_opening_timeouts_do_not_break_other_streams() {
    let ca = TestCa::new();
    let server = h2_fixture::Server::start(ca.server_config(PROXY_NAME), 10).await;
    let mut config = agent_config(server.addr, ca.roots(), PROXY_NAME);
    config.limits.handshake_timeout = Duration::from_millis(200);
    let agent = start_agent(config).await;
    let mut stable = tunnel(agent, "echo.test:443").await;
    for (target, expected) in [
        ("403.test:443", 403),
        ("407.test:443", 502),
        ("500.test:443", 502),
        ("reset.test:443", 502),
        ("slow.test:443", 504),
    ] {
        let (_, response) = send(agent, &connect_request(target)).await;
        assert_eq!(response.status, expected, "{target}: {}", response.head);
        echo(&mut stable, b"still active").await;
    }
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn large_bidirectional_data_and_half_close_preserve_early_bytes() {
    let ca = TestCa::new();
    let server = h2_fixture::Server::start(ca.server_config(PROXY_NAME), 10).await;
    let agent = start_agent(agent_config(server.addr, ca.roots(), PROXY_NAME)).await;
    for target in ["echo.test:443", "halfclose.test:443"] {
        let mut request = connect_request(target);
        request.extend_from_slice(b"early");
        let (mut stream, response) = send(agent, &request).await;
        assert_eq!(response.status, 200);
        let message = payload(2 * 1024 * 1024);
        let expected = [b"early".as_slice(), &message].concat();
        let (mut read, mut write) = stream.split();
        let writing = async {
            write.write_all(&message).await.unwrap();
            write.shutdown().await.unwrap();
        };
        let reading = async {
            let mut result = response.rest;
            read.read_to_end(&mut result).await.unwrap();
            assert_eq!(result, expected);
        };
        timeout(Duration::from_secs(10), async {
            tokio::join!(writing, reading);
        })
        .await
        .unwrap();
    }
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn peer_stream_limit_queues_connect_until_the_first_stream_releases_capacity() {
    let ca = TestCa::new();
    let server = h2_fixture::Server::start(ca.server_config(PROXY_NAME), 1).await;
    let agent = start_agent(agent_config(server.addr, ca.roots(), PROXY_NAME)).await;
    let mut first = tunnel(agent, "echo.test:443").await;
    let mut second = TcpStream::connect(agent).await.unwrap();
    second
        .write_all(&connect_request("echo.test:443"))
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_millis(100), read_response(&mut second))
            .await
            .is_err()
    );
    assert_eq!(server.requests.lock().unwrap().len(), 1);
    echo(&mut first, b"first").await;
    first.shutdown().await.unwrap();
    assert!(
        read_to_end_within(&mut first, Duration::from_secs(3))
            .await
            .is_empty()
    );
    let response = timeout(Duration::from_secs(3), read_response(&mut second))
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    echo(&mut second, b"second").await;
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn zero_peer_stream_limit_times_out_without_submitting_a_connect() {
    let ca = TestCa::new();
    let server = h2_fixture::Server::start(ca.server_config(PROXY_NAME), 0).await;
    let mut config = agent_config(server.addr, ca.roots(), PROXY_NAME);
    config.limits.handshake_timeout = Duration::from_millis(100);
    let agent = start_agent(config).await;
    for _ in 0..3 {
        let (_, response) = send(agent, &connect_request("echo.test:443")).await;
        assert_eq!(response.status, 504);
        assert!(server.requests.lock().unwrap().is_empty());
    }
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn goaway_drains_existing_streams_and_new_connect_uses_another_connection() {
    let ca = TestCa::new();
    let server = h2_fixture::Server::start(ca.server_config(PROXY_NAME), 10).await;
    let proxy = Proxy::bind(agent_config(server.addr, ca.roots(), PROXY_NAME))
        .await
        .unwrap();
    let agent = proxy.local_addr();
    let running = tokio::spawn(proxy.run());
    let mut old = tunnel(agent, "goaway.test:443").await;
    echo(&mut old, b"draining").await;
    let mut new = tunnel(agent, "echo.test:443").await;
    echo(&mut old, b"old still works").await;
    echo(&mut new, b"new works").await;
    assert_eq!(server.accepted.load(Ordering::SeqCst), 2);
    assert_eq!(server.active.load(Ordering::SeqCst), 2);
    running.abort();
    let _ = running.await;
    timeout(Duration::from_secs(3), async {
        while server.active.load(Ordering::SeqCst) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        read_to_end_within(&mut old, Duration::from_secs(3))
            .await
            .is_empty()
    );
    assert!(
        read_to_end_within(&mut new, Duration::from_secs(3))
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn idle_timeout_is_per_stream_and_local_tunnel_limit_still_applies() {
    let ca = TestCa::new();
    let server = h2_fixture::Server::start(ca.server_config(PROXY_NAME), 10).await;
    let mut config = agent_config(server.addr, ca.roots(), PROXY_NAME);
    config.limits.max_tunnels = 2;
    config.limits.idle_timeout = Duration::from_millis(150);
    let agent = start_agent(config).await;
    let mut idle = tunnel(agent, "echo.test:443").await;
    let mut active = tunnel(agent, "echo.test:443").await;
    let (_, response) = send(agent, &connect_request("echo.test:443")).await;
    assert_eq!(response.status, 503);
    for _ in 0..8 {
        echo(&mut active, b"activity").await;
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(
        read_to_end_within(&mut idle, Duration::from_secs(3))
            .await
            .is_empty()
    );
    echo(
        &mut tunnel(agent, "echo.test:443").await,
        b"capacity released",
    )
    .await;
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "test-hooks")]
mod renewal {
    use super::*;
    use gateinto::identity::certificates::{DeviceSigner, SelfSignedCertificates};
    use gateinto::identity::client_cert::ClientCertificate;
    use rcgen::PublicKeyData;
    use rustls::pki_types::UnixTime;
    use rustls::sign::{Signer, SigningKey};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64},
    };

    #[derive(Debug)]
    struct Clock(AtomicU64);
    impl rustls::time_provider::TimeProvider for Clock {
        fn current_time(&self) -> Option<UnixTime> {
            Some(at(self.0.load(Ordering::SeqCst)))
        }
    }
    fn at(seconds: u64) -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(seconds))
    }

    #[derive(Debug)]
    struct Key {
        inner: Arc<dyn SigningKey>,
        failing: Arc<AtomicBool>,
    }
    impl SigningKey for Key {
        fn choose_scheme(&self, schemes: &[rustls::SignatureScheme]) -> Option<Box<dyn Signer>> {
            if self.failing.load(Ordering::SeqCst) {
                None
            } else {
                self.inner.choose_scheme(schemes)
            }
        }
        fn algorithm(&self) -> rustls::SignatureAlgorithm {
            self.inner.algorithm()
        }
    }

    async fn setup(
        required: bool,
    ) -> (
        h2_fixture::Server,
        Arc<Clock>,
        Arc<AtomicBool>,
        Arc<SelfSignedCertificates>,
        SocketAddr,
        tokio::task::JoinHandle<()>,
    ) {
        setup_with_limit(required, 10).await
    }

    async fn setup_with_limit(
        required: bool,
        limit: u32,
    ) -> (
        h2_fixture::Server,
        Arc<Clock>,
        Arc<AtomicBool>,
        Arc<SelfSignedCertificates>,
        SocketAddr,
        tokio::task::JoinHandle<()>,
    ) {
        let now = UnixTime::now().as_secs();
        let clock = Arc::new(Clock(AtomicU64::new(now)));
        let key = rcgen::KeyPair::generate().unwrap();
        let failing = Arc::new(AtomicBool::new(false));
        let signer = DeviceSigner::new(
            key.public_key_raw().try_into().unwrap(),
            Arc::new(Key {
                inner: software_signer(&key).key(),
                failing: failing.clone(),
            }),
        );
        let certificates = Arc::new(SelfSignedCertificates::new(signer, at(now)).unwrap());
        let ca = TestCa::new();
        let mut tls =
            ca.server_config_requesting_client_spki(PROXY_NAME, key.subject_public_key_info());
        Arc::make_mut(&mut tls).time_provider = clock.clone();
        let server = h2_fixture::Server::start(tls, limit).await;
        let mut config = agent_config(server.addr, ca.roots(), PROXY_NAME);
        config.client_certificate = Some(ClientCertificate::SelfSigned {
            certificates: certificates.clone(),
            required,
        });
        let proxy = Proxy::bind_with_time_provider(config, clock.clone())
            .await
            .unwrap();
        let agent = proxy.local_addr();
        let running = tokio::spawn(proxy.run());
        (server, clock, failing, certificates, agent, running)
    }

    #[tokio::test]
    async fn certificate_is_rechecked_after_waiting_for_stream_capacity() {
        for required in [true, false] {
            let (server, clock, failing, _, agent, running) = setup_with_limit(required, 1).await;
            let issued = clock.0.load(Ordering::SeqCst);
            let mut first = tunnel(agent, "echo.test:443").await;
            let mut queued = TcpStream::connect(agent).await.unwrap();
            queued
                .write_all(&connect_request("echo.test:443"))
                .await
                .unwrap();
            assert!(
                timeout(Duration::from_millis(50), read_response(&mut queued))
                    .await
                    .is_err()
            );
            let mut waiting = TcpStream::connect(agent).await.unwrap();
            waiting
                .write_all(&connect_request("echo.test:443"))
                .await
                .unwrap();
            assert!(
                timeout(Duration::from_millis(50), read_response(&mut waiting))
                    .await
                    .is_err()
            );
            failing.store(true, Ordering::SeqCst);
            clock.0.store(issued + 86_400, Ordering::SeqCst);
            first.shutdown().await.unwrap();
            assert!(
                read_to_end_within(&mut first, Duration::from_secs(3))
                    .await
                    .is_empty()
            );
            assert_eq!(read_response(&mut queued).await.status, 200);
            queued.shutdown().await.unwrap();
            assert!(
                read_to_end_within(&mut queued, Duration::from_secs(3))
                    .await
                    .is_empty()
            );
            let response = timeout(Duration::from_secs(3), read_response(&mut waiting))
                .await
                .unwrap();
            assert_eq!(response.status, if required { 502 } else { 200 });
            assert_eq!(
                server.accepted.load(Ordering::SeqCst),
                if required { 1 } else { 2 }
            );
            running.abort();
        }
    }

    #[tokio::test]
    async fn renewal_rotates_at_twelve_hours_and_keeps_old_streams_draining() {
        for required in [true, false] {
            let (server, clock, _, certificates, agent, running) = setup(required).await;
            let issued = clock.0.load(Ordering::SeqCst);
            let mut old = tunnel(agent, "echo.test:443").await;
            let original = certificates.current().cert[0].clone();
            clock.0.store(issued + 43_199, Ordering::SeqCst);
            echo(&mut tunnel(agent, "echo.test:443").await, b"before renewal").await;
            assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
            clock.0.store(issued + 43_200, Ordering::SeqCst);
            echo(&mut tunnel(agent, "echo.test:443").await, b"after renewal").await;
            echo(&mut old, b"old still works").await;
            let renewed = certificates.current().cert[0].clone();
            assert_ne!(original, renewed);
            assert_eq!(
                *server.certificates.lock().unwrap(),
                [vec![original], vec![renewed]]
            );
            assert_eq!(server.accepted.load(Ordering::SeqCst), 2);
            running.abort();
            let _ = running.await;
            timeout(Duration::from_secs(3), async {
                while server.active.load(Ordering::SeqCst) != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn failed_renewals_keep_required_and_optional_semantics_and_retry_throttle() {
        for required in [true, false] {
            let (server, clock, failing, certificates, agent, running) = setup(required).await;
            let issued = clock.0.load(Ordering::SeqCst);
            let mut old = tunnel(agent, "echo.test:443").await;
            let original = certificates.current().cert[0].clone();
            failing.store(true, Ordering::SeqCst);
            clock.0.store(issued + 43_200, Ordering::SeqCst);
            echo(
                &mut tunnel(agent, "echo.test:443").await,
                b"valid despite failed renewal",
            )
            .await;
            assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
            clock.0.store(issued + 86_400, Ordering::SeqCst);
            let (_, response) = send(agent, &connect_request("echo.test:443")).await;
            assert_eq!(response.status, if required { 502 } else { 200 });
            assert_eq!(
                server.accepted.load(Ordering::SeqCst),
                if required { 1 } else { 2 }
            );
            if !required {
                assert_eq!(server.certificates.lock().unwrap()[1], []);
            }
            echo(&mut old, b"existing stream still works").await;
            failing.store(false, Ordering::SeqCst);
            clock.0.store(issued + 86_459, Ordering::SeqCst);
            let (_, response) = send(agent, &connect_request("echo.test:443")).await;
            assert_eq!(response.status, if required { 502 } else { 200 });
            assert_eq!(certificates.current().cert[0], original);
            clock.0.store(issued + 86_460, Ordering::SeqCst);
            echo(
                &mut tunnel(agent, "echo.test:443").await,
                b"renewed on retry",
            )
            .await;
            assert_ne!(certificates.current().cert[0], original);
            assert_eq!(
                server.accepted.load(Ordering::SeqCst),
                if required { 2 } else { 3 }
            );
            assert_eq!(
                server.certificates.lock().unwrap().last().unwrap(),
                &certificates.current().cert
            );
            running.abort();
        }
    }
}

#[tokio::test]
async fn alpn_is_rechecked_when_a_legacy_gateway_starts_selecting_http2() {
    let ca = TestCa::new();
    let server = h2_fixture::Server::start_switching(ca.server_config(PROXY_NAME), 10, true).await;
    let agent = start_agent(agent_config(server.addr, ca.roots(), PROXY_NAME)).await;
    for _ in 0..3 {
        echo(
            &mut tunnel(agent, "echo.test:443").await,
            b"protocol changed",
        )
        .await;
    }
    assert_eq!(server.accepted.load(Ordering::SeqCst), 2);
    assert_eq!(server.requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn optional_certificate_with_unsupported_signature_keeps_anonymous_http2_connection() {
    use gateinto::identity::certificates::SelfSignedCertificates;
    use gateinto::identity::client_cert::ClientCertificate;
    use rcgen::PublicKeyData;
    use std::sync::Arc;
    let ca = TestCa::new();
    let key = rcgen::KeyPair::generate().unwrap();
    let server = h2_fixture::Server::start(
        ca.server_config_requesting_unsupported_client_signature(
            PROXY_NAME,
            key.subject_public_key_info(),
        ),
        10,
    )
    .await;
    let mut config = agent_config(server.addr, ca.roots(), PROXY_NAME);
    config.client_certificate = Some(ClientCertificate::SelfSigned {
        certificates: Arc::new(
            SelfSignedCertificates::new(software_signer(&key), rustls::pki_types::UnixTime::now())
                .unwrap(),
        ),
        required: false,
    });
    let agent = start_agent(config).await;
    for _ in 0..3 {
        echo(&mut tunnel(agent, "echo.test:443").await, b"anonymous").await;
    }
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
    assert_eq!(*server.certificates.lock().unwrap(), [vec![]]);
}

#[tokio::test]
async fn a_connection_error_does_not_replay_the_submitted_connect_and_next_request_reconnects() {
    let ca = TestCa::new();
    let server = h2_fixture::Server::start(ca.server_config(PROXY_NAME), 10).await;
    let agent = start_agent(agent_config(server.addr, ca.roots(), PROXY_NAME)).await;
    let (_, response) = send(agent, &connect_request("drop.test:443")).await;
    assert_eq!(response.status, 502);
    echo(&mut tunnel(agent, "echo.test:443").await, b"new connection").await;
    let requests = server.requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|(_, target)| target == "drop.test:443")
            .count(),
        1
    );
    assert_eq!(server.accepted.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn early_upstream_data_and_ipv6_connect_authority_are_preserved() {
    let ca = TestCa::new();
    let server = h2_fixture::Server::start(ca.server_config(PROXY_NAME), 10).await;
    let agent = start_agent(agent_config(server.addr, ca.roots(), PROXY_NAME)).await;
    let mut request = connect_request("greeting.test:443");
    request.extend_from_slice(b"client early");
    let (mut stream, response) = send(agent, &request).await;
    assert_eq!(response.status, 200);
    let mut actual = response.rest;
    let expected = b"upstream earlyclient early";
    let missing = expected.len() - actual.len();
    let mut remaining = vec![0; missing];
    timeout(Duration::from_secs(3), stream.read_exact(&mut remaining))
        .await
        .unwrap()
        .unwrap();
    actual.extend_from_slice(&remaining);
    assert_eq!(actual, expected);
    echo(&mut tunnel(agent, "[::1]:443").await, b"ipv6 authority").await;
    assert_eq!(server.requests.lock().unwrap()[1].1, "[::1]:443");
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_slow_receiver_applies_backpressure_without_blocking_other_streams() {
    let ca = TestCa::new();
    let server = h2_fixture::Server::start(ca.server_config(PROXY_NAME), 10).await;
    let agent = start_agent(agent_config(server.addr, ca.roots(), PROXY_NAME)).await;
    let (slow, response) = send(agent, &connect_request("flood.test:443")).await;
    assert_eq!(response.status, 200);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(server.sent_bytes.load(Ordering::SeqCst) < 16 * 1024 * 1024);
    let mut healthy = tunnel(agent, "echo.test:443").await;
    echo(&mut healthy, &payload(128 * 1024)).await;
    drop(slow);
    echo(&mut healthy, b"capacity after cancelled slow stream").await;
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn many_unread_streams_cannot_exhaust_the_connection_window_for_a_new_tunnel() {
    let ca = TestCa::new();
    let server = h2_fixture::Server::start(ca.server_config(PROXY_NAME), 100).await;
    let agent = start_agent(agent_config(server.addr, ca.roots(), PROXY_NAME)).await;
    let mut stalled = Vec::new();
    for _ in 0..20 {
        let (stream, response) = send(agent, &connect_request("flood.test:443")).await;
        assert_eq!(response.status, 200);
        stalled.push(stream);
    }
    let mut previous = usize::MAX;
    loop {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let sent = server.sent_bytes.load(Ordering::SeqCst);
        if sent == previous {
            break;
        }
        previous = sent;
    }
    let mut healthy = tunnel(agent, "echo.test:443").await;
    echo(&mut healthy, &payload(128 * 1024)).await;
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
    drop(stalled);
}

async fn blackholed_gateway(
    handshake_timeout: Duration,
) -> (h2_fixture::Server, SocketAddr, TestCa) {
    let ca = TestCa::new();
    let server = h2_fixture::Server::start(ca.server_config(PROXY_NAME), 10).await;
    let mut config = agent_config(server.addr, ca.roots(), PROXY_NAME);
    config.limits.handshake_timeout = handshake_timeout;
    let agent = start_agent(config).await;
    echo(
        &mut tunnel(agent, "echo.test:443").await,
        b"before blackhole",
    )
    .await;
    server
        .blackhole_first_connection
        .store(true, Ordering::SeqCst);
    (server, agent, ca)
}

#[tokio::test]
async fn an_unanswered_connect_on_a_silent_connection_retires_it_for_later_requests() {
    let (server, agent, _ca) = blackholed_gateway(Duration::from_secs(2)).await;
    let started = tokio::time::Instant::now();
    let unanswered = tokio::spawn(async move {
        send(agent, &connect_request("echo.test:443"))
            .await
            .1
            .status
    });
    tokio::time::sleep(Duration::from_millis(1400)).await;
    let mut recovered = timeout(Duration::from_millis(1500), tunnel(agent, "echo.test:443"))
        .await
        .expect("a later CONNECT must not wait on the silent connection");
    echo(&mut recovered, b"fresh connection").await;
    assert!(started.elapsed() < Duration::from_millis(3500));
    assert_eq!(unanswered.await.unwrap(), 504);
    assert_eq!(server.accepted.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn an_idle_silent_connection_is_verified_and_replaced_before_reuse() {
    let (server, agent, _ca) = blackholed_gateway(Duration::from_secs(1)).await;
    tokio::time::sleep(Duration::from_millis(1300)).await;
    echo(
        &mut tunnel(agent, "echo.test:443").await,
        b"fresh connection",
    )
    .await;
    assert_eq!(server.accepted.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_dead_connection_is_closed_once_its_last_stream_ends() {
    let ca = TestCa::new();
    let server = h2_fixture::Server::start(ca.server_config(PROXY_NAME), 10).await;
    let mut config = agent_config(server.addr, ca.roots(), PROXY_NAME);
    config.limits.handshake_timeout = Duration::from_secs(1);
    let agent = start_agent(config).await;
    echo(
        &mut tunnel(agent, "echo.test:443").await,
        b"before blackhole",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    server
        .blackhole_first_connection
        .store(true, Ordering::SeqCst);
    let unanswered = tokio::spawn(async move {
        send(agent, &connect_request("echo.test:443"))
            .await
            .1
            .status
    });
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(server.active.load(Ordering::SeqCst), 1);
    assert_eq!(unanswered.await.unwrap(), 504);
    timeout(Duration::from_secs(3), async {
        while server.active.load(Ordering::SeqCst) > 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the agent must close a dead connection without streams");
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
}

async fn read_for(stream: &mut TcpStream, duration: Duration) {
    let deadline = tokio::time::Instant::now() + duration;
    let mut chunk = [0; 4096];
    while tokio::time::Instant::now() < deadline {
        let read = timeout(Duration::from_secs(5), stream.read(&mut chunk))
            .await
            .unwrap()
            .unwrap();
        assert!(read > 0);
    }
}

#[tokio::test]
async fn a_connection_receiving_data_is_reused_without_a_liveness_ping() {
    let ca = TestCa::new();
    let server = h2_fixture::Server::start(ca.server_config(PROXY_NAME), 10).await;
    let mut config = agent_config(server.addr, ca.roots(), PROXY_NAME);
    config.limits.handshake_timeout = Duration::from_secs(1);
    let agent = start_agent(config).await;
    let mut download = tunnel_with_data(agent, "trickle.test:443").await;
    read_for(&mut download, Duration::from_millis(1500)).await;
    let pings = server.pings.load(Ordering::SeqCst);
    echo(&mut tunnel(agent, "echo.test:443").await, b"reused").await;
    assert_eq!(server.pings.load(Ordering::SeqCst), pings);
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_late_pong_on_a_connection_still_delivering_data_does_not_retire_it() {
    let ca = TestCa::new();
    let server = h2_fixture::Server::start(ca.server_config(PROXY_NAME), 10).await;
    let mut config = agent_config(server.addr, ca.roots(), PROXY_NAME);
    config.limits.handshake_timeout = Duration::from_secs(2);
    let agent = start_agent(config).await;
    let mut download = tunnel_with_data(agent, "trickle.test:443").await;
    let downloading =
        tokio::spawn(async move { read_for(&mut download, Duration::from_millis(2500)).await });
    *server.ping_delay.lock().unwrap() = Duration::from_millis(1500);
    let pings = server.pings.load(Ordering::SeqCst);
    let unanswered = tokio::spawn(async move {
        send(agent, &connect_request("slow.test:443"))
            .await
            .1
            .status
    });
    tokio::time::sleep(Duration::from_millis(1300)).await;
    assert_eq!(server.pings.load(Ordering::SeqCst), pings + 1);
    echo(&mut tunnel(agent, "echo.test:443").await, b"still alive").await;
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
    assert_eq!(unanswered.await.unwrap(), 504);
    downloading.await.unwrap();
    *server.ping_delay.lock().unwrap() = Duration::ZERO;
    tokio::time::sleep(Duration::from_millis(2300)).await;
    echo(&mut tunnel(agent, "echo.test:443").await, b"pinged again").await;
    assert_eq!(server.pings.load(Ordering::SeqCst), pings + 2);
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn sessions_use_separate_http2_connections_and_closing_one_leaves_the_other_working() {
    use gateinto::identity::certificates::SelfSignedCertificates;
    use gateinto::identity::client_cert::ClientCertificate;
    use gateinto::sessions::{SessionConfig, SessionKind, SessionManager};
    use rcgen::PublicKeyData;
    use std::sync::Arc;
    let ca = TestCa::new();
    let key = rcgen::KeyPair::generate().unwrap();
    let certificates = Arc::new(
        SelfSignedCertificates::new(software_signer(&key), rustls::pki_types::UnixTime::now())
            .unwrap(),
    );
    let original = certificates.current().cert[0].clone();
    let server = h2_fixture::Server::start(
        ca.server_config_trusting_client_spki(PROXY_NAME, key.subject_public_key_info()),
        10,
    )
    .await;
    let mut config = agent_config(server.addr, ca.roots(), PROXY_NAME);
    config.client_certificate = Some(ClientCertificate::SelfSigned {
        certificates,
        required: true,
    });
    let mut sessions = SessionManager::new();
    let mut ids = Vec::new();
    for _ in 0..2 {
        ids.push(
            sessions
                .start(SessionConfig {
                    kind: SessionKind::Device,
                    gateway: "test".parse().unwrap(),
                    proxy: config.clone(),
                })
                .await
                .unwrap(),
        );
    }
    let first_addr = sessions.session(ids[0]).unwrap().local_addr();
    let second_addr = sessions.session(ids[1]).unwrap().local_addr();
    let mut first = tunnel(first_addr, "echo.test:443").await;
    let mut second = tunnel(second_addr, "echo.test:443").await;
    for _ in 0..3 {
        echo(
            &mut tunnel(first_addr, "echo.test:443").await,
            b"first session",
        )
        .await;
        echo(
            &mut tunnel(second_addr, "echo.test:443").await,
            b"second session",
        )
        .await;
    }
    assert_eq!(server.accepted.load(Ordering::SeqCst), 2);
    let chains = server.certificates.lock().unwrap().clone();
    assert_ne!(chains[0], chains[1]);
    assert_ne!(chains[0].as_slice(), std::slice::from_ref(&original));
    assert_ne!(chains[1], [original]);
    assert!(sessions.close(ids[0]).await);
    timeout(Duration::from_secs(3), async {
        while server.active.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        read_to_end_within(&mut first, Duration::from_secs(3))
            .await
            .is_empty()
    );
    echo(&mut second, b"remaining session").await;
    echo(
        &mut tunnel(second_addr, "echo.test:443").await,
        b"new stream on remaining session",
    )
    .await;
    sessions.close_all().await;
    timeout(Duration::from_secs(3), async {
        while server.active.load(Ordering::SeqCst) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        read_to_end_within(&mut second, Duration::from_secs(3))
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn a_slow_legacy_tls_handshake_does_not_delay_another_tunnel() {
    use std::sync::{Arc, atomic::AtomicBool};
    use tokio::net::TcpListener;
    let ca = TestCa::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted_slow = Arc::new(AtomicBool::new(false));
    let acceptor = tokio_rustls::TlsAcceptor::from(ca.server_config(PROXY_NAME));
    let server = tokio::spawn({
        let accepted_slow = accepted_slow.clone();
        async move {
            let mut tasks = tokio::task::JoinSet::new();
            for index in 0..3 {
                let (tcp, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                if index == 1 {
                    accepted_slow.store(true, Ordering::SeqCst);
                }
                tasks.spawn(async move {
                    if index == 1 {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let _ = read_head(&mut tls).await;
                    let _ = tls.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
                    let (mut reader, mut writer) = tokio::io::split(tls);
                    let _ = tokio::io::copy(&mut reader, &mut writer).await;
                });
            }
            while tasks.join_next().await.is_some() {}
        }
    });
    let agent = start_agent(agent_config(addr, ca.roots(), PROXY_NAME)).await;
    echo(&mut tunnel(agent, "echo.test:443").await, b"warm fallback").await;
    let slow = tokio::spawn(async move { tunnel(agent, "echo.test:443").await });
    timeout(Duration::from_secs(2), async {
        while !accepted_slow.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut fast = timeout(Duration::from_millis(200), tunnel(agent, "echo.test:443"))
        .await
        .expect("legacy TLS handshakes must run independently");
    echo(&mut fast, b"fast fallback").await;
    drop(fast);
    drop(slow.await.unwrap());
    server.abort();
}

async fn assert_initialization_timeout_recovers(prefix: &'static [u8]) {
    let ca = TestCa::new();
    let server =
        h2_fixture::Server::start_with_stalled_initialization(ca.server_config(PROXY_NAME), prefix)
            .await;
    let mut config = agent_config(server.addr, ca.roots(), PROXY_NAME);
    config.limits.handshake_timeout = Duration::from_millis(200);
    let agent = start_agent(config).await;
    let (_, response) = send(agent, &connect_request("echo.test:443")).await;
    assert_eq!(response.status, 504);
    timeout(Duration::from_secs(3), async {
        while server.active.load(Ordering::SeqCst) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("timed-out HTTP/2 initialization must close its TLS connection");
    for _ in 0..2 {
        echo(&mut tunnel(agent, "echo.test:443").await, b"recovered").await;
    }
    assert_eq!(server.accepted.load(Ordering::SeqCst), 2);
    assert_eq!(server.requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn missing_initial_settings_timeout_closes_tls_and_allows_reconnect() {
    assert_initialization_timeout_recovers(b"").await;
}

#[tokio::test]
async fn partial_initial_settings_timeout_closes_tls_and_allows_reconnect() {
    assert_initialization_timeout_recovers(&[0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 3]).await;
}

#[tokio::test]
async fn missing_initial_pong_timeout_closes_tls_and_allows_reconnect() {
    assert_initialization_timeout_recovers(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await;
}
