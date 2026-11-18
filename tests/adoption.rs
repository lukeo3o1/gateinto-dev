#[allow(dead_code)]
mod fixture;

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use fixture::*;
use gateinto::http::Authority;
use gateinto::identity::client_cert::ClientCertificate;
use gateinto::proxy::{Adopter, Config, OpenTunnels, Proxy, Verifications, reset};
use rcgen::KeyPair;
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::sign::CertifiedKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::timeout;

const CLOSE_WITHIN: Duration = Duration::from_secs(5);
const TARGET: &str = "192.0.2.1:443";

fn target() -> Authority {
    TARGET.parse().unwrap()
}

async fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (accepted, _) = listener.accept().await.unwrap();
    (client, accepted)
}

struct Running {
    agent: SocketAddr,
    adopter: Adopter,
    open_tunnels: OpenTunnels,
    verifications: Verifications,
}

impl Running {
    async fn start(config: Config) -> Self {
        let proxy = Proxy::bind(config).await.unwrap();
        let agent = proxy.local_addr();
        let adopter = proxy.adopter();
        let open_tunnels = proxy.open_tunnels();
        let verifications = proxy.verifications();
        tokio::spawn(proxy.run());
        Self {
            agent,
            adopter,
            open_tunnels,
            verifications,
        }
    }

    async fn adopt(&self) -> TcpStream {
        let (client, accepted) = pair().await;
        self.adopter.adopt(accepted, target()).unwrap();
        client
    }
}

struct Gateway {
    ca: TestCa,
    upstream: UpstreamProxy,
}

impl Gateway {
    async fn start(behavior: Behavior) -> Self {
        let ca = TestCa::new();
        let upstream = UpstreamProxy::start(ca.server_config(PROXY_NAME), behavior).await;
        Self { ca, upstream }
    }

    async fn echoing(banner: &'static [u8]) -> Self {
        Self::start(Behavior::TunnelTo(echo_server().await, banner)).await
    }

    fn config(&self) -> Config {
        agent_config(self.upstream.addr, self.ca.roots(), PROXY_NAME)
    }
}

async fn assert_reset(client: &mut TcpStream) {
    let mut received = [0; 64];
    match timeout(CLOSE_WITHIN, client.read(&mut received)).await {
        Err(_) => panic!("the adopted stream was not closed in time"),
        Ok(Err(error)) => assert_eq!(error.kind(), ErrorKind::ConnectionReset, "{error}"),
        Ok(Ok(n)) => panic!("expected a reset, got {:?}", &received[..n]),
    }
}

async fn echo_to_end(client: &mut TcpStream, data: &[u8]) {
    client.write_all(data).await.unwrap();
    client.shutdown().await.unwrap();
    assert_eq!(read_to_end_within(client, CLOSE_WITHIN).await, data);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_adopted_stream_is_relayed_through_the_gateway_without_a_status_line() {
    let gateway = Gateway::echoing(b"").await;
    let running = Running::start(gateway.config()).await;

    let mut client = running.adopt().await;
    echo_to_end(&mut client, b"both ways").await;

    assert_eq!(gateway.upstream.requests(), [gateway_connect(TARGET)]);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_gateways_early_bytes_reach_an_adopted_client() {
    let gateway = Gateway::echoing(b"banner").await;
    let running = Running::start(gateway.config()).await;

    let mut client = running.adopt().await;
    let mut banner = [0; 6];
    timeout(CLOSE_WITHIN, client.read_exact(&mut banner))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(&banner, b"banner");
    echo_to_end(&mut client, b"after").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_adopted_tunnel_holds_a_tunnel_permit_until_it_ends() {
    let gateway = Gateway::echoing(b"").await;
    let mut config = gateway.config();
    config.limits.max_tunnels = 1;
    let running = Running::start(config).await;
    let mut adopted = running.adopt().await;
    adopted.write_all(b"open").await.unwrap();
    adopted.read_exact(&mut [0; 4]).await.unwrap();

    let (_, response) = send(running.agent, &connect_request(TARGET)).await;
    assert_eq!(response.status, 503, "{}", response.head);

    echo_to_end(&mut adopted, b"").await;
    let deadline = tokio::time::Instant::now() + CLOSE_WITHIN;
    loop {
        let (_stream, response) = send(running.agent, &connect_request(TARGET)).await;
        if response.status == 200 {
            break;
        }
        assert_eq!(response.status, 503, "{}", response.head);
        assert!(
            tokio::time::Instant::now() < deadline,
            "the permit was not released"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_adopted_stream_beyond_the_tunnel_limit_is_reset_without_a_reject_permit() {
    let gateway = Gateway::echoing(b"").await;
    let mut config = gateway.config();
    config.limits.max_tunnels = 1;
    config.limits.max_pending_rejects = 1;
    config.limits.reject_linger = Duration::from_secs(3600);
    let running = Running::start(config).await;
    let _tunnel = open_tunnel(running.agent, "192.0.2.2:443".parse().unwrap()).await;

    let mut adopted = running.adopt().await;
    assert_reset(&mut adopted).await;

    assert_eq!(gateway.upstream.accepted(), 1);
    assert_eq!(
        gateway.upstream.requests(),
        [gateway_connect("192.0.2.2:443")]
    );
    let mut lingering = TcpStream::connect(running.agent).await.unwrap();
    assert_eq!(read_response(&mut lingering).await.status, 503);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_adopted_stream_is_reset_when_the_gateway_fails() {
    let unreachable = agent_config(unused_port().await, TestCa::new().roots(), PROXY_NAME);
    let mut gateways = Vec::new();
    for behavior in [
        Behavior::Status(403),
        Behavior::Status(502),
        Behavior::Close,
    ] {
        gateways.push(Gateway::start(behavior).await);
    }
    let configs = gateways.iter().map(Gateway::config);
    for config in std::iter::once(unreachable).chain(configs) {
        let running = Running::start(config).await;
        assert_reset(&mut running.adopt().await).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_adopted_stream_is_reset_when_the_gateway_does_not_answer_in_time() {
    let gateway = Gateway::start(Behavior::Hang).await;
    let mut config = gateway.config();
    config.limits.handshake_timeout = Duration::from_millis(200);
    let running = Running::start(config).await;

    let started = tokio::time::Instant::now();
    let mut adopted = running.adopt().await;
    assert_reset(&mut adopted).await;

    assert!(started.elapsed() >= Duration::from_millis(200));
    assert_eq!(gateway.upstream.requests(), [gateway_connect(TARGET)]);
}

fn fixed(certificate: &IssuedCertificate, key: &KeyPair) -> ClientCertificate {
    let der = PrivatePkcs8KeyDer::from(key.serialize_der()).into();
    let signer = rustls::crypto::aws_lc_rs::sign::any_ecdsa_type(&der).unwrap();
    Arc::new(CertifiedKey::new(vec![certificate.der.clone()], signer)).into()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_challenge_to_an_adopted_stream_stores_the_offer_and_resets_the_stream() {
    let ca = TestCa::new();
    let client_ca = TestCa::new();
    let key = KeyPair::generate().unwrap();
    let issued = client_ca.issue_client_certificate(&key);
    let gateway = UpstreamProxy::start(
        ca.server_config_requesting_client_certificates(PROXY_NAME, &client_ca),
        Behavior::Challenge(CHALLENGE_CODES[0]),
    )
    .await;
    let mut config = agent_config(gateway.addr, ca.roots(), PROXY_NAME);
    config.client_certificate = Some(fixed(&issued, &key));
    let running = Running::start(config).await;

    let mut adopted = running.adopt().await;
    assert_reset(&mut adopted).await;

    let verification = running.verifications.get().expect("a stored offer");
    assert_eq!(verification.user_code.as_str(), CHALLENGE_CODES[0]);
    assert_eq!(verification.targets, [TARGET]);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_adopted_tunnel_is_counted_while_it_is_open() {
    let gateway = Gateway::echoing(b"").await;
    let running = Running::start(gateway.config()).await;
    assert_eq!(running.open_tunnels.count(), 0);

    let mut adopted = running.adopt().await;
    adopted.write_all(b"open").await.unwrap();
    adopted.read_exact(&mut [0; 4]).await.unwrap();
    assert_eq!(running.open_tunnels.count(), 1);

    echo_to_end(&mut adopted, b"").await;
    let deadline = tokio::time::Instant::now() + CLOSE_WITHIN;
    while running.open_tunnels.count() != 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the tunnel is still counted"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn closing_the_proxy_aborts_adopted_tunnels_and_hands_back_later_streams() {
    let gateway = Gateway::echoing(b"").await;
    let proxy = Proxy::bind(gateway.config()).await.unwrap();
    let adopter = proxy.adopter();
    let (close, closed) = oneshot::channel::<()>();
    let task = tokio::spawn(proxy.run_until(async {
        let _ = closed.await;
    }));
    let (mut adopted, accepted) = pair().await;
    adopter.adopt(accepted, target()).unwrap();
    adopted.write_all(b"open").await.unwrap();
    adopted.read_exact(&mut [0; 4]).await.unwrap();

    close.send(()).unwrap();
    timeout(CLOSE_WITHIN, task).await.unwrap().unwrap();
    assert_eq!(read_to_end_within(&mut adopted, CLOSE_WITHIN).await, b"");

    let (mut late, accepted) = pair().await;
    let back = adopter.adopt(accepted, target()).unwrap_err();
    assert_eq!(back.peer_addr().unwrap(), late.local_addr().unwrap());
    reset(back);
    assert_reset(&mut late).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn streams_still_queued_when_the_proxy_closes_are_reset() {
    let config = agent_config(unused_port().await, TestCa::new().roots(), PROXY_NAME);
    let proxy = Proxy::bind(config).await.unwrap();
    let adopter = proxy.adopter();
    let (mut queued, accepted) = pair().await;
    adopter.adopt(accepted, target()).unwrap();

    proxy.run_until(async {}).await;

    assert_reset(&mut queued).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn adopt_hands_the_stream_back_when_the_queue_is_full() {
    let mut config = agent_config(unused_port().await, TestCa::new().roots(), PROXY_NAME);
    config.limits.max_tunnels = 2;
    let proxy = Proxy::bind(config).await.unwrap();
    let adopter = proxy.adopter();
    let mut queued = Vec::new();
    for _ in 0..2 {
        let (client, accepted) = pair().await;
        adopter.adopt(accepted, target()).unwrap();
        queued.push(client);
    }

    let (client, accepted) = pair().await;
    let back = adopter.adopt(accepted, target()).unwrap_err();

    assert_eq!(back.peer_addr().unwrap(), client.local_addr().unwrap());
    drop(proxy);
}
