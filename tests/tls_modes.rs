#[allow(dead_code)]
mod fixture;

use std::net::SocketAddr;
use std::time::Duration;

use fixture::*;
use gateinto::tls::TlsMode;
use rustls::NamedGroup;
use rustls::crypto::SupportedKxGroup;
use tokio::io::AsyncWriteExt;

const CLOSE_WITHIN: Duration = Duration::from_secs(5);
const ALL_MODES: [TlsMode; 3] = [
    TlsMode::HybridPreferred,
    TlsMode::HybridRequired,
    TlsMode::ClassicalOnly,
];

struct Setup {
    ca: TestCa,
    upstream: UpstreamProxy,
}

impl Setup {
    async fn new(groups: &[&'static dyn SupportedKxGroup]) -> Self {
        let ca = TestCa::new();
        let upstream = UpstreamProxy::start(
            ca.server_config_with_groups(PROXY_NAME, groups),
            Behavior::Tunnel,
        )
        .await;
        Self { ca, upstream }
    }

    async fn agent(&self, mode: TlsMode) -> SocketAddr {
        let mut config = agent_config(self.upstream.addr, self.ca.roots(), PROXY_NAME);
        config.tls_mode = mode;
        start_agent(config).await
    }
}

async fn assert_tunnel_works(agent: SocketAddr) {
    let mut stream = open_tunnel(agent, echo_server().await).await;
    stream.write_all(b"key exchange").await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(
        read_to_end_within(&mut stream, CLOSE_WITHIN).await,
        b"key exchange"
    );
}

async fn assert_bad_gateway(agent: SocketAddr) {
    let target = echo_server().await;
    let (mut stream, response) = send(agent, &connect_request(&target.to_string())).await;
    assert_eq!(response.status, 502, "{}", response.head);
    read_to_end_within(&mut stream, CLOSE_WITHIN).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn hybrid_preferred_negotiates_x25519mlkem768_with_a_hybrid_upstream() {
    let setup = Setup::new(HYBRID_GROUPS).await;
    assert_tunnel_works(setup.agent(TlsMode::HybridPreferred).await).await;
    assert_eq!(
        setup.upstream.negotiated_groups(),
        [NamedGroup::X25519MLKEM768]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn hybrid_preferred_falls_back_to_x25519_with_a_classical_upstream() {
    let setup = Setup::new(CLASSICAL_GROUPS).await;
    assert_tunnel_works(setup.agent(TlsMode::HybridPreferred).await).await;
    assert_eq!(setup.upstream.negotiated_groups(), [NamedGroup::X25519]);
}

#[tokio::test(flavor = "multi_thread")]
async fn hybrid_required_negotiates_x25519mlkem768_with_a_hybrid_upstream() {
    let setup = Setup::new(HYBRID_GROUPS).await;
    assert_tunnel_works(setup.agent(TlsMode::HybridRequired).await).await;
    assert_eq!(
        setup.upstream.negotiated_groups(),
        [NamedGroup::X25519MLKEM768]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn hybrid_required_refuses_a_classical_upstream_with_502() {
    let setup = Setup::new(CLASSICAL_GROUPS).await;
    assert_bad_gateway(setup.agent(TlsMode::HybridRequired).await).await;
    let errors = setup.upstream.wait_for_handshake_errors(1).await;
    assert!(errors[0].contains("NoKxGroupsInCommon"), "{errors:?}");
    assert!(setup.upstream.negotiated_groups().is_empty());
    assert!(setup.upstream.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn classical_only_negotiates_x25519_with_a_hybrid_upstream() {
    let setup = Setup::new(HYBRID_GROUPS).await;
    assert_tunnel_works(setup.agent(TlsMode::ClassicalOnly).await).await;
    assert_eq!(setup.upstream.negotiated_groups(), [NamedGroup::X25519]);
}

#[tokio::test(flavor = "multi_thread")]
async fn every_mode_rejects_an_untrusted_upstream_certificate() {
    let setup = Setup::new(HYBRID_GROUPS).await;
    for mode in ALL_MODES {
        let mut config = agent_config(setup.upstream.addr, TestCa::new().roots(), PROXY_NAME);
        config.tls_mode = mode;
        assert_bad_gateway(start_agent(config).await).await;
    }
    assert!(setup.upstream.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn every_mode_rejects_an_upstream_certificate_for_another_name() {
    let setup = Setup::new(HYBRID_GROUPS).await;
    for mode in ALL_MODES {
        let mut config = agent_config(setup.upstream.addr, setup.ca.roots(), "other.test");
        config.tls_mode = mode;
        assert_bad_gateway(start_agent(config).await).await;
    }
    assert!(setup.upstream.requests().is_empty());
}
