#[allow(dead_code)]
mod fixture;

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use fixture::*;
use gateinto::proxy::{LocalAuth, Proxy, Route};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

const OTHER_LOOPBACK: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

#[tokio::test]
async fn the_default_route_still_sends_a_distinct_target_to_the_gateway() {
    let ca = TestCa::new();
    let gateway = UpstreamProxy::start(ca.server_config(PROXY_NAME), Behavior::Tunnel).await;
    let agent = start_agent(agent_config(gateway.addr, ca.roots(), PROXY_NAME)).await;
    let target = echo_server_on(OTHER_LOOPBACK).await;
    let mut stream = open_tunnel(agent, target).await;
    stream.write_all(b"gateway").await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(
        read_to_end_within(&mut stream, Duration::from_secs(5)).await,
        b"gateway"
    );
    assert_eq!(gateway.requests().len(), 1);
}

#[tokio::test]
async fn mixed_direct_tunnels_preserve_early_bytes_half_close_and_end_to_end_tls() {
    let ca = TestCa::new();
    let gateway = UpstreamProxy::start(ca.server_config(PROXY_NAME), Behavior::Status(403)).await;
    let mut config = agent_config(gateway.addr, ca.roots(), PROXY_NAME);
    config.route = Route::Mixed;
    let agent = start_agent(config).await;
    let target = echo_server_on(OTHER_LOOPBACK).await;
    let early = payload(65536);
    let mut request = connect_request(&target.to_string());
    request.extend_from_slice(&early);
    let (mut stream, response) = send(agent, &request).await;
    assert_eq!(response.status, 200);
    stream.shutdown().await.unwrap();
    let mut received = response.rest;
    received.extend(read_to_end_within(&mut stream, Duration::from_secs(5)).await);
    assert_eq!(received, early);
    assert_eq!(gateway.accepted(), 0);

    let origin_ca = TestCa::new();
    let listener = TcpListener::bind((OTHER_LOOPBACK, 0)).await.unwrap();
    let target = listener.local_addr().unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(origin_ca.server_config("origin.test"));
    let origin = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.unwrap();
        let (mut reader, mut writer) = tokio::io::split(&mut tls);
        tokio::io::copy(&mut reader, &mut writer).await.unwrap();
        writer.shutdown().await.unwrap();
    });
    let tcp = open_tunnel(agent, target).await;
    let mut tls = inner_tls(tcp, origin_ca.client_config(), "origin.test").await;
    tls.write_all(b"encrypted").await.unwrap();
    tls.shutdown().await.unwrap();
    let mut received = Vec::new();
    timeout(Duration::from_secs(5), tls.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, b"encrypted");
    origin.await.unwrap();
    assert_eq!(gateway.accepted(), 0);
}

#[tokio::test]
async fn mixed_routes_matching_gateway_ips_through_the_gateway() {
    let ca = TestCa::new();
    let gateway = UpstreamProxy::start(ca.server_config(PROXY_NAME), Behavior::Tunnel).await;
    let mut config = agent_config(gateway.addr, ca.roots(), PROXY_NAME);
    config.route = Route::Mixed;
    let agent = start_agent(config).await;
    let target = echo_server().await;
    let mut stream = open_tunnel(agent, target).await;
    stream.write_all(b"same IP").await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(
        read_to_end_within(&mut stream, Duration::from_secs(5)).await,
        b"same IP"
    );
    assert_eq!(gateway.requests().len(), 1);
}

#[tokio::test]
async fn failed_direct_tcp_falls_back_once_and_preserves_gateway_refusals() {
    for (upstream, local) in [(403, 403), (407, 502), (500, 502)] {
        let ca = TestCa::new();
        let gateway =
            UpstreamProxy::start(ca.server_config(PROXY_NAME), Behavior::Status(upstream)).await;
        let mut config = agent_config(gateway.addr, ca.roots(), PROXY_NAME);
        config.route = Route::Mixed;
        let agent = start_agent(config).await;
        let listener = TcpListener::bind((OTHER_LOOPBACK, 0)).await.unwrap();
        let unavailable = listener.local_addr().unwrap();
        drop(listener);
        let (_, response) = send(agent, &connect_request(&unavailable.to_string())).await;
        assert_eq!(response.status, local);
        assert_eq!(
            gateway.requests(),
            vec![format!(
                "CONNECT {unavailable} HTTP/1.1\r\nHost: {unavailable}\r\n\r\n"
            )]
        );
    }
}

#[tokio::test]
async fn established_direct_connections_are_never_replayed_through_the_gateway() {
    let ca = TestCa::new();
    let gateway = UpstreamProxy::start(ca.server_config(PROXY_NAME), Behavior::Status(200)).await;
    let mut config = agent_config(gateway.addr, ca.roots(), PROXY_NAME);
    config.route = Route::Mixed;
    let agent = start_agent(config).await;
    let listener = TcpListener::bind((OTHER_LOOPBACK, 0)).await.unwrap();
    let target = listener.local_addr().unwrap();
    let mut stream = open_tunnel(agent, target).await;
    let (mut origin, _) = listener.accept().await.unwrap();
    stream.write_all(b"one attempt").await.unwrap();
    let mut received = [0; 11];
    origin.read_exact(&mut received).await.unwrap();
    assert_eq!(&received, b"one attempt");
    drop(origin);
    let _ = read_to_end_within(&mut stream, Duration::from_secs(5)).await;
    assert_eq!(gateway.accepted(), 0);
}

#[tokio::test]
async fn mixed_direct_connections_require_local_auth_and_close_on_shutdown() {
    let ca = TestCa::new();
    let gateway = UpstreamProxy::start(ca.server_config(PROXY_NAME), Behavior::Status(403)).await;
    let mut config = agent_config(gateway.addr, ca.roots(), PROXY_NAME);
    config.route = Route::Mixed;
    config.local_auth = LocalAuth::SESSION_CREDENTIALS;
    let proxy = Proxy::bind(config).await.unwrap();
    let agent = proxy.local_addr();
    let issued = proxy.credentials().unwrap();
    let issued = basic(issued.username(), issued.password());
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let running = tokio::spawn(proxy.run_until(async {
        let _ = stopped.await;
    }));
    let listener = TcpListener::bind((OTHER_LOOPBACK, 0)).await.unwrap();
    let target = listener.local_addr().unwrap();
    let (_, refused) = send(agent, &connect_request(&target.to_string())).await;
    assert_eq!(refused.status, 407);
    assert!(
        timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
    let (mut stream, response) =
        send(agent, &connect_with(&target.to_string(), Some(&issued))).await;
    assert_eq!(response.status, 200);
    let (mut origin, _) = listener.accept().await.unwrap();
    let (_, refused) = send(
        agent,
        &connect_with(&target.to_string(), Some(&basic("alice", "secret"))),
    )
    .await;
    assert_eq!(refused.status, 407);
    stop.send(()).unwrap();
    running.await.unwrap();
    assert!(
        read_to_end_within(&mut stream, Duration::from_secs(5))
            .await
            .is_empty()
    );
    let mut byte = [0];
    assert_eq!(
        timeout(Duration::from_secs(5), origin.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(tokio::net::TcpStream::connect(agent).await.is_err());
    assert_eq!(gateway.accepted(), 0);
}

#[tokio::test]
async fn gateway_tls_failure_after_direct_failure_does_not_retry_the_target() {
    let trusted = TestCa::new();
    let untrusted = TestCa::new();
    let gateway = UpstreamProxy::start(untrusted.server_config(PROXY_NAME), Behavior::Tunnel).await;
    let mut config = agent_config(gateway.addr, trusted.roots(), PROXY_NAME);
    config.route = Route::Mixed;
    let agent = start_agent(config).await;
    let listener = TcpListener::bind((OTHER_LOOPBACK, 0)).await.unwrap();
    let target: SocketAddr = listener.local_addr().unwrap();
    drop(listener);
    let (_, response) = send(agent, &connect_request(&target.to_string())).await;
    assert_eq!(response.status, 502);
    assert_eq!(gateway.accepted(), 1);
    assert!(gateway.requests().is_empty());
}
