#[allow(dead_code)]
mod fixture;

use std::io::Write;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fixture::*;
use gateinto::ipc::{LogPage, Response};
use gateinto::logbook::Logbook;
use gateinto::proxy::Route;
use tokio::io::AsyncWriteExt;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::{Layer, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;

const OTHER_LOOPBACK: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
const SUCCESS_LINES: [&str; 2] = ["tunnel established", "selected tunnel route"];

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

impl Captured {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

async fn echo_through(agent: std::net::SocketAddr, target: std::net::SocketAddr) {
    let mut stream = open_tunnel(agent, target).await;
    stream.write_all(b"echo").await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(
        read_to_end_within(&mut stream, Duration::from_secs(5)).await,
        b"echo"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn successful_tunnels_log_their_route_and_establishment_only_at_debug() {
    let book = Logbook::default();
    let info = Captured::default();
    let debug = Captured::default();
    let (info_writer, debug_writer) = (info.clone(), debug.clone());
    tracing_subscriber::registry()
        .with(book.layer().with_filter(LevelFilter::INFO))
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(move || info_writer.clone())
                .with_filter(LevelFilter::INFO),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(move || debug_writer.clone())
                .with_filter(LevelFilter::DEBUG),
        )
        .init();

    let ca = TestCa::new();
    let gateway = UpstreamProxy::start(ca.server_config(PROXY_NAME), Behavior::Tunnel).await;
    let agent = start_agent(agent_config(gateway.addr, ca.roots(), PROXY_NAME)).await;
    echo_through(agent, echo_server_on(OTHER_LOOPBACK).await).await;
    assert_eq!(gateway.requests().len(), 1);

    let refusing = UpstreamProxy::start(ca.server_config(PROXY_NAME), Behavior::Status(403)).await;
    let mut config = agent_config(refusing.addr, ca.roots(), PROXY_NAME);
    config.route = Route::Mixed;
    let agent = start_agent(config).await;
    echo_through(agent, echo_server_on(OTHER_LOOPBACK).await).await;
    assert_eq!(refusing.accepted(), 0);

    let Response::Ok(lines) = book.response(0) else {
        panic!("a log response is ok");
    };
    let page = LogPage::parse(&lines).unwrap();
    let info = info.text();
    for line in SUCCESS_LINES {
        assert!(!info.contains(line), "{line} logged at INFO in\n{info}");
        assert!(
            page.events
                .iter()
                .all(|event| !event.message.contains(line)),
            "{line} reached the logbook: {:?}",
            page.events
        );
    }

    let debug = debug.text();
    for expected in [
        "selected tunnel route route=\"gateway\"",
        "selected tunnel route route=\"direct\"",
        "tunnel established",
    ] {
        let found = debug
            .lines()
            .filter(|line| line.contains(expected))
            .collect::<Vec<_>>();
        assert!(
            !found.is_empty() && found.iter().all(|line| line.contains("DEBUG")),
            "{expected} not logged at DEBUG in\n{debug}"
        );
    }
    assert_eq!(debug.matches("tunnel established").count(), 2, "{debug}");
}
