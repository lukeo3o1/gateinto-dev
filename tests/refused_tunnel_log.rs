#[allow(dead_code)]
mod fixture;

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fixture::*;
use gateinto::proxy::LocalAuth;
use gateinto::sessions::{SessionConfig, SessionKind, SessionManager};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::{Layer, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;

const TARGET: &str = "blocked.example.test:8443";

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

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_tunnel_is_logged_with_its_target_and_without_credentials() {
    let captured = Captured::default();
    let writer = captured.clone();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .with_filter(LevelFilter::WARN),
        )
        .init();
    let ca = TestCa::new();
    let upstream = UpstreamProxy::start(ca.server_config(PROXY_NAME), Behavior::Status(403)).await;
    let mut config = agent_config(upstream.addr, ca.roots(), PROXY_NAME);
    config.local_auth = LocalAuth::SESSION_CREDENTIALS;
    let mut sessions = SessionManager::new();
    let id = sessions
        .start(SessionConfig {
            kind: SessionKind::Browser,
            gateway: "office".parse().unwrap(),
            proxy: config,
        })
        .await
        .unwrap();
    let session = sessions.session(id).unwrap();
    let agent = session.local_addr();
    let issued = session.credentials().unwrap().clone();
    let authorization = basic(issued.username(), issued.password());

    let (mut stream, response) = send(agent, &connect_with(TARGET, Some(&authorization))).await;
    assert_eq!(response.status, 403, "{}", response.head);
    read_to_end_within(&mut stream, Duration::from_secs(5)).await;
    sessions.close_all().await;

    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    let refused = logs
        .lines()
        .find(|line| line.contains("upstream refused tunnel"))
        .unwrap_or_else(|| panic!("no refused tunnel warning in\n{logs}"));
    assert!(refused.contains("WARN"), "{refused}");
    assert!(refused.contains(&format!("target={TARGET}")), "{refused}");
    for secret in [
        issued.password(),
        &authorization["Basic ".len()..],
        "Proxy-Authorization",
    ] {
        assert!(!logs.contains(secret), "{secret} leaked into\n{logs}");
    }
}
