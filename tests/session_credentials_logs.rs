#[allow(dead_code)]
mod fixture;

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fixture::*;
use gateinto::proxy::{FailureLimit, LocalAuth};
use gateinto::sessions::{SessionConfig, SessionKind, SessionManager};
use tokio::io::AsyncWriteExt;

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
async fn logs_never_contain_the_credentials() {
    let captured = Captured::default();
    let writer = captured.clone();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .init();
    let ca = TestCa::new();
    let upstream = UpstreamProxy::start(ca.server_config(PROXY_NAME), Behavior::Tunnel).await;
    let target = echo_server().await.to_string();
    let mut config = agent_config(upstream.addr, ca.roots(), PROXY_NAME);
    config.local_auth = LocalAuth::SessionCredentials;
    config.limits.local_auth_failures = FailureLimit {
        max_failures: 4,
        window: Duration::from_secs(600),
    };
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
    let (username, password) = (issued.username(), issued.password());
    let wrong_password = "wr0ng-Pa55word";
    let right = basic(username, password);
    let wrong = basic(username, wrong_password);
    let malformed = format!(
        "Basic {}",
        base64(format!("{username}{password}").as_bytes())
    );

    let (mut stream, response) = send(agent, &connect_with(&target, Some(&right))).await;
    assert_eq!(response.status, 200, "{}", response.head);
    stream.write_all(b"logged").await.unwrap();
    stream.shutdown().await.unwrap();
    read_to_end_within(&mut stream, Duration::from_secs(5)).await;
    let mut statuses = Vec::new();
    for value in [&wrong, &malformed, &wrong, &wrong, &right] {
        statuses.push(
            send(agent, &connect_with(&target, Some(value)))
                .await
                .1
                .status,
        );
    }
    assert_eq!(statuses, [407, 400, 407, 407, 429]);
    sessions.close_all().await;

    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    for expected in [
        "tunnel established",
        "differ from the ones issued",
        "malformed local proxy credential",
        "rate limited",
    ] {
        assert!(logs.contains(expected), "{expected} missing from\n{logs}");
    }
    for secret in [
        username,
        password,
        wrong_password,
        &right["Basic ".len()..],
        &wrong["Basic ".len()..],
        &malformed["Basic ".len()..],
    ] {
        assert!(!logs.contains(secret), "{secret} leaked into\n{logs}");
    }
}
