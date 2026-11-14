#![cfg(target_os = "linux")]

#[allow(dead_code)]
mod fixture;

use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fixture::*;
use gateinto::proxy::{Config, LocalAuth, Proxy};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::{Layer, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;

const CLOSE_WITHIN: Duration = Duration::from_secs(5);
const SUDO_NOBODY: &str = "GATEINTO_TEST_SUDO_NOBODY";

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

struct Setup {
    _ca: TestCa,
    proxy: SocketAddr,
    target: SocketAddr,
}

impl Setup {
    async fn start() -> Self {
        let ca = TestCa::new();
        let upstream = UpstreamProxy::start(ca.server_config(PROXY_NAME), Behavior::Tunnel).await;
        let config = Config {
            local_auth: LocalAuth::OS_USER,
            ..agent_config(upstream.addr, ca.roots(), PROXY_NAME)
        };
        let proxy = Proxy::bind(config).await.unwrap();
        let addr = proxy.local_addr();
        tokio::spawn(proxy.run());
        Self {
            _ca: ca,
            proxy: addr,
            target: echo_server().await,
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_connection_from_the_current_user_tunnels_without_credentials() {
    let setup = Setup::start().await;
    let (mut stream, response) =
        send(setup.proxy, &connect_request(&setup.target.to_string())).await;
    assert_eq!(response.status, 200, "{}", response.head);
    stream.write_all(b"as the same user").await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(
        read_to_end_within(&mut stream, CLOSE_WITHIN).await,
        b"as the same user"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_connection_from_another_user_is_forbidden_and_logged() {
    if std::env::var_os(SUDO_NOBODY).is_none_or(|value| value != "1") {
        eprintln!("skipped: set {SUDO_NOBODY}=1 where `sudo -n -u nobody` works");
        return;
    }
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
    let setup = Setup::start().await;
    let client = Command::new("/usr/bin/sudo")
        .args(["-n", "-u", "nobody", "/bin/bash", "-c"])
        .arg(
            "exec 3<>/dev/tcp/127.0.0.1/$1 && \
             printf 'CONNECT %s HTTP/1.1\\r\\nHost: %s\\r\\n\\r\\n' \"$2\" \"$2\" >&3 && \
             cat <&3",
        )
        .args([
            "bash".to_owned(),
            setup.proxy.port().to_string(),
            setup.target.to_string(),
        ])
        .kill_on_drop(true)
        .output();
    let output = tokio::time::timeout(Duration::from_secs(30), client)
        .await
        .expect("the client under sudo did not finish")
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{}: {stdout}{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{stdout}");

    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    let denied = logs
        .lines()
        .find(|line| line.contains("os_user denied the connection"))
        .unwrap_or_else(|| panic!("no os_user denial in\n{logs}"));
    assert!(denied.contains("WARN"), "{denied}");
    assert!(denied.contains("another OS user"), "{denied}");
}
