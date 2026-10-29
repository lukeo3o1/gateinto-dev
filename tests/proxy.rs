#[allow(dead_code)]
mod fixture;
#[cfg(feature = "test-hooks")]
mod isolated;

use std::net::SocketAddr;
use std::time::Duration;

use fixture::*;
use gateinto::proxy::{Config, Error, Limits, Proxy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

const CLOSE_WITHIN: Duration = Duration::from_secs(5);
const KEEP_OPEN_IDLE_TIMEOUT: Duration = Duration::from_secs(3);
const KEEP_OPEN_EVERY: Duration = Duration::from_millis(500);
const KEEP_OPEN_ROUNDS: usize = 12;

struct Setup {
    ca: TestCa,
    upstream: UpstreamProxy,
}

impl Setup {
    async fn new(behavior: Behavior) -> Self {
        let ca = TestCa::new();
        let upstream = UpstreamProxy::start(ca.server_config(PROXY_NAME), behavior).await;
        Self { ca, upstream }
    }

    fn config(&self) -> Config {
        agent_config(self.upstream.addr, self.ca.roots(), PROXY_NAME)
    }

    async fn agent(&self) -> SocketAddr {
        start_agent(self.config()).await
    }
}

async fn assert_refused(agent: SocketAddr, target: &str, status: u16) -> Response {
    let (mut stream, response) = send(agent, &connect_request(target)).await;
    assert_eq!(response.status, status, "{}", response.head);
    read_to_end_within(&mut stream, CLOSE_WITHIN).await;
    response
}

#[tokio::test(flavor = "multi_thread")]
async fn relays_binary_data_in_both_directions() {
    let setup = Setup::new(Behavior::Tunnel).await;
    let agent = setup.agent().await;
    let target = echo_server().await;
    let stream = open_tunnel(agent, target).await;

    let sent = payload(8 * 1024 * 1024);
    let (mut reader, mut writer) = stream.into_split();
    let to_send = sent.clone();
    let writing = tokio::spawn(async move {
        writer.write_all(&to_send).await.unwrap();
        writer.shutdown().await.unwrap();
    });
    let mut received = Vec::new();
    timeout(Duration::from_secs(30), reader.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    writing.await.unwrap();

    assert_eq!(received.len(), sent.len());
    assert!(received == sent);
    assert_eq!(
        setup.upstream.requests(),
        vec![format!(
            "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n"
        )]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn inner_tls_passes_through_the_tunnel() {
    let setup = Setup::new(Behavior::Tunnel).await;
    let agent = setup.agent().await;
    let origin_ca = TestCa::new();
    let origin = tls_echo_origin(origin_ca.server_config("origin.test")).await;
    let stream = open_tunnel(agent, origin).await;

    let tls = inner_tls(stream, origin_ca.client_config(), "origin.test").await;
    let sent = payload(256 * 1024);
    let (mut reader, mut writer) = tokio::io::split(tls);
    let to_send = sent.clone();
    let writing = tokio::spawn(async move {
        writer.write_all(&to_send).await.unwrap();
        writer.flush().await.unwrap();
    });
    let mut received = vec![0; sent.len()];
    timeout(Duration::from_secs(30), reader.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    writing.await.unwrap();

    assert!(received == sent);
}

#[tokio::test(flavor = "multi_thread")]
async fn forwards_client_bytes_sent_with_the_connect_request() {
    let setup = Setup::new(Behavior::Tunnel).await;
    let agent = setup.agent().await;
    let target = echo_server().await;
    let early = payload(3000);
    let mut request = connect_request(&target.to_string());
    request.extend_from_slice(&early);

    let (mut stream, response) = send(agent, &request).await;
    assert_eq!(response.status, 200);
    stream.shutdown().await.unwrap();
    let mut received = response.rest;
    received.extend(read_to_end_within(&mut stream, CLOSE_WITHIN).await);

    assert!(received == early);
}

#[tokio::test(flavor = "multi_thread")]
async fn forwards_upstream_bytes_sent_with_its_response() {
    let setup = Setup::new(Behavior::TunnelWithBanner(b"banner\0\xff")).await;
    let agent = setup.agent().await;
    let target = echo_server().await;

    let (mut stream, response) = send(agent, &connect_request(&target.to_string())).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.head, "HTTP/1.1 200 Connection Established\r\n\r\n");
    stream.shutdown().await.unwrap();
    let mut received = response.rest;
    received.extend(read_to_end_within(&mut stream, CLOSE_WITHIN).await);

    assert_eq!(received, b"banner\0\xff");
}

#[tokio::test(flavor = "multi_thread")]
async fn half_close_still_delivers_upstream_data() {
    let setup = Setup::new(Behavior::Tunnel).await;
    let agent = setup.agent().await;
    let target = reply_after_eof_server().await;
    let mut stream = open_tunnel(agent, target).await;

    let sent = payload(100_000);
    stream.write_all(&sent).await.unwrap();
    stream.shutdown().await.unwrap();
    let received = read_to_end_within(&mut stream, CLOSE_WITHIN).await;

    let mut expected = sent;
    expected.reverse();
    assert!(received == expected);
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_forbidden_maps_to_403() {
    let setup = Setup::new(Behavior::Status(403)).await;
    let response = assert_refused(setup.agent().await, "example.test:443", 403).await;
    assert!(!response.head.contains(SECRET));
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_proxy_auth_required_maps_to_502_without_its_headers_or_body() {
    let setup = Setup::new(Behavior::Status(407)).await;
    let agent = setup.agent().await;
    let (mut stream, response) = send(agent, &connect_request("example.test:443")).await;
    let rest = read_to_end_within(&mut stream, CLOSE_WITHIN).await;

    assert_eq!(response.status, 502);
    let all = format!("{}{}", response.head, String::from_utf8_lossy(&rest));
    assert!(
        !all.to_ascii_lowercase().contains("proxy-authenticate"),
        "{all}"
    );
    assert!(!all.contains(SECRET), "{all}");
    assert!(response.rest.is_empty() && rest.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn other_upstream_statuses_map_to_502() {
    for code in [101, 301, 302, 404, 500, 503] {
        let setup = Setup::new(Behavior::Status(code)).await;
        assert_refused(setup.agent().await, "example.test:443", 502).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_closing_without_response_maps_to_502() {
    let setup = Setup::new(Behavior::Close).await;
    assert_refused(setup.agent().await, "example.test:443", 502).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unreachable_upstream_maps_to_502() {
    let ca = TestCa::new();
    let config = agent_config(unused_port().await, ca.roots(), PROXY_NAME);
    assert_refused(start_agent(config).await, "example.test:443", 502).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_without_tls_maps_to_502() {
    let ca = TestCa::new();
    let config = agent_config(echo_server().await, ca.roots(), PROXY_NAME);
    assert_refused(start_agent(config).await, "example.test:443", 502).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_hanging_after_connect_maps_to_504() {
    let setup = Setup::new(Behavior::Hang).await;
    let mut config = setup.config();
    config.limits.handshake_timeout = Duration::from_millis(300);
    let agent = start_agent(config).await;
    assert_refused(agent, "example.test:443", 504).await;
    assert_eq!(setup.upstream.requests().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_hanging_during_tls_handshake_maps_to_504() {
    let ca = TestCa::new();
    let mut config = agent_config(silent_server().await, ca.roots(), PROXY_NAME);
    config.limits.handshake_timeout = Duration::from_millis(300);
    assert_refused(start_agent(config).await, "example.test:443", 504).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_certificate_from_untrusted_ca_is_rejected() {
    let setup = Setup::new(Behavior::Tunnel).await;
    let config = agent_config(setup.upstream.addr, TestCa::new().roots(), PROXY_NAME);
    let target = echo_server().await.to_string();
    assert_refused(start_agent(config).await, &target, 502).await;
    assert!(setup.upstream.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_certificate_for_another_name_is_rejected() {
    let setup = Setup::new(Behavior::Tunnel).await;
    let config = agent_config(setup.upstream.addr, setup.ca.roots(), "other.test");
    let target = echo_server().await.to_string();
    assert_refused(start_agent(config).await, &target, 502).await;
    assert!(setup.upstream.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn rejects_other_methods_with_405() {
    let setup = Setup::new(Behavior::Tunnel).await;
    let agent = setup.agent().await;
    let (mut stream, response) = send(
        agent,
        b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n",
    )
    .await;
    read_to_end_within(&mut stream, CLOSE_WITHIN).await;

    assert_eq!(response.status, 405);
    assert!(response.head.contains("\r\nAllow: CONNECT\r\n"));
    assert!(setup.upstream.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn rejects_malformed_requests_with_400() {
    let setup = Setup::new(Behavior::Tunnel).await;
    let agent = setup.agent().await;
    for request in [
        &b"CONNECT example.test:443 HTTP/1.1\nHost: example.test:443\n\n"[..],
        b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\nX: a\0\r\n\r\n",
        b"CONNECT example.test HTTP/1.1\r\nHost: example.test\r\n\r\n",
    ] {
        let (mut stream, response) = send(agent, request).await;
        read_to_end_within(&mut stream, CLOSE_WITHIN).await;
        assert_eq!(response.status, 400);
    }
    assert!(setup.upstream.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn rejects_oversized_request_heads_with_431() {
    let setup = Setup::new(Behavior::Tunnel).await;
    let mut config = setup.config();
    config.limits.max_header_bytes = 1024;
    let agent = start_agent(config).await;
    let mut request =
        b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\nX: ".to_vec();
    request.resize(2000, b'x');
    request.extend_from_slice(b"\r\n\r\n");

    let (mut stream, response) = send(agent, &request).await;
    read_to_end_within(&mut stream, CLOSE_WITHIN).await;

    assert_eq!(response.status, 431);
    assert!(setup.upstream.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_head_at_the_limit_is_tunneled_and_one_byte_more_is_431() {
    let setup = Setup::new(Behavior::Tunnel).await;
    let mut config = setup.config();
    config.limits.max_header_bytes = 1024;
    let agent = start_agent(config).await;
    let target = echo_server().await;
    let request = connect_request(&target.to_string());

    let (mut stream, response) = send(agent, &pad_head(&request, 1025)).await;
    read_to_end_within(&mut stream, CLOSE_WITHIN).await;
    assert_eq!(response.status, 431, "{}", response.head);
    assert!(setup.upstream.requests().is_empty());

    let (mut stream, response) = send(agent, &pad_head(&request, 1024)).await;
    assert_eq!(response.status, 200, "{}", response.head);
    stream.write_all(b"at the limit").await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(
        read_to_end_within(&mut stream, CLOSE_WITHIN).await,
        b"at the limit"
    );
    assert_eq!(setup.upstream.requests().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn incomplete_request_head_times_out_with_408() {
    let setup = Setup::new(Behavior::Tunnel).await;
    let mut config = setup.config();
    config.limits.handshake_timeout = Duration::from_millis(300);
    let agent = start_agent(config).await;

    let (mut stream, response) = send(agent, b"CONNECT example.test:443 HTTP/1.1\r\n").await;
    read_to_end_within(&mut stream, CLOSE_WITHIN).await;

    assert_eq!(response.status, 408);
}

#[tokio::test(flavor = "multi_thread")]
async fn rejects_tunnels_beyond_the_limit_with_503() {
    let setup = Setup::new(Behavior::Tunnel).await;
    let mut config = setup.config();
    config.limits.max_tunnels = 1;
    let agent = start_agent(config).await;
    let target = echo_server().await;
    let mut first = open_tunnel(agent, target).await;

    assert_refused(agent, &target.to_string(), 503).await;

    first.write_all(b"still open").await.unwrap();
    let mut echoed = [0; 10];
    first.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"still open");
    first.shutdown().await.unwrap();
    read_to_end_within(&mut first, CLOSE_WITHIN).await;
    drop(first);

    let deadline = tokio::time::Instant::now() + CLOSE_WITHIN;
    loop {
        let (_stream, response) = send(agent, &connect_request(&target.to_string())).await;
        if response.status == 200 {
            break;
        }
        assert_eq!(response.status, 503);
        assert!(
            tokio::time::Instant::now() < deadline,
            "permit was not released"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[test]
fn rejected_connections_linger_for_one_second_by_default() {
    assert_eq!(Limits::default().reject_linger, Duration::from_secs(1));
}

#[tokio::test(flavor = "multi_thread")]
async fn closes_excess_connections_without_a_response_while_rejects_are_pending() {
    let setup = Setup::new(Behavior::Tunnel).await;
    let mut config = setup.config();
    config.limits.max_tunnels = 1;
    config.limits.max_pending_rejects = 1;
    config.limits.reject_linger = Duration::from_secs(3600);
    let agent = start_agent(config).await;
    let target = echo_server().await;
    let _tunnel = open_tunnel(agent, target).await;

    let mut lingering = tokio::net::TcpStream::connect(agent).await.unwrap();
    assert_eq!(read_response(&mut lingering).await.status, 503);

    let mut excess = tokio::net::TcpStream::connect(agent).await.unwrap();
    assert!(
        read_to_end_within(&mut excess, CLOSE_WITHIN)
            .await
            .is_empty()
    );

    drop(lingering);
    let deadline = tokio::time::Instant::now() + CLOSE_WITHIN;
    loop {
        let mut stream = tokio::net::TcpStream::connect(agent).await.unwrap();
        if read_response(&mut stream).await.status == 503 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "reject permit was not released"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn idle_tunnels_are_closed() {
    let setup = Setup::new(Behavior::Tunnel).await;
    let mut config = setup.config();
    config.limits.idle_timeout = KEEP_OPEN_IDLE_TIMEOUT;
    let agent = start_agent(config).await;
    let mut stream = open_tunnel(agent, echo_server().await).await;

    for _ in 0..KEEP_OPEN_ROUNDS {
        tokio::time::sleep(KEEP_OPEN_EVERY).await;
        stream.write_all(b"ping").await.unwrap();
        let mut echoed = [0; 4];
        stream.read_exact(&mut echoed).await.unwrap();
    }
    let started = tokio::time::Instant::now();
    let rest = read_to_end_within(&mut stream, KEEP_OPEN_IDLE_TIMEOUT + CLOSE_WITHIN).await;

    assert!(rest.is_empty());
    assert!(started.elapsed() >= KEEP_OPEN_IDLE_TIMEOUT - KEEP_OPEN_EVERY);
}

#[tokio::test(flavor = "multi_thread")]
async fn upload_only_traffic_keeps_the_tunnel_open() {
    let setup = Setup::new(Behavior::Tunnel).await;
    let mut config = setup.config();
    config.limits.idle_timeout = KEEP_OPEN_IDLE_TIMEOUT;
    let agent = start_agent(config).await;
    let mut stream = open_tunnel(agent, reply_after_eof_server().await).await;

    for _ in 0..KEEP_OPEN_ROUNDS {
        tokio::time::sleep(KEEP_OPEN_EVERY).await;
        stream.write_all(b"ab").await.unwrap();
    }
    stream.shutdown().await.unwrap();

    assert_eq!(
        read_to_end_within(&mut stream, CLOSE_WITHIN).await,
        b"ba".repeat(KEEP_OPEN_ROUNDS)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn download_only_traffic_keeps_the_tunnel_open() {
    let setup = Setup::new(Behavior::Tunnel).await;
    let mut config = setup.config();
    config.limits.idle_timeout = KEEP_OPEN_IDLE_TIMEOUT;
    let agent = start_agent(config).await;
    let target = drip_server(b"tick", KEEP_OPEN_ROUNDS, KEEP_OPEN_EVERY).await;
    let (mut stream, response) = send(agent, &connect_request(&target.to_string())).await;
    assert_eq!(response.status, 200, "{}", response.head);

    let dripping = KEEP_OPEN_EVERY * u32::try_from(KEEP_OPEN_ROUNDS).unwrap();
    let mut received = response.rest;
    received.extend(read_to_end_within(&mut stream, dripping + CLOSE_WITHIN).await);
    assert_eq!(received, b"tick".repeat(KEEP_OPEN_ROUNDS));
}

#[tokio::test(flavor = "multi_thread")]
async fn refuses_any_non_loopback_listen_address() {
    let setup = Setup::new(Behavior::Tunnel).await;
    for listen in ["0.0.0.0:0", "[::]:0", "192.0.2.1:0"] {
        let mut config = setup.config();
        config.listen = listen.parse().unwrap();
        match Proxy::bind(config).await {
            Err(error @ Error::NonLoopbackListen(addr)) => {
                assert_eq!(addr, listen.parse().unwrap());
                assert_eq!(
                    error.to_string(),
                    format!("refusing to listen on non-loopback address {addr}")
                );
            }
            other => panic!("{listen}: {:?}", other.map(|proxy| proxy.local_addr())),
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn refuses_tunnel_limits_beyond_the_http2_window_bound() {
    let setup = Setup::new(Behavior::Tunnel).await;
    let mut config = setup.config();
    config.limits.max_tunnels = gateinto::proxy::MAX_TUNNELS as usize;
    Proxy::bind(config).await.unwrap();
    let mut config = setup.config();
    config.limits.max_tunnels = gateinto::proxy::MAX_TUNNELS as usize + 1;
    match Proxy::bind(config).await {
        Err(Error::TunnelLimit(limit)) => {
            assert_eq!(limit, gateinto::proxy::MAX_TUNNELS as usize + 1)
        }
        other => panic!("{:?}", other.map(|proxy| proxy.local_addr())),
    }
}

fn write_temp(name: &str, contents: &[u8]) -> std::path::PathBuf {
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("{}-{n}-{name}", std::process::id()));
    std::fs::write(&path, contents).unwrap();
    path
}

#[test]
fn loads_ca_bundle_from_pem_file() {
    let first = TestCa::new();
    let second = TestCa::new();
    let bundle = format!("{}\n{}", first.pem(), second.pem());
    let path = write_temp("bundle.pem", bundle.as_bytes());

    let roots = gateinto::tls::load_pem_roots(&path).unwrap();

    assert_eq!(roots.len(), 2);
}

#[test]
fn rejects_ca_bundle_without_certificates() {
    let path = write_temp("empty.pem", b"not a certificate\n");
    assert!(gateinto::tls::load_pem_roots(&path).is_err());
    let missing = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("missing.pem");
    assert!(gateinto::tls::load_pem_roots(&missing).is_err());
}

#[test]
fn default_roots_are_not_empty() {
    assert!(!gateinto::tls::webpki_roots().is_empty());
}

#[cfg(feature = "test-hooks")]
struct Child(std::process::Child);

#[cfg(feature = "test-hooks")]
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(feature = "test-hooks")]
struct Agent {
    child: Child,
    addr: SocketAddr,
    authorization: String,
    startup: Vec<String>,
    stderr: std::io::Lines<std::io::BufReader<std::process::ChildStderr>>,
}

#[cfg(feature = "test-hooks")]
impl Agent {
    async fn spawn(setup: &Setup, log_filter: &str) -> Self {
        Self::spawn_with(setup, log_filter, &[]).await
    }

    async fn spawn_with(setup: &Setup, log_filter: &str, extra: &[&str]) -> Self {
        let ca_file = write_temp("cli-ca.pem", setup.ca.pem().as_bytes());
        let prompt = write_temp("credentials-prompt.txt", b"");
        let mut child = Child(
            isolated::gateinto()
                .args(["session", "browser", "--upstream-host", "127.0.0.1"])
                .args(["--upstream-port", &setup.upstream.addr.port().to_string()])
                .args(["--upstream-server-name", PROXY_NAME])
                .arg("--ca-file")
                .arg(&ca_file)
                .args(extra)
                .env("RUST_LOG", log_filter)
                .env("GATEINTO_TEST_CREDENTIALS_FILE", &prompt)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let stderr = child.0.stderr.take().unwrap();
        let (addr, startup, stderr) = tokio::task::spawn_blocking(move || {
            use std::io::BufRead;
            let mut lines = std::io::BufReader::new(stderr).lines();
            let mut startup = Vec::new();
            loop {
                let line = lines
                    .next()
                    .unwrap_or_else(|| panic!("session exited before listening: {startup:?}"))
                    .unwrap();
                if let Some((_, addr)) = line.split_once("local_addr=") {
                    let addr = addr.split_whitespace().next().unwrap().parse().unwrap();
                    return (addr, startup, lines);
                }
                startup.push(line);
            }
        })
        .await
        .unwrap();
        let (username, password) = tokio::task::spawn_blocking(move || shown_credentials(&prompt))
            .await
            .unwrap();
        Self {
            child,
            addr,
            authorization: basic(&username, &password),
            startup,
            stderr,
        }
    }

    async fn stop(mut self) -> String {
        let _ = self.child.0.kill();
        let _ = self.child.0.wait();
        tokio::task::spawn_blocking(move || {
            self.startup
                .into_iter()
                .chain(self.stderr.map_while(Result::ok))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .await
        .unwrap()
    }
}

#[cfg(feature = "test-hooks")]
fn shown_credentials(prompt: &std::path::Path) -> (String, String) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let text = std::fs::read_to_string(prompt).unwrap_or_default();
        let value = |name: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix(name))
                .map(str::to_owned)
        };
        if let (Some(username), Some(password)) = (value("Username: "), value("Password: ")) {
            return (username, password);
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no credentials were shown: {text:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(feature = "test-hooks")]
async fn echo_through(agent: &Agent, target: SocketAddr) {
    let request = connect_with(&target.to_string(), Some(&agent.authorization));
    let (mut stream, response) = send(agent.addr, &request).await;
    assert_eq!(response.status, 200, "{}", response.head);
    assert!(response.rest.is_empty());
    stream.write_all(b"through the binary").await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(
        read_to_end_within(&mut stream, CLOSE_WITHIN).await,
        b"through the binary"
    );
}

#[cfg(feature = "test-hooks")]
#[tokio::test(flavor = "multi_thread")]
async fn session_browser_relays_through_the_upstream() {
    let setup = Setup::new(Behavior::Tunnel).await;
    let agent = Agent::spawn(&setup, "info").await;
    echo_through(&agent, echo_server().await).await;
    agent.stop().await;
}

#[cfg(feature = "test-hooks")]
#[tokio::test(flavor = "multi_thread")]
async fn session_browser_requires_its_session_credentials() {
    let setup = Setup::new(Behavior::Tunnel).await;
    let agent = Agent::spawn(&setup, "info").await;
    let target = echo_server().await.to_string();
    let (_, response) = send(agent.addr, &connect_with(&target, None)).await;
    assert_eq!(response.status, 407, "{}", response.head);
    agent.stop().await;
}

#[cfg(feature = "test-hooks")]
#[tokio::test(flavor = "multi_thread")]
async fn tunnel_target_is_logged_only_at_debug() {
    let setup = Setup::new(Behavior::Tunnel).await;
    let target = echo_server().await;

    let agent = Agent::spawn(&setup, "info").await;
    echo_through(&agent, target).await;
    let info = agent.stop().await;
    assert!(!info.contains(&target.to_string()), "{info}");

    let agent = Agent::spawn(&setup, "debug").await;
    echo_through(&agent, target).await;
    let debug = agent.stop().await;
    assert!(debug.contains(&target.to_string()), "{debug}");
}

#[cfg(feature = "test-hooks")]
const NOT_CONFIGURED: &str =
    "mTLS is not configured and upstream connections do not authenticate this device";
#[cfg(feature = "test-hooks")]
const MISSING_KEY: &str = "gateinto-test-missing-device-key";

#[cfg(feature = "test-hooks")]
#[tokio::test(flavor = "multi_thread")]
async fn optional_client_certificate_without_a_device_identity_warns_once_and_relays() {
    let setup = Setup::new(Behavior::Tunnel).await;
    let target = echo_server().await;

    for extra in [
        &["--key-name", MISSING_KEY][..],
        &[
            "--key-name",
            MISSING_KEY,
            "--client-certificate",
            "optional",
        ],
    ] {
        let agent = Agent::spawn_with(&setup, "info", extra).await;
        echo_through(&agent, target).await;
        echo_through(&agent, target).await;
        let log = agent.stop().await;
        assert_eq!(log.matches(NOT_CONFIGURED).count(), 1, "{log}");
        assert!(log.contains("WARN"), "{log}");
    }
}

#[cfg(feature = "test-hooks")]
#[tokio::test(flavor = "multi_thread")]
async fn disabled_client_certificate_relays_without_the_warning() {
    let setup = Setup::new(Behavior::Tunnel).await;
    let agent = Agent::spawn_with(
        &setup,
        "info",
        &["--key-name", MISSING_KEY, "--client-certificate", "off"],
    )
    .await;
    echo_through(&agent, echo_server().await).await;
    let log = agent.stop().await;
    assert!(!log.contains(NOT_CONFIGURED), "{log}");
}

#[cfg(feature = "test-hooks")]
#[tokio::test(flavor = "multi_thread")]
async fn negotiated_key_exchange_group_is_logged_per_tunnel_at_debug() {
    let setup = Setup::new(Behavior::Tunnel).await;
    let target = echo_server().await;
    for (extra, group) in [
        (&[][..], "key_exchange_group=Some(X25519MLKEM768)"),
        (
            &["--tls-mode", "hybrid_preferred"],
            "key_exchange_group=Some(X25519MLKEM768)",
        ),
        (
            &["--tls-mode", "hybrid_required"],
            "key_exchange_group=Some(X25519MLKEM768)",
        ),
        (
            &["--tls-mode", "classical_only"],
            "key_exchange_group=Some(X25519)",
        ),
    ] {
        let agent = Agent::spawn_with(&setup, "debug", extra).await;
        echo_through(&agent, target).await;
        echo_through(&agent, target).await;
        let log = agent.stop().await;
        assert_eq!(log.matches(group).count(), 2, "{extra:?}: {log}");
        assert_eq!(log.matches("version=Some(TLSv1_3)").count(), 2, "{log}");
    }

    let agent = Agent::spawn(&setup, "info").await;
    echo_through(&agent, target).await;
    let info = agent.stop().await;
    assert!(!info.contains("key_exchange_group"), "{info}");
}
