#[allow(dead_code)]
mod fixture;

use std::io::BufRead;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use fixture::*;
use tokio::io::AsyncWriteExt;

fn temp_dir() -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("config-cli-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_config(dir: &Path, text: &str) -> PathBuf {
    let path = dir.join("gateinto.toml");
    std::fs::write(&path, text).unwrap();
    path
}

fn gateinto(args: &[&str], config: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_gateinto"))
        .args(args)
        .arg("--config")
        .arg(config)
        .output()
        .unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

struct Fixture {
    dir: PathBuf,
    upstream: UpstreamProxy,
}

impl Fixture {
    async fn new() -> Self {
        let ca = TestCa::new();
        let upstream = UpstreamProxy::start(ca.server_config(PROXY_NAME), Behavior::Tunnel).await;
        let dir = temp_dir();
        std::fs::write(dir.join("ca.pem"), ca.pem()).unwrap();
        Self { dir, upstream }
    }

    fn config(&self, extra: &str) -> PathBuf {
        let port = self.upstream.addr.port();
        write_config(
            &self.dir,
            &format!(
                "[gateways.main]\nhost = \"127.0.0.1\"\nport = {port}\nserver_name = \"{PROXY_NAME}\"\nca_file = \"ca.pem\"\n{extra}"
            ),
        )
    }
}

async fn run(args: Vec<String>, config: PathBuf) -> Output {
    tokio::task::spawn_blocking(move || {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        gateinto(&args, &config)
    })
    .await
    .unwrap()
}

fn args(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_owned()).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn check_upstream_reads_the_config_file() {
    let fixture = Fixture::new().await;
    let config = fixture.config("tls_mode = \"classical_only\"\nclient_certificate = \"off\"\n");

    let output = run(args(&["check-upstream"]), config).await;

    assert!(output.status.success(), "{}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("tls-mode: classical_only\n"), "{stdout}");
    assert!(stdout.contains("key-exchange-group: X25519\n"), "{stdout}");
    assert!(
        stdout.contains(&format!("server-name: {PROXY_NAME}\n")),
        "{stdout}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn command_line_flags_override_the_config_file() {
    let fixture = Fixture::new().await;
    let real_port = fixture.upstream.addr.port().to_string();
    let config = write_config(
        &fixture.dir,
        "[gateways.main]\nhost = \"127.0.0.1\"\nport = 9\nserver_name = \"other.test\"\nca_file = \"missing.pem\"\ntls_mode = \"classical_only\"\nclient_certificate = \"required\"\n",
    );
    let ca_file = fixture.dir.join("ca.pem").display().to_string();

    let output = run(
        args(&[
            "check-upstream",
            "--upstream-port",
            &real_port,
            "--upstream-server-name",
            PROXY_NAME,
            "--ca-file",
            &ca_file,
            "--tls-mode",
            "hybrid_required",
            "--client-certificate",
            "off",
        ]),
        config,
    )
    .await;

    assert!(output.status.success(), "{}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("tls-mode: hybrid_required\n"), "{stdout}");
    assert!(
        stdout.contains("key-exchange-group: X25519MLKEM768\n"),
        "{stdout}"
    );
}

#[test]
fn missing_upstream_is_a_clear_error() {
    let dir = temp_dir();
    let config = write_config(&dir, "[gateways.main]\ntls_mode = \"hybrid_required\"\n");
    for command in ["proxy", "check-upstream"] {
        let output = gateinto(&[command], &config);
        assert!(!output.status.success());
        let stderr = stderr(&output);
        assert!(
            stderr.contains(&format!(
                "config file {}: gateway \"main\": no upstream configured",
                config.display()
            )),
            "{stderr}"
        );
        assert!(stderr.contains("--upstream-host"), "{stderr}");
    }
}

#[test]
fn unknown_keys_and_unreadable_files_name_the_file() {
    let dir = temp_dir();
    let config = write_config(
        &dir,
        "[gateways.main]\nhost = \"127.0.0.1\"\nport = 9\nproxy_password = \"x\"\n",
    );
    let missing = dir.join("missing.toml");
    for command in [
        &["proxy"][..],
        &["check-upstream"],
        &["key", "init"],
        &["key", "info"],
    ] {
        let output = gateinto(command, &config);
        assert!(!output.status.success());
        let error = stderr(&output);
        assert!(error.contains(&config.display().to_string()), "{error}");
        assert!(error.contains("unknown field `proxy_password`"), "{error}");
        assert!(error.contains("gateway \"main\""), "{error}");

        let output = gateinto(command, &missing);
        assert!(!output.status.success());
        let error = stderr(&output);
        assert!(error.contains(&missing.display().to_string()), "{error}");
    }
}

#[test]
fn key_commands_read_the_device_key_section() {
    let dir = temp_dir();
    let invalid = write_config(&dir, "[device_key]\nname = \"\"\n");
    for command in ["init", "info"] {
        let output = gateinto(&["key", command], &invalid);
        assert!(!output.status.success());
        assert!(
            stderr(&output).contains("key name must not be empty"),
            "{}",
            stderr(&output)
        );
    }
    #[cfg(not(windows))]
    {
        let valid = write_config(
            &dir,
            "[device_key]\nname = \"gateinto-config\"\npreferred = \"software\"\nsoftware_fallback_on_first_create = false\n",
        );
        for command in ["init", "info"] {
            let output = gateinto(&["key", command], &valid);
            assert!(!output.status.success());
            assert!(
                stderr(&output).contains("device keys are only supported on Windows"),
                "{}",
                stderr(&output)
            );
        }
    }
}

struct Child(std::process::Child);

impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn spawn_proxy(config: PathBuf, extra: &[&str]) -> (Child, SocketAddr) {
    let extra = args(extra);
    tokio::task::spawn_blocking(move || {
        let mut child = Child(
            Command::new(env!("CARGO_BIN_EXE_gateinto"))
                .arg("proxy")
                .arg("--config")
                .arg(&config)
                .args(&extra)
                .env("RUST_LOG", "info")
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut lines = std::io::BufReader::new(child.0.stderr.take().unwrap()).lines();
        loop {
            let line = lines
                .next()
                .expect("proxy exited before listening")
                .unwrap();
            if let Some((_, addr)) = line.split_once("local_addr=") {
                let addr = addr.split_whitespace().next().unwrap().parse().unwrap();
                std::thread::spawn(move || lines.for_each(drop));
                return (child, addr);
            }
        }
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_reads_listen_tls_and_limits_from_the_config_file() {
    let fixture = Fixture::new().await;
    let target = echo_server().await;
    let config = fixture.config(
        "client_certificate = \"off\"\n[device_session]\nlisten = \"127.0.0.1:0\"\n[limits]\nmax_concurrent_tunnels = 1\n",
    );

    let (_child, agent) = spawn_proxy(config.clone(), &[]).await;
    let mut first = open_tunnel(agent, target).await;
    let (_, second) = send(agent, &connect_request(&target.to_string())).await;
    assert_eq!(second.status, 503, "{}", second.head);
    first.shutdown().await.unwrap();

    let (_child, agent) = spawn_proxy(config, &["--max-tunnels", "2"]).await;
    let _first = open_tunnel(agent, target).await;
    let _second = open_tunnel(agent, target).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn non_loopback_listen_from_the_config_file_still_needs_the_flag() {
    let fixture = Fixture::new().await;
    let config =
        fixture.config("client_certificate = \"off\"\n[device_session]\nlisten = \"0.0.0.0:0\"\n");

    let output = run(args(&["proxy"]), config.clone()).await;
    assert!(!output.status.success());
    let error = stderr(&output);
    assert!(
        error.contains("refusing to listen on non-loopback address 0.0.0.0:0"),
        "{error}"
    );
    assert!(
        error.contains("--unsafe-allow-non-loopback-listen"),
        "{error}"
    );

    let (_child, agent) = spawn_proxy(config, &["--unsafe-allow-non-loopback-listen"]).await;
    assert!(agent.ip().is_unspecified(), "{agent}");
}

#[tokio::test]
async fn example_config_is_accepted_up_to_the_network() {
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.example.toml");
    let closed = unused_port().await;
    let output = Command::new(env!("CARGO_BIN_EXE_gateinto"))
        .args(["check-upstream", "--client-certificate", "off"])
        .args(["--upstream-host", &closed.ip().to_string()])
        .args(["--upstream-port", &closed.port().to_string()])
        .arg("--config")
        .arg(&example)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error = stderr(&output);
    assert!(error.contains("connect failed"), "{error}");
    assert!(!error.contains("config file"), "{error}");
}

#[tokio::test(flavor = "multi_thread")]
async fn self_signed_flag_conflicts_with_a_client_cert_file_from_the_config_file() {
    let fixture = Fixture::new().await;
    let config = fixture.config("client_cert_file = \"client.pem\"\n");

    let output = run(
        args(&["check-upstream", "--self-signed-client-cert"]),
        config,
    )
    .await;

    assert!(!output.status.success());
    let error = stderr(&output);
    assert!(
        error.contains(
            "a client certificate file and a self-signed client certificate cannot be combined"
        ),
        "{error}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn check_upstream_selects_a_gateway_by_name() {
    let fixture = Fixture::new().await;
    let closed = unused_port().await.port();
    let config = fixture.config(&format!(
        "tls_mode = \"classical_only\"\nclient_certificate = \"off\"\n\
         [gateways.closed]\nhost = \"127.0.0.1\"\nport = {closed}\nclient_certificate = \"off\"\n\
         [device_session]\ngateway = \"closed\"\n"
    ));

    let output = run(args(&["check-upstream"]), config.clone()).await;
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("connect failed"),
        "{}",
        stderr(&output)
    );

    let output = run(
        args(&["check-upstream", "--gateway", "main"]),
        config.clone(),
    )
    .await;
    assert!(output.status.success(), "{}", stderr(&output));
    let printed = stdout(&output);
    assert!(
        printed.contains(&format!(
            "upstream: 127.0.0.1:{}\n",
            fixture.upstream.addr.port()
        )),
        "{printed}"
    );
    assert!(printed.contains("tls-mode: classical_only\n"), "{printed}");

    let output = run(
        args(&[
            "check-upstream",
            "--gateway",
            "main",
            "--tls-mode",
            "hybrid_required",
        ]),
        config.clone(),
    )
    .await;
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("key-exchange-group: X25519MLKEM768\n"),
        "{}",
        stdout(&output)
    );

    let output = run(
        args(&["check-upstream", "--gateway", "missing"]),
        config.clone(),
    )
    .await;
    assert!(!output.status.success());
    let error = stderr(&output);
    assert!(
        error.contains(&format!(
            "config file {}: --gateway names the unknown gateway \"missing\"; configured \
             gateways: closed, main",
            config.display()
        )),
        "{error}"
    );

    let output = run(args(&["check-upstream", "--gateway", "not valid"]), config).await;
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("invalid gateway name \"not valid\""),
        "{}",
        stderr(&output)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_uses_the_device_session_gateway() {
    let fixture = Fixture::new().await;
    let target = echo_server().await;
    let closed = unused_port().await.port();
    let config = fixture.config(&format!(
        "client_certificate = \"off\"\n\
         [gateways.closed]\nhost = \"127.0.0.1\"\nport = {closed}\n\
         [device_session]\ngateway = \"main\"\nlisten = \"127.0.0.1:0\"\n"
    ));

    let (_child, agent) = spawn_proxy(config, &[]).await;
    let mut stream = open_tunnel(agent, target).await;
    stream.write_all(b"gateway").await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(
        read_to_end_within(&mut stream, std::time::Duration::from_secs(5)).await,
        b"gateway"
    );
    assert_eq!(fixture.upstream.requests().len(), 1);
}

#[test]
fn proxy_refuses_several_gateways_without_a_device_session_gateway() {
    let dir = temp_dir();
    let config = write_config(
        &dir,
        "[gateways.a]\nhost = \"127.0.0.1\"\nport = 9\n[gateways.b]\nhost = \"127.0.0.1\"\nport = 9\n",
    );
    let output = gateinto(&["proxy"], &config);
    assert!(!output.status.success());
    let error = stderr(&output);
    assert!(
        error.contains(&format!(
            "config file {}: 2 gateways are configured (a, b)",
            config.display()
        )),
        "{error}"
    );
}

struct BrowserSession {
    _child: Child,
    agent: SocketAddr,
    realm: String,
    stdout: Vec<String>,
}

async fn spawn_browser_session(config: PathBuf, extra: &[&str]) -> BrowserSession {
    let extra = args(extra);
    tokio::task::spawn_blocking(move || {
        let mut child = Child(
            Command::new(env!("CARGO_BIN_EXE_gateinto"))
                .args(["session", "browser", "--config"])
                .arg(&config)
                .args(&extra)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let mut lines = std::io::BufReader::new(child.0.stdout.take().unwrap()).lines();
        let mut stdout = Vec::new();
        let (mut agent, mut realm) = (None, None);
        while agent.is_none() || realm.is_none() {
            let line = lines
                .next()
                .expect("session exited before printing its listener")
                .unwrap();
            if let Some(addr) = line.strip_prefix("listen: ") {
                agent = Some(addr.parse().unwrap());
            }
            if let Some(value) = line.strip_prefix("realm: ") {
                realm = Some(value.to_owned());
            }
            stdout.push(line);
        }
        std::thread::spawn(move || lines.for_each(drop));
        BrowserSession {
            _child: child,
            agent: agent.unwrap(),
            realm: realm.unwrap(),
            stdout,
        }
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn session_browser_requires_basic_tofu_on_an_ephemeral_loopback_port() {
    let fixture = Fixture::new().await;
    let target = echo_server().await.to_string();
    let closed = unused_port().await.port();
    let config = fixture.config(&format!(
        "client_certificate = \"off\"\n\
         [gateways.closed]\nhost = \"127.0.0.1\"\nport = {closed}\nclient_certificate = \"off\"\n\
         [device_session]\ngateway = \"closed\"\nlisten = \"127.0.0.1:18736\"\n"
    ));

    let first = spawn_browser_session(config.clone(), &["--gateway", "main"]).await;
    let second = spawn_browser_session(config, &["--gateway", "main"]).await;

    for session in [&first, &second] {
        assert!(session.agent.ip().is_loopback(), "{}", session.agent);
        assert_ne!(session.agent.port(), 18736);
        assert!(session.realm.starts_with("Gateinto "), "{}", session.realm);
        assert!(
            session.stdout.iter().any(|line| line == "gateway: main"),
            "{:?}",
            session.stdout
        );
    }
    assert_ne!(first.agent, second.agent);
    assert_ne!(first.realm, second.realm);

    let (_, challenge) = send(first.agent, &connect_with(&target, None)).await;
    assert_eq!(challenge.status, 407, "{}", challenge.head);
    assert!(
        challenge.head.contains(&format!(
            "Proxy-Authenticate: Basic realm=\"{}\"",
            first.realm
        )),
        "{}",
        challenge.head
    );
    let mine = basic("me", "browser secret");
    let (mut stream, response) = send(first.agent, &connect_with(&target, Some(&mine))).await;
    assert_eq!(response.status, 200, "{}", response.head);
    stream.write_all(b"browser").await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(
        read_to_end_within(&mut stream, std::time::Duration::from_secs(5)).await,
        b"browser"
    );
    let (_, other) = send(first.agent, &connect_with(&target, Some(&basic("me", "x")))).await;
    assert_eq!(other.status, 407);
    let (_, fresh) = send(
        second.agent,
        &connect_with(&target, Some(&basic("me", "x"))),
    )
    .await;
    assert_eq!(fresh.status, 200, "{}", fresh.head);
    for line in first.stdout.iter().chain(&second.stdout) {
        assert!(!line.contains("browser secret"), "{line}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_applies_the_device_session_auth() {
    let fixture = Fixture::new().await;
    let target = echo_server().await.to_string();
    let config = fixture.config(
        "client_certificate = \"off\"\n[device_session]\nlisten = \"127.0.0.1:0\"\nauth = \"basic_tofu\"\n",
    );

    let (_child, agent) = spawn_proxy(config, &[]).await;

    let (_, challenge) = send(agent, &connect_with(&target, None)).await;
    assert_eq!(challenge.status, 407, "{}", challenge.head);
    let (_, response) = send(agent, &connect_with(&target, Some(&basic("d", "pw")))).await;
    assert_eq!(response.status, 200, "{}", response.head);
}
