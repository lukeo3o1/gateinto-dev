#[allow(dead_code)]
mod fixture;
#[allow(dead_code)]
mod launch_support;

use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

use fixture::*;
use gateinto::browser::ProfileDir;
use gateinto::ipc::{SessionInfo, SessionKind, SessionRoute};
use launch_support::*;
use tokio::io::AsyncWriteExt;

const PORTAL: &str = "https://portal.example.test/welcome";
const CREDENTIALS_PROMPT: &str = "credentials-prompt.txt";

struct Output {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

impl Output {
    fn success(&self) -> &Self {
        assert!(
            self.status.success(),
            "{}\n{}\n{}",
            self.status,
            self.stdout,
            self.stderr
        );
        self
    }

    fn failure(&self) -> &Self {
        assert!(
            !self.status.success(),
            "{}\n{}\n{}",
            self.status,
            self.stdout,
            self.stderr
        );
        self
    }

    fn lines(&self) -> Vec<String> {
        self.stdout.lines().map(str::to_owned).collect()
    }
}

struct Launcher {
    dir: PathBuf,
    config: PathBuf,
    env: Vec<(&'static str, OsString)>,
    profiles_root: PathBuf,
    upstream_port: u16,
    _upstream: Option<UpstreamProxy>,
}

impl Launcher {
    async fn new(extra: &str) -> Self {
        let dir = temp_dir("launch");
        let ca = TestCa::new();
        let upstream = UpstreamProxy::start(ca.server_config(PROXY_NAME), Behavior::Tunnel).await;
        std::fs::write(dir.join("ca.pem"), ca.pem()).unwrap();
        let config = dir.join("gateinto.toml");
        std::fs::write(
            &config,
            format!(
                "[gateways.main]\nhost = \"127.0.0.1\"\nport = {}\nserver_name = \"{PROXY_NAME}\"\n\
                 ca_file = \"ca.pem\"\nclient_certificate = \"off\"\nportal_url = \"{PORTAL}\"\n\
                 [browser]\nexecutable = '{}'\n{extra}",
                upstream.addr.port(),
                fake_browser().display()
            ),
        )
        .unwrap();
        Self::instance(dir, config, Some(upstream))
    }

    async fn without_gateways() -> Self {
        let dir = temp_dir("linked");
        let ca = TestCa::new();
        let upstream = UpstreamProxy::start(ca.server_config("127.0.0.1"), Behavior::Tunnel).await;
        let ca_file = dir.join("linked-ca.pem");
        std::fs::write(&ca_file, ca.pem()).unwrap();
        let config = dir.join("gateinto.toml");
        std::fs::write(
            &config,
            format!("[browser]\nexecutable = '{}'\n", fake_browser().display()),
        )
        .unwrap();
        let mut launcher = Self::instance(dir, config, Some(upstream));
        launcher
            .env
            .push(("GATEINTO_TEST_LINKED_CA_FILE", ca_file.into()));
        launcher
    }

    fn linked_store(&self) -> PathBuf {
        let base = if cfg!(windows) {
            self.dir.join("roaming").join("Gateinto")
        } else {
            self.dir.join("config").join("gateinto")
        };
        base.join("gateways")
    }

    fn endpoint(&self) -> gateinto::ipc::Endpoint {
        let env = self.env.clone();
        let lookup = move |name: &str| {
            env.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.clone())
        };
        #[cfg(unix)]
        let user = String::new();
        #[cfg(windows)]
        let user = gateinto::ipc::user_sid().unwrap();
        gateinto::ipc::Endpoint::from_env_with(lookup, &user).unwrap()
    }

    fn instance(dir: PathBuf, config: PathBuf, upstream: Option<UpstreamProxy>) -> Self {
        static INSTANCE: AtomicU32 = AtomicU32::new(0);
        let instance = format!(
            "t{}-{}",
            std::process::id(),
            INSTANCE.fetch_add(1, Ordering::Relaxed)
        );
        let profiles_root = if cfg!(windows) {
            dir.join("local").join("Gateinto")
        } else {
            dir.join("state").join("gateinto")
        }
        .join(format!("profiles-{instance}"));
        let env = vec![
            ("GATEINTO_INSTANCE", OsString::from(instance)),
            ("XDG_RUNTIME_DIR", dir.join("run").into()),
            ("XDG_STATE_HOME", dir.join("state").into()),
            ("HOME", dir.join("home").into()),
            ("LOCALAPPDATA", dir.join("local").into()),
            ("XDG_CONFIG_HOME", dir.join("config").into()),
            ("APPDATA", dir.join("roaming").into()),
            ("RUST_LOG", OsString::from("info")),
            (
                "GATEINTO_TEST_CREDENTIALS_FILE",
                dir.join(CREDENTIALS_PROMPT).into(),
            ),
        ];
        Self {
            dir,
            config,
            env,
            profiles_root,
            upstream_port: upstream.as_ref().map_or(0, |upstream| upstream.addr.port()),
            _upstream: upstream,
        }
    }

    fn credentials_prompt(&self) -> PathBuf {
        self.dir.join(CREDENTIALS_PROMPT)
    }

    fn without_a_credentials_prompt(mut self) -> Self {
        self.env
            .retain(|(name, _)| *name != "GATEINTO_TEST_CREDENTIALS_FILE");
        #[cfg(windows)]
        self.env.push((
            "GATEINTO_TEST_CREDENTIALS_FILE",
            self.dir.join("no-desktop").join("prompt.txt").into(),
        ));
        self
    }

    fn sibling(&self) -> Self {
        Self::instance(self.dir.clone(), self.config.clone(), None)
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gateinto"));
        command.args(args).envs(self.env.iter().cloned());
        command
    }

    async fn run(&self, args: &[&str]) -> Output {
        static RUN: AtomicU32 = AtomicU32::new(0);
        let n = RUN.fetch_add(1, Ordering::Relaxed);
        let (out, err) = (
            self.dir.join(format!("{n}.out")),
            self.dir.join(format!("{n}.err")),
        );
        let mut command = self.command(args);
        command
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(&out).unwrap())
            .stderr(std::fs::File::create(&err).unwrap());
        let status = tokio::task::spawn_blocking(move || command.status().unwrap())
            .await
            .unwrap();
        Output {
            status,
            stdout: std::fs::read_to_string(out).unwrap(),
            stderr: std::fs::read_to_string(err).unwrap(),
        }
    }

    async fn open(&self, uri: &str) -> Output {
        let config = self.config.to_str().unwrap().to_owned();
        self.run(&["open", "--config", &config, "--", uri]).await
    }

    async fn opened(&self, profile: &str) -> (Vec<String>, FakeBrowser) {
        let output = self
            .open(&format!(
                "gateinto://connect?profile={profile}&auth=session_credentials"
            ))
            .await;
        assert_no_credentials(&output);
        let lines = output.success().lines();
        let listen: SocketAddr = field(&lines, "listen").parse().unwrap();
        let browser = wait_for_browser(&self.profiles_root, listen).await;
        (lines, browser)
    }

    async fn list(&self) -> Vec<SessionInfo> {
        let lines = self
            .run(&["session", "list", "--json"])
            .await
            .success()
            .lines();
        let sessions = SessionInfo::parse_list(&lines).unwrap();
        assert_eq!(sessions.len(), lines.len(), "{lines:?}");
        sessions
    }
}

impl Drop for Launcher {
    fn drop(&mut self) {
        let _ = self
            .command(&["stop"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

impl Launcher {
    async fn session_auth(&self, listen: SocketAddr) -> String {
        session_auth(&self.shown_credentials(listen).await)
    }

    async fn shown_credentials(&self, listen: SocketAddr) -> Vec<String> {
        use gateinto::ipc::{self, Request, Response};

        let endpoint = self.endpoint();
        let Response::Ok(list) = ipc::send(&endpoint, &Request::List).await.unwrap() else {
            panic!("listing the sessions failed");
        };
        let id = SessionInfo::parse_list(&list)
            .unwrap()
            .iter()
            .find(|session| session.listen == listen)
            .map(|session| session.id.to_string().parse().unwrap())
            .unwrap_or_else(|| panic!("no session listens on {listen}: {list:?}"));
        let Response::Ok(lines) = ipc::send(&endpoint, &Request::Credentials(id))
            .await
            .unwrap()
        else {
            panic!("the credentials of session {id} were not shown");
        };
        assert_eq!(field(&lines, "listen"), listen.to_string());
        lines
    }

    async fn tunnel_echoes(&self, proxy: SocketAddr) {
        let target = echo_server().await.to_string();
        let auth = self.session_auth(proxy).await;
        let (mut stream, response) = send(proxy, &connect_with(&target, Some(&auth))).await;
        assert_eq!(response.status, 200, "{}", response.head);
        stream.write_all(b"hello").await.unwrap();
        stream.shutdown().await.unwrap();
        assert_eq!(read_to_end_within(&mut stream, WAIT).await, b"hello");
    }
}

fn assert_no_credentials(output: &Output) {
    for text in [&output.stdout, &output.stderr] {
        for line in text.lines() {
            assert!(
                !line.starts_with("username:") && !line.starts_with("password:"),
                "{text}"
            );
        }
    }
}

fn listed_session<'a>(list: &'a [SessionInfo], lines: &[String]) -> Option<&'a SessionInfo> {
    list.iter().find(|session| {
        session.id.to_string() == field(lines, "session")
            && session.kind == SessionKind::Browser
            && session.gateway == "main"
            && session.listen.to_string() == field(lines, "listen")
    })
}

fn listed(list: &[SessionInfo], lines: &[String]) -> bool {
    listed_session(list, lines).is_some()
}

fn in_table(table: &[String], lines: &[String]) -> bool {
    let row = [
        field(lines, "session"),
        "browser",
        "main",
        field(lines, "listen"),
    ];
    table
        .iter()
        .any(|line| line.split_whitespace().take(4).eq(row))
}

#[tokio::test(flavor = "multi_thread")]
async fn gateway_only_open_reuses_configured_trust_and_can_start_blank_in_mixed_mode() {
    let launcher = Launcher::new("").await;
    let original = std::fs::read_to_string(&launcher.config)
        .unwrap()
        .replace(&format!("portal_url = \"{PORTAL}\"\n"), "");
    std::fs::write(&launcher.config, &original).unwrap();
    let gateway = format!("[::ffff:127.0.0.1]:{}", launcher.upstream_port);
    let request = gateinto::uri::LaunchRequest::from_fields(
        None,
        "session_credentials",
        None,
        Some(&gateway),
        None,
    )
    .unwrap()
    .with_route("mixed")
    .unwrap();
    let uri = request.to_string();
    assert!(!uri.contains("profile="));
    assert!(!uri.contains("portal="));
    let output = launcher.open(&uri).await;
    let lines = output.success().lines();
    assert_eq!(field(&lines, "gateway"), "main");
    assert_eq!(field(&lines, "route"), "mixed");
    let listen: SocketAddr = field(&lines, "listen").parse().unwrap();
    let browser = wait_for_browser(&launcher.profiles_root, listen).await;
    assert_eq!(browser.start_page(), "about:blank");
    launcher.tunnel_echoes(listen).await;
    assert_eq!(launcher._upstream.as_ref().unwrap().requests().len(), 1);
    assert_eq!(std::fs::read_to_string(&launcher.config).unwrap(), original);
    assert!(!launcher.linked_store().exists());
    browser.exit();
}

#[tokio::test(flavor = "multi_thread")]
async fn gateway_only_open_refuses_ambiguous_configured_profiles() {
    let launcher = Launcher::new("").await;
    let mut text = std::fs::read_to_string(&launcher.config).unwrap();
    text.push_str(&format!(
        "\n[gateways.alternate]\nhost = \"127.0.0.1\"\nport = {}\ntls_mode = \"hybrid_required\"\n",
        launcher.upstream_port
    ));
    std::fs::write(&launcher.config, &text).unwrap();
    let gateway = format!("127.0.0.1:{}", launcher.upstream_port);
    let request = gateinto::uri::LaunchRequest::from_fields(
        None,
        "session_credentials",
        None,
        Some(&gateway),
        None,
    )
    .unwrap();
    let output = launcher.open(&request.to_string()).await;
    assert!(
        output
            .failure()
            .stderr
            .contains("matches several configured profiles"),
        "{}",
        output.stderr
    );
    assert!(browsers(&launcher.profiles_root).is_empty());
    let explicit = gateinto::uri::LaunchRequest::from_fields(
        Some("main"),
        "session_credentials",
        None,
        Some(&gateway),
        None,
    )
    .unwrap();
    let output = launcher.open(&explicit.to_string()).await;
    let listen: SocketAddr = field(&output.success().lines(), "listen").parse().unwrap();
    let browser = wait_for_browser(&launcher.profiles_root, listen).await;
    assert_eq!(browser.start_page(), PORTAL);
    launcher.tunnel_echoes(listen).await;
    browser.exit();
}

#[cfg(feature = "test-hooks")]
#[tokio::test(flavor = "multi_thread")]
async fn an_address_only_gateway_is_confirmed_stored_without_portal_and_reloaded_by_open() {
    use gateinto::ipc::{self, Request, Response};
    let launcher = Launcher::without_gateways().await;
    let config = launcher.config.to_str().unwrap().to_owned();
    launcher
        .run(&["agent", "--detach", "--config", &config])
        .await
        .success();
    let endpoint = launcher.endpoint();
    let gateway = format!("127.0.0.1:{}", launcher.upstream_port);
    let request = gateinto::uri::LaunchRequest::from_fields(
        None,
        "session_credentials",
        None,
        Some(&gateway),
        None,
    )
    .unwrap()
    .with_route("mixed")
    .unwrap();
    let generated = request.proposed_profile().unwrap();
    let Response::Ok(lines) = ipc::send(&endpoint, &Request::Launch(request.clone()))
        .await
        .unwrap()
    else {
        panic!("not confirmation")
    };
    assert_eq!(field(&lines, "gateway"), generated.as_str());
    assert_eq!(field(&lines, "portal"), "none");
    assert_eq!(field(&lines, "route"), "mixed");
    let token = ipc::confirm_token(&lines).unwrap();
    let Response::Ok(lines) = ipc::send(&endpoint, &Request::Approve(token))
        .await
        .unwrap()
    else {
        panic!("approval failed")
    };
    assert_eq!(field(&lines, "route"), "mixed");
    let listen: SocketAddr = field(&lines, "listen").parse().unwrap();
    let browser = wait_for_browser(&launcher.profiles_root, listen).await;
    assert_eq!(browser.start_page(), "about:blank");
    launcher.tunnel_echoes(listen).await;
    let file = launcher
        .linked_store()
        .join(format!("127.0.0.1_{}.toml", launcher.upstream_port));
    let stored = std::fs::read_to_string(&file).unwrap();
    assert!(!stored.contains("portal_url"));
    assert!(stored.contains(generated.as_str()));
    launcher.run(&["stop"]).await.success();
    let request = request.with_route("gateway").unwrap();
    let output = launcher.open(&request.to_string()).await;
    let lines = output.success().lines();
    assert_eq!(field(&lines, "gateway"), generated.as_str());
    assert!(!lines.iter().any(|line| line.starts_with("route:")));
    let listen: SocketAddr = field(&lines, "listen").parse().unwrap();
    let browser = wait_for_browser(&launcher.profiles_root, listen).await;
    assert_eq!(browser.start_page(), "about:blank");
    launcher.tunnel_echoes(listen).await;
    assert_eq!(std::fs::read_to_string(&file).unwrap(), stored);
    let invalid = request
        .with_link(Some("https://127.0.0.1/"), Some(&gateway), None)
        .unwrap();
    assert!(
        launcher
            .open(&invalid.to_string())
            .await
            .failure()
            .stderr
            .contains("has no portal_url")
    );
    browser.exit();
}

#[cfg(not(windows))]
#[tokio::test(flavor = "multi_thread")]
async fn address_only_open_verifies_the_portalless_confirmation_before_refusing_without_a_terminal()
{
    let launcher = Launcher::without_gateways().await;
    let gateway = format!("127.0.0.1:{}", launcher.upstream_port);
    let uri = gateinto::uri::LaunchRequest::from_fields(
        None,
        "session_credentials",
        None,
        Some(&gateway),
        None,
    )
    .unwrap()
    .to_string();
    let output = launcher.open(&uri).await;
    assert!(
        output.failure().stderr.contains("no desktop or terminal"),
        "{}",
        output.stderr
    );
    assert!(!launcher.linked_store().exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn uri_route_mode_reaches_the_agent_and_is_isolated_to_each_browser_session() {
    let launcher = Launcher::new("").await;
    let target = echo_server_on(std::net::Ipv4Addr::new(127, 0, 0, 2)).await;
    let output = launcher
        .open("gateinto://connect?profile=main&route=mixed")
        .await;
    let mixed = output.success().lines();
    assert_eq!(field(&mixed, "route"), "mixed");
    let listen: SocketAddr = field(&mixed, "listen").parse().unwrap();
    let mixed_browser = wait_for_browser(&launcher.profiles_root, listen).await;
    let (gateway, gateway_browser) = launcher.opened("main").await;
    for browser in [&mixed_browser, &gateway_browser] {
        let auth = launcher.session_auth(browser.proxy()).await;
        let (mut stream, response) = send(
            browser.proxy(),
            &connect_with(&target.to_string(), Some(&auth)),
        )
        .await;
        assert_eq!(response.status, 200);
        stream.write_all(b"isolated").await.unwrap();
        stream.shutdown().await.unwrap();
        assert_eq!(read_to_end_within(&mut stream, WAIT).await, b"isolated");
    }
    assert_eq!(launcher._upstream.as_ref().unwrap().requests().len(), 1);
    let list = launcher.list().await;
    let route = |lines: &[String]| listed_session(&list, lines).map(|session| session.route);
    assert_eq!(route(&mixed), Some(SessionRoute::Mixed), "{list:?}");
    assert_eq!(route(&gateway), Some(SessionRoute::All), "{list:?}");
    mixed_browser.exit();
    gateway_browser.exit();
}

#[tokio::test(flavor = "multi_thread")]
async fn open_starts_the_agent_which_opens_the_configured_portal_in_a_browser_session() {
    let launcher = Launcher::new("").await;

    let (lines, browser) = launcher.opened("main").await;

    assert_eq!(browser.start_page(), PORTAL);
    assert_eq!(
        browser.profile().parent(),
        Some(launcher.profiles_root.as_path())
    );
    assert!(listed(&launcher.list().await, &lines));
    launcher.tunnel_echoes(browser.proxy()).await;

    browser.exit();

    wait_until("the profile is removed", || !browser.profile().exists()).await;
    assert!(!listed(&launcher.list().await, &lines));
}

#[tokio::test(flavor = "multi_thread")]
async fn repeated_launches_reach_the_running_agent_and_open_separate_sessions() {
    let launcher = Launcher::new("").await;

    let (first, first_browser) = launcher.opened("main").await;
    let (second, second_browser) = launcher.opened("main").await;

    assert_ne!(field(&first, "session"), field(&second, "session"));
    assert_ne!(first_browser.profile(), second_browser.profile());
    let list = launcher.list().await;
    assert!(listed(&list, &first) && listed(&list, &second), "{list:?}");
    let config = launcher.config.to_str().unwrap().to_owned();
    let output = launcher.run(&["agent", "--config", &config]).await;
    assert!(
        output.failure().stderr.contains("already running"),
        "{}",
        output.stderr
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn open_without_config_uses_the_default_config_file_like_the_installed_handler() {
    let launcher = Launcher::new("").await;
    let default = if cfg!(windows) {
        launcher.dir.join("roaming").join("Gateinto")
    } else {
        launcher.dir.join("config").join("gateinto")
    };
    std::fs::create_dir_all(&default).unwrap();
    std::fs::copy(&launcher.config, default.join("gateinto.toml")).unwrap();
    std::fs::copy(launcher.dir.join("ca.pem"), default.join("ca.pem")).unwrap();

    let output = launcher
        .run(&[
            "open",
            "--",
            "gateinto://connect?profile=main&auth=session_credentials",
        ])
        .await;

    let lines = output.success().lines();
    let listen: SocketAddr = field(&lines, "listen").parse().unwrap();
    let browser = wait_for_browser(&launcher.profiles_root, listen).await;
    assert_eq!(browser.start_page(), PORTAL);
    launcher.tunnel_echoes(browser.proxy()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_uris_are_rejected_before_any_agent_is_contacted() {
    let launcher = Launcher::new("").await;

    for uri in [
        "gateinto://connect?profile=main&url=https://evil.example",
        "gateinto://connect?profile=main&profile=other",
        "gateinto://connect?profile=main%22%20--config%20evil",
        "gateinto://connect?profile=main#x",
        "https://connect?profile=main",
        "--config=evil",
    ] {
        let output = launcher.open(uri).await;
        assert!(
            output.failure().stderr.contains("invalid launch URI"),
            "{uri}: {}",
            output.stderr
        );
    }
    let config = launcher.config.to_str().unwrap().to_owned();
    let output = launcher
        .run(&[
            "open",
            "--config",
            &config,
            "--",
            "gateinto://connect?profile=main",
            "extra",
        ])
        .await;
    output.failure();
    let output = launcher.run(&["session", "list"]).await;
    assert!(
        output.failure().stderr.contains("no agent is running"),
        "{}",
        output.stderr
    );
    assert!(browsers(&launcher.profiles_root).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_agent_rejects_a_profile_missing_from_its_configuration() {
    let launcher = Launcher::new("").await;

    let output = launcher.open("gateinto://connect?profile=nope").await;

    assert!(
        output.failure().stderr.contains("unknown gateway \"nope\""),
        "{}",
        output.stderr
    );
    assert!(browsers(&launcher.profiles_root).is_empty());
    assert!(launcher.list().await.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn session_close_revokes_the_credentials_and_ends_the_tunnels() {
    use gateinto::ipc::{self, Request, Response};
    use tokio::io::AsyncReadExt;

    let launcher = Launcher::new("").await;
    let (lines, _browser) = launcher.opened("main").await;
    let id = field(&lines, "session");
    let listen: SocketAddr = field(&lines, "listen").parse().unwrap();
    let shown = launcher.shown_credentials(listen).await;
    let cached = ipc::issued_credentials(&shown).unwrap();
    let target = echo_server().await.to_string();
    let (mut tunnel, response) =
        send(listen, &connect_with(&target, Some(&session_auth(&shown)))).await;
    assert_eq!(response.status, 200, "{}", response.head);
    tunnel.write_all(b"open").await.unwrap();
    let mut echoed = [0; 4];
    tokio::time::timeout(WAIT, tunnel.read_exact(&mut echoed))
        .await
        .unwrap()
        .unwrap();

    launcher.run(&["session", "close", id]).await.success();

    let mut rest = [0; 16];
    match tokio::time::timeout(WAIT, tunnel.read(&mut rest)).await {
        Ok(Ok(0) | Err(_)) => {}
        Ok(Ok(n)) => panic!("the closed session's tunnel delivered {:?}", &rest[..n]),
        Err(_) => panic!("the closed session's tunnel stayed open"),
    }
    let error = tokio::net::TcpStream::connect(listen).await.unwrap_err();
    assert_eq!(
        error.kind(),
        std::io::ErrorKind::ConnectionRefused,
        "{error}"
    );
    let request = Request::Credentials(id.parse().unwrap());
    let answer = ipc::send(&launcher.endpoint(), &request).await.unwrap();
    let Response::Error(message) = answer else {
        panic!("a closed session still answered with credentials: {answer:?}");
    };
    assert!(message.contains(&format!("no session {id}")), "{message}");
    assert!(!message.contains(cached.password()), "{message}");
}

#[tokio::test(flavor = "multi_thread")]
async fn sessions_can_be_closed_explicitly_and_stop_closes_the_rest() {
    let launcher = Launcher::new("").await;
    let (first, first_browser) = launcher.opened("main").await;
    let (_, second_browser) = launcher.opened("main").await;

    launcher
        .run(&["session", "close", field(&first, "session")])
        .await
        .success();

    assert!(!first_browser.profile().exists());
    assert!(!listed(&launcher.list().await, &first));
    assert!(second_browser.profile().exists());
    let output = launcher.run(&["session", "close", "999"]).await;
    assert!(
        output.failure().stderr.contains("no session 999"),
        "{}",
        output.stderr
    );

    launcher.run(&["stop"]).await.success();

    assert!(!second_browser.profile().exists());
    let output = launcher.run(&["session", "list"]).await;
    assert!(output.failure().stderr.contains("no agent is running"));
}

async fn status(launcher: &Launcher) -> Vec<String> {
    let config = launcher.config.to_str().unwrap().to_owned();
    launcher
        .run(&["status", "--config", &config])
        .await
        .success()
        .lines()
}

#[tokio::test(flavor = "multi_thread")]
async fn status_reports_gateways_and_agent_sessions_without_secrets_or_changes() {
    let launcher = Launcher::new("").await;
    let before = status(&launcher).await;
    assert!(
        before.contains(&"agent: not running".to_owned()),
        "{before:?}"
    );
    let (lines, browser) = launcher.opened("main").await;

    let after = status(&launcher).await;

    assert!(
        after.contains(&format!("config: {}", launcher.config.display())),
        "{after:?}"
    );
    assert!(
        after
            .iter()
            .any(|line| line.starts_with("gateway: main: 127.0.0.1:")),
        "{after:?}"
    );
    assert!(
        after.contains(&"device-session: none".to_owned()),
        "{after:?}"
    );
    assert!(after.contains(&"agent: running".to_owned()), "{after:?}");
    assert!(in_table(&after, &lines), "{after:?}");
    let text = after.join("\n");
    let shown = launcher.shown_credentials(browser.proxy()).await;
    for secret in [
        PORTAL,
        "ca.pem",
        field(&lines, "realm"),
        field(&shown, "password"),
    ] {
        assert!(!text.contains(secret), "{secret}: {text}");
    }
    assert!(browser.profile().exists());
    assert_eq!(launcher.list().await.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn session_list_prints_an_aligned_table_or_json_objects_without_secrets() {
    let launcher = Launcher::new("").await;
    let (lines, browser) = launcher.opened("main").await;

    let table = launcher.run(&["session", "list"]).await.success().lines();
    let json = launcher
        .run(&["session", "list", "--json"])
        .await
        .success()
        .lines();

    assert_eq!(table.len(), 2, "{table:?}");
    assert_eq!(
        table[0].split_whitespace().collect::<Vec<_>>(),
        [
            "ID", "KIND", "GATEWAY", "LISTEN", "ROUTE", "AUTH", "TUNNELS", "UPTIME", "BROWSER"
        ]
    );
    assert!(in_table(&table, &lines), "{table:?}");
    assert_eq!(
        table[0].find("LISTEN"),
        table[1].find(field(&lines, "listen")),
        "{table:?}"
    );
    assert_eq!(json.len(), 1, "{json:?}");
    assert!(listed(&SessionInfo::parse_list(&json).unwrap(), &lines));
    let text = [table, json].concat().join("\n");
    let shown = launcher.shown_credentials(browser.proxy()).await;
    for secret in [field(&lines, "realm"), field(&shown, "password")] {
        assert!(!text.contains(secret), "{secret}: {text}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_detach_starts_a_background_agent_once_and_returns() {
    let launcher = Launcher::new("").await;
    let config = launcher.config.to_str().unwrap().to_owned();

    let output = launcher
        .run(&["agent", "--detach", "--config", &config])
        .await;

    assert_eq!(
        output.success().lines(),
        vec!["started the agent".to_owned()]
    );
    assert!(
        status(&launcher)
            .await
            .contains(&"agent: running".to_owned())
    );
    let output = launcher
        .run(&["agent", "--detach", "--config", &config])
        .await;
    assert_eq!(
        output.success().lines(),
        vec!["an agent is already running".to_owned()]
    );
    let (_, browser) = launcher.opened("main").await;
    assert_eq!(browser.start_page(), PORTAL);
    launcher.run(&["stop"]).await.success();
}

fn stopped_pid(lines: &[String]) -> u32 {
    lines
        .iter()
        .find_map(|line| {
            line.strip_prefix("stopped the agent (process ")?
                .strip_suffix(')')?
                .parse()
                .ok()
        })
        .unwrap_or_else(|| panic!("no stopped agent line in {lines:?}"))
}

#[tokio::test(flavor = "multi_thread")]
async fn stop_returns_only_after_the_agent_process_exited() {
    let launcher = Launcher::new("").await;
    let (_, browser) = launcher.opened("main").await;

    let output = launcher.run(&["stop"]).await;

    let pid = stopped_pid(&output.success().lines());
    assert!(gateinto::process::wait_for_exit(pid, std::time::Duration::ZERO).unwrap());
    assert!(!browser.profile().exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn stop_for_the_uninstaller_closes_sessions_and_removes_stale_profiles() {
    let launcher = Launcher::new("").await;
    let (_, browser) = launcher.opened("main").await;

    let output = launcher.run(&["stop", "--remove-stale-profiles"]).await;

    let lines = output.success().lines();
    let pid = stopped_pid(&lines);
    assert!(gateinto::process::wait_for_exit(pid, std::time::Duration::ZERO).unwrap());
    assert_eq!(lines.last().unwrap(), "removed 0 stale browser profiles");
    assert!(!browser.profile().exists());
    assert!(
        status(&launcher)
            .await
            .contains(&"agent: not running".to_owned())
    );
    let stale = ProfileDir::create(&launcher.profiles_root, "5".parse().unwrap()).unwrap();
    let unmarked = launcher.profiles_root.join("not-a-profile");
    std::fs::create_dir_all(&unmarked).unwrap();

    let output = launcher.run(&["stop", "--remove-stale-profiles"]).await;

    assert_eq!(
        output.success().lines(),
        vec![
            "no agent is running".to_owned(),
            "removed 1 stale browser profiles".to_owned()
        ]
    );
    assert!(!stale.path().exists());
    assert!(unmarked.exists());
    let output = launcher.run(&["stop"]).await;
    assert!(
        output.failure().stderr.contains("no agent is running"),
        "{}",
        output.stderr
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn profiles_left_behind_are_removed_when_the_agent_starts() {
    let launcher = Launcher::new("").await;
    let stale = ProfileDir::create(&launcher.profiles_root, "5".parse().unwrap()).unwrap();
    std::fs::write(stale.path().join("Cookies"), b"x").unwrap();
    let foreign = launcher.profiles_root.join("Default");
    std::fs::create_dir(&foreign).unwrap();

    launcher.opened("main").await;

    assert!(!stale.path().exists());
    assert!(foreign.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_agent_of_another_instance_leaves_running_profiles_alone() {
    let first = Launcher::new("").await;
    let (lines, browser) = first.opened("main").await;
    let second = first.sibling();

    second.opened("main").await;

    assert!(browser.profile().exists());
    assert!(listed(&first.list().await, &lines));
    first.tunnel_echoes(browser.proxy()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_opens_without_an_agent_start_exactly_one() {
    let launcher = Launcher::new("").await;
    let uri = "gateinto://connect?profile=main";

    let (first, second) = tokio::join!(launcher.open(uri), launcher.open(uri));

    let (first, second) = (first.success().lines(), second.success().lines());
    let list = launcher.list().await;
    assert!(listed(&list, &first) && listed(&list, &second), "{list:?}");
    assert_eq!(
        list.iter()
            .filter(|session| session.kind == SessionKind::Browser)
            .count(),
        2,
        "{list:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_agent_runs_the_configured_device_session_with_session_credentials() {
    let launcher =
        Launcher::new("[device_session]\ngateway = \"main\"\nlisten = \"127.0.0.1:0\"\n").await;

    let (lines, _) = launcher.opened("main").await;

    let device = device_session_listen(&launcher).await;
    let target = echo_server().await.to_string();
    let (_, challenge) = send(device, &connect_with(&target, None)).await;
    assert_eq!(challenge.status, 407, "{}", challenge.head);
    launcher.tunnel_echoes(device).await;
    assert_ne!(field(&lines, "session"), "1");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_agent_logs_how_to_show_the_device_session_credentials_but_not_them() {
    let launcher =
        Launcher::new("[device_session]\ngateway = \"main\"\nlisten = \"127.0.0.1:0\"\n").await;
    let config = launcher.config.to_str().unwrap().to_owned();
    let log = launcher.dir.join("agent.err");
    let mut agent = launcher
        .command(&["agent", "--config", &config])
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log).unwrap())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + WAIT;
    while !launcher.run(&["session", "list"]).await.status.success() {
        assert!(agent.try_wait().unwrap().is_none(), "agent exited");
        assert!(std::time::Instant::now() < deadline, "no agent");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let device = device_session_listen(&launcher).await;
    let credentials = launcher.shown_credentials(device).await;

    assert!(launcher.run(&["stop"]).await.status.success());
    tokio::task::block_in_place(|| agent.wait().unwrap());

    let text = std::fs::read_to_string(&log).unwrap();
    let line = text
        .lines()
        .find(|line| line.contains("device session 1 accepts session_credentials"))
        .unwrap_or_else(|| panic!("{text}"));
    assert!(line.contains(" INFO "), "{line}");
    assert!(
        line.contains("run `gateinto session credentials 1`"),
        "{line}"
    );
    let password = field(&credentials, "password");
    assert!(!password.is_empty());
    assert!(!text.contains(password), "{text}");
    assert!(!text.contains(&format!("gateinto:{password}")), "{text}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_agent_device_session_with_auth_none_accepts_any_local_client() {
    let launcher = Launcher::new(
        "[device_session]\ngateway = \"main\"\nlisten = \"127.0.0.1:0\"\nauth = \"none\"\n",
    )
    .await;

    launcher.opened("main").await;

    let device = device_session_listen(&launcher).await;
    let mut stream = open_tunnel(device, echo_server().await).await;
    stream.write_all(b"device").await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(read_to_end_within(&mut stream, WAIT).await, b"device");
}

async fn device_session_listen(launcher: &Launcher) -> SocketAddr {
    let list = launcher.list().await;
    list.iter()
        .find(|session| {
            session.id == 1 && session.kind == SessionKind::Device && session.gateway == "main"
        })
        .unwrap_or_else(|| panic!("{list:?}"))
        .listen
}

#[cfg(unix)]
mod interrupt {
    use super::*;

    async fn interrupt(child: &mut std::process::Child) -> ExitStatus {
        signal(child, "-INT").await
    }

    async fn signal(child: &mut std::process::Child, signal: &str) -> ExitStatus {
        let status = Command::new("kill")
            .args([signal, &child.id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
        let deadline = std::time::Instant::now() + WAIT;
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            assert!(std::time::Instant::now() < deadline, "did not exit");
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sigint_and_sigterm_stop_the_agent_after_closing_its_sessions() {
        for name in ["-INT", "-TERM"] {
            let launcher = Launcher::new("").await;
            let config = launcher.config.to_str().unwrap().to_owned();
            let mut agent = launcher
                .command(&["agent", "--config", &config])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + WAIT;
            while !launcher.run(&["session", "list"]).await.status.success() {
                assert!(agent.try_wait().unwrap().is_none(), "{name}: agent exited");
                assert!(std::time::Instant::now() < deadline, "{name}: no agent");
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            let (_, browser) = launcher.opened("main").await;

            let status = signal(&mut agent, name).await;

            assert!(status.success(), "{name}: {status}");
            assert!(!browser.profile().exists(), "{name}");
            let output = launcher.run(&["session", "list"]).await;
            assert!(output.failure().stderr.contains("no agent is running"));
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ctrl_c_stops_proxy_and_session_browser_cleanly() {
        let launcher = Launcher::new(
            "[device_session]\ngateway = \"main\"\nlisten = \"127.0.0.1:0\"\nauth = \"none\"\n",
        )
        .await;
        let config = launcher.config.to_str().unwrap().to_owned();
        #[allow(unused_mut)]
        let mut commands = vec![vec!["proxy", "--config", &config]];
        #[cfg(feature = "test-hooks")]
        commands.push(vec!["session", "browser", "--config", &config]);
        for args in commands {
            let mut child = launcher
                .command(&args)
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let stderr = std::io::BufReader::new(child.stderr.take().unwrap());
            tokio::task::block_in_place(|| {
                let mut lines = std::io::BufRead::lines(stderr);
                let listening = lines
                    .by_ref()
                    .map_while(Result::ok)
                    .any(|line| line.contains("local_addr="));
                assert!(listening, "{args:?} exited before listening");
                std::thread::spawn(move || lines.for_each(drop));
            });

            let status = interrupt(&mut child).await;

            assert!(status.success(), "{args:?}: {status}");
        }
    }
}

#[cfg(not(windows))]
#[tokio::test(flavor = "multi_thread")]
async fn uri_registration_is_windows_only() {
    let launcher = Launcher::new("").await;
    for args in [&["uri", "register"][..], &["uri", "unregister"]] {
        let output = launcher.run(args).await;
        assert!(
            output
                .failure()
                .stderr
                .contains("only supported on Windows"),
            "{}",
            output.stderr
        );
    }
}

fn link_uri(
    profile: &str,
    url: Option<&str>,
    gateway: Option<&str>,
    portal: Option<&str>,
) -> String {
    gateinto::uri::LaunchRequest::new(profile, "session_credentials")
        .unwrap()
        .with_link(url, gateway, portal)
        .unwrap()
        .to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_link_opens_a_start_page_on_the_configured_portal_origin_only() {
    let launcher = Launcher::new("").await;
    let start = "https://portal.example.test/deep/link?x=1";

    let output = launcher
        .open(&link_uri("main", Some(start), None, None))
        .await;
    let listen: SocketAddr = field(&output.success().lines(), "listen").parse().unwrap();
    let browser = wait_for_browser(&launcher.profiles_root, listen).await;
    assert_eq!(browser.start_page(), start);

    for (uri, error) in [
        (
            link_uri("main", Some("https://evil.example/"), None, None),
            "not on the origin",
        ),
        (
            link_uri("main", None, Some("evil.example"), Some(PORTAL)),
            "differs from the gateway \"main\"",
        ),
        (
            link_uri("nope", None, None, None),
            "unknown gateway \"nope\"",
        ),
    ] {
        let output = launcher.open(&uri).await;
        assert!(
            output.failure().stderr.contains(error),
            "{uri}: {}",
            output.stderr
        );
    }
    assert_eq!(browsers(&launcher.profiles_root).len(), 1);
    assert!(!launcher.linked_store().exists());
}

#[cfg(not(windows))]
#[tokio::test(flavor = "multi_thread")]
async fn without_a_terminal_open_refuses_a_new_gateway_and_stores_nothing() {
    let launcher = Launcher::without_gateways().await;
    let uri = link_uri(
        "newco",
        None,
        Some(&format!("127.0.0.1:{}", launcher.upstream_port)),
        Some("https://portal.newco.example/"),
    );
    for _ in 0..2 {
        let output = launcher.open(&uri).await;
        assert!(
            output.failure().stderr.contains("no desktop or terminal"),
            "{}",
            output.stderr
        );
    }
    assert!(!launcher.linked_store().exists());
    assert!(browsers(&launcher.profiles_root).is_empty());
}

#[cfg(feature = "test-hooks")]
#[tokio::test(flavor = "multi_thread")]
async fn an_approved_gateway_from_a_link_is_stored_and_relays_through_its_upstream() {
    use gateinto::ipc::{self, Request, Response};

    let launcher = Launcher::without_gateways().await;
    let config = launcher.config.to_str().unwrap().to_owned();
    launcher
        .run(&["agent", "--detach", "--config", &config])
        .await
        .success();
    let endpoint = launcher.endpoint();
    let gateway = format!("127.0.0.1:{}", launcher.upstream_port);
    let portal = "https://portal.newco.example/home";
    let start = "https://portal.newco.example/app";
    let uri = link_uri("newco", Some(start), Some(&gateway), Some(portal));

    let request = Request::Launch(uri.parse().unwrap());
    let Response::Ok(lines) = ipc::send(&endpoint, &request).await.unwrap() else {
        panic!("the agent refused the link");
    };
    let token = ipc::confirm_token(&lines).unwrap();
    assert!(!launcher.linked_store().exists());
    let lines = match ipc::send(&endpoint, &Request::Approve(token))
        .await
        .unwrap()
    {
        Response::Ok(lines) => lines,
        Response::Error(error) => panic!("approving failed: {error}"),
    };
    let listen: SocketAddr = field(&lines, "listen").parse().unwrap();
    let browser = wait_for_browser(&launcher.profiles_root, listen).await;
    assert_eq!(browser.start_page(), start);
    launcher.tunnel_echoes(listen).await;

    let file = launcher
        .linked_store()
        .join(format!("127.0.0.1_{}.toml", launcher.upstream_port));
    let stored = std::fs::read_to_string(&file).unwrap();
    assert!(
        stored.contains(&format!(
            "name = \"newco\"\nhost = \"127.0.0.1\"\nport = {}\nportal_url = \"{portal}\"\n",
            launcher.upstream_port
        )),
        "{stored}"
    );
    assert_eq!(
        std::fs::read_dir(launcher.linked_store()).unwrap().count(),
        1
    );
    let output = launcher.open(&uri).await;
    let listen: SocketAddr = field(&output.success().lines(), "listen").parse().unwrap();
    wait_for_browser(&launcher.profiles_root, listen).await;
    launcher.tunnel_echoes(listen).await;
    let output = launcher
        .run(&["gateway", "list", "--config", &config])
        .await;
    assert_eq!(
        output.success().stdout,
        format!("newco: {gateway}, portal https://portal.newco.example (linked)\n")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_linked_gateway_trusts_only_the_public_roots() {
    use gateinto::ipc::{self, Request, Response};

    let mut launcher = Launcher::without_gateways().await;
    launcher
        .env
        .retain(|(name, _)| *name != "GATEINTO_TEST_LINKED_CA_FILE");
    let config = launcher.config.to_str().unwrap().to_owned();
    let log = launcher.dir.join("agent.log");
    let mut agent = launcher
        .command(&["agent", "--config", &config])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log).unwrap())
        .spawn()
        .unwrap();
    let endpoint = launcher.endpoint();
    let deadline = std::time::Instant::now() + WAIT;
    while ipc::send(&endpoint, &Request::List).await.is_err() {
        assert!(
            std::time::Instant::now() < deadline,
            "the agent did not start"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let uri = link_uri(
        "newco",
        None,
        Some(&format!("127.0.0.1:{}", launcher.upstream_port)),
        Some("https://portal.newco.example/"),
    );
    let Response::Ok(lines) = ipc::send(&endpoint, &Request::Launch(uri.parse().unwrap()))
        .await
        .unwrap()
    else {
        panic!("the agent refused the link");
    };
    let token = ipc::confirm_token(&lines).unwrap();
    let Response::Ok(lines) = ipc::send(&endpoint, &Request::Approve(token))
        .await
        .unwrap()
    else {
        panic!("approving failed");
    };
    let listen: SocketAddr = field(&lines, "listen").parse().unwrap();
    let target = echo_server().await.to_string();
    let (_, response) = send(
        listen,
        &connect_with(&target, Some(&launcher.session_auth(listen).await)),
    )
    .await;
    assert_eq!(response.status, 502, "{}", response.head);

    launcher.run(&["stop"]).await.success();
    tokio::task::spawn_blocking(move || agent.wait().unwrap())
        .await
        .unwrap();
    let log = std::fs::read_to_string(&log).unwrap();
    assert!(
        log.lines()
            .any(|line| line.contains("upstream refused tunnel")
                && line.contains("invalid peer certificate: UnknownIssuer")),
        "{log}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_damaged_gateway_file_blocks_only_its_own_gateway() {
    let launcher = Launcher::new("").await;
    let dir = launcher.linked_store();
    std::fs::create_dir_all(&dir).unwrap();
    let broken = dir.join("held.example.toml");
    let damaged = "name = \"held\"\nhost = \"held.example\"\nport = 443\nca_file = \"x\"\n";
    std::fs::write(&broken, damaged).unwrap();

    let output = launcher.open(&link_uri("main", None, None, None)).await;
    let lines = output.success().lines();
    let listen: SocketAddr = field(&lines, "listen").parse().unwrap();
    wait_for_browser(&launcher.profiles_root, listen).await;
    let error = format!("linked-gateway: error: {}: ", broken.display());
    assert!(
        lines.iter().any(|line| line.starts_with(&error)),
        "{lines:?}"
    );

    for uri in [
        link_uri("held", None, None, None),
        link_uri(
            "held",
            None,
            Some("new.example"),
            Some("https://new.example/"),
        ),
        link_uri(
            "other",
            None,
            Some("held.example"),
            Some("https://new.example/"),
        ),
    ] {
        let output = launcher.open(&uri).await;
        assert!(
            output.failure().stderr.contains("damaged file"),
            "{uri}: {}",
            output.stderr
        );
    }
    assert_eq!(std::fs::read_to_string(&broken).unwrap(), damaged);
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
    assert_eq!(browsers(&launcher.profiles_root).len(), 1);
}

#[cfg(feature = "test-hooks")]
#[tokio::test(flavor = "multi_thread")]
async fn every_launcher_routes_the_credentials_prompt_to_the_test_hook() {
    let launcher = Launcher::new("").await;
    let (lines, browser) = launcher.opened("main").await;
    if cfg!(windows) {
        let id = field(&lines, "session");
        launcher
            .run(&["session", "credentials", id])
            .await
            .success();
    }
    let shown = std::fs::read_to_string(launcher.credentials_prompt()).unwrap();
    assert!(
        shown.contains(&format!("Gateinto session {}", field(&lines, "session"))),
        "{shown}"
    );
    browser.exit();
}

#[cfg(feature = "test-hooks")]
#[tokio::test(flavor = "multi_thread")]
async fn launch_errors_notify_once_but_a_successful_launch_does_not() {
    let mut launcher = Launcher::new("").await;
    let notification = launcher.dir.join("launch-notification.txt");
    launcher
        .env
        .push(("GATEINTO_TEST_OPEN_ERROR_FILE", notification.clone().into()));
    let (_, browser) = launcher.opened("main").await;
    assert!(!notification.exists());
    let output = launcher
        .open("gateinto://connect?profile=missing&auth=session_credentials")
        .await;
    output.failure();
    let text = std::fs::read_to_string(notification).unwrap();
    assert!(text.contains(output.stderr.trim()), "{text}");
    assert_eq!(text.matches("Gateinto could not open the link.").count(), 1);
    browser.exit();
}

#[cfg(feature = "test-hooks")]
#[tokio::test(flavor = "multi_thread")]
async fn open_prompts_for_credentials_unless_os_user_is_offered_and_session_credentials_shows_them()
{
    let launcher = Launcher::new("").await;
    let prompt = launcher.credentials_prompt();
    let (lines, browser) = launcher.opened("main").await;
    let id = field(&lines, "session");
    let listen = browser.proxy();
    if cfg!(windows) {
        assert!(
            !prompt.exists(),
            "os_user browser sessions open without a prompt"
        );
        launcher
            .run(&["session", "credentials", id])
            .await
            .success();
    }
    let issued =
        gateinto::ipc::issued_credentials(&launcher.shown_credentials(listen).await).unwrap();
    let shown = std::fs::read_to_string(&prompt).unwrap();
    for expected in [
        format!("Gateinto session {id}"),
        format!("Proxy: {listen}"),
        format!("Username: {}", issued.username()),
        format!("Password: {}", issued.password()),
        format!("gateinto session credentials {id}"),
    ] {
        assert!(shown.contains(&expected), "{expected:?} in {shown}");
    }
    std::fs::remove_file(&prompt).unwrap();

    let again = launcher.run(&["session", "credentials", id]).await;
    again.success();
    for text in [&again.stdout, &again.stderr] {
        assert!(!text.contains(issued.password()), "{text}");
    }
    assert_eq!(std::fs::read_to_string(&prompt).unwrap(), shown);

    let unknown = launcher.run(&["session", "credentials", "999"]).await;
    unknown.failure();
    assert!(
        unknown.stderr.contains("no session 999"),
        "{}",
        unknown.stderr
    );
    browser.exit();
}

#[cfg(any(not(windows), feature = "test-hooks"))]
#[tokio::test(flavor = "multi_thread")]
async fn without_a_desktop_or_terminal_the_credentials_are_not_shown() {
    let launcher = Launcher::new("").await.without_a_credentials_prompt();
    let output = launcher
        .open("gateinto://connect?profile=main&auth=session_credentials")
        .await;
    let lines = output.success().lines();
    let id = field(&lines, "session");
    let listen: SocketAddr = field(&lines, "listen").parse().unwrap();
    let browser = wait_for_browser(&launcher.profiles_root, listen).await;
    let issued =
        gateinto::ipc::issued_credentials(&launcher.shown_credentials(listen).await).unwrap();
    for text in [&output.stdout, &output.stderr] {
        assert!(!text.contains(issued.password()), "{text}");
    }
    let named = format!("run `gateinto session credentials {id}` in a terminal");
    if cfg!(windows) {
        assert!(
            !output.stderr.contains("were not shown"),
            "{}",
            output.stderr
        );
        assert!(!output.stderr.contains(&named), "{}", output.stderr);
    } else {
        assert!(
            output.stderr.contains("were not shown"),
            "{}",
            output.stderr
        );
        assert!(output.stderr.contains(&named), "{}", output.stderr);
    }

    let again = launcher.run(&["session", "credentials", id]).await;
    again.failure();
    assert!(
        again.stderr.contains("no desktop or terminal"),
        "{}",
        again.stderr
    );
    assert!(
        !again.stderr.contains(issued.password()),
        "{}",
        again.stderr
    );
    assert!(again.stdout.is_empty(), "{}", again.stdout);
    browser.exit();
}
