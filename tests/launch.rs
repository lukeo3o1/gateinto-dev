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
use launch_support::*;
use tokio::io::AsyncWriteExt;

const PORTAL: &str = "https://portal.example.test/welcome";

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
                "gateinto://connect?profile={profile}&auth=basic_tofu"
            ))
            .await;
        let lines = output.success().lines();
        let listen: SocketAddr = field(&lines, "listen").parse().unwrap();
        let browser = wait_for_browser(&self.profiles_root, listen).await;
        (lines, browser)
    }

    async fn list(&self) -> Vec<String> {
        self.run(&["session", "list"]).await.success().lines()
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

async fn tunnel_echoes(proxy: SocketAddr) {
    let target = echo_server().await.to_string();
    let (mut stream, response) =
        send(proxy, &connect_with(&target, Some(&basic("me", "pw")))).await;
    assert_eq!(response.status, 200, "{}", response.head);
    stream.write_all(b"hello").await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(read_to_end_within(&mut stream, WAIT).await, b"hello");
}

fn listed(list: &[String], lines: &[String]) -> bool {
    list.contains(&format!(
        "session: {} browser main {}",
        field(lines, "session"),
        field(lines, "listen")
    ))
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
    tunnel_echoes(browser.proxy()).await;

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
            "gateinto://connect?profile=main&auth=basic_tofu",
        ])
        .await;

    let lines = output.success().lines();
    let listen: SocketAddr = field(&lines, "listen").parse().unwrap();
    let browser = wait_for_browser(&launcher.profiles_root, listen).await;
    assert_eq!(browser.start_page(), PORTAL);
    tunnel_echoes(browser.proxy()).await;
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
    assert!(listed(&after, &lines), "{after:?}");
    let text = after.join("\n");
    for secret in [PORTAL, "ca.pem", field(&lines, "realm")] {
        assert!(!text.contains(secret), "{secret}: {text}");
    }
    assert!(browser.profile().exists());
    assert_eq!(launcher.list().await.len(), 1);
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
    tunnel_echoes(browser.proxy()).await;
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
            .filter(|line| line.contains(" browser "))
            .count(),
        2,
        "{list:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_agent_runs_the_configured_device_session() {
    let launcher =
        Launcher::new("[device_session]\ngateway = \"main\"\nlisten = \"127.0.0.1:0\"\n").await;

    let (lines, _) = launcher.opened("main").await;

    let list = launcher.list().await;
    let device = list
        .iter()
        .find_map(|line| line.strip_prefix("session: 1 device main "))
        .unwrap_or_else(|| panic!("{list:?}"));
    let device: SocketAddr = device.parse().unwrap();
    let target = echo_server().await;
    let mut stream = open_tunnel(device, target).await;
    stream.write_all(b"device").await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(read_to_end_within(&mut stream, WAIT).await, b"device");
    assert_ne!(field(&lines, "session"), "1");
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
        let launcher =
            Launcher::new("[device_session]\ngateway = \"main\"\nlisten = \"127.0.0.1:0\"\n").await;
        let config = launcher.config.to_str().unwrap().to_owned();
        for args in [
            vec!["proxy", "--config", &config],
            vec!["session", "browser", "--config", &config],
        ] {
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
    gateinto::uri::LaunchRequest::new(profile, "basic_tofu")
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
    tunnel_echoes(listen).await;

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
    tunnel_echoes(listen).await;
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
    let (_, response) = send(listen, &connect_with(&target, Some(&basic("me", "pw")))).await;
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
async fn launch_errors_notify_once_but_a_successful_launch_does_not() {
    let mut launcher = Launcher::new("").await;
    let notification = launcher.dir.join("launch-notification.txt");
    launcher
        .env
        .push(("GATEINTO_TEST_OPEN_ERROR_FILE", notification.clone().into()));
    let (_, browser) = launcher.opened("main").await;
    assert!(!notification.exists());
    let output = launcher
        .open("gateinto://connect?profile=missing&auth=basic_tofu")
        .await;
    output.failure();
    let text = std::fs::read_to_string(notification).unwrap();
    assert!(text.contains(output.stderr.trim()), "{text}");
    assert_eq!(text.matches("Gateinto could not open the link.").count(), 1);
    browser.exit();
}
