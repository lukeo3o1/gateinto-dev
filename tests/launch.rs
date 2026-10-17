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
            ("RUST_LOG", OsString::from("info")),
        ];
        Self {
            dir,
            config,
            env,
            profiles_root,
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
