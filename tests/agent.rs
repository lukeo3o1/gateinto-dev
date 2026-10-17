#[allow(dead_code)]
mod fixture;
#[allow(dead_code)]
mod launch_support;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use fixture::*;
use gateinto::agent::{Agent, AgentLimits, AgentOptions, BrowserSessionPlan, Profiles};
use gateinto::browser::ProfileDir;
use gateinto::config::{GatewayName, PortalUrl};
use gateinto::ipc::{self, BindError, Endpoint, Request, RequestError, Response, Server};
use gateinto::proxy::Config;
use gateinto::uri::LaunchRequest;
use launch_support::*;
use tokio::io::AsyncWriteExt;
use tokio::task::JoinHandle;

struct TestProfiles(BTreeMap<GatewayName, BrowserSessionPlan>);

impl Profiles for TestProfiles {
    fn browser_session(&self, gateway: &GatewayName) -> Result<BrowserSessionPlan, String> {
        self.0
            .get(gateway)
            .cloned()
            .ok_or_else(|| format!("unknown gateway \"{gateway}\""))
    }
}

struct TestAgent {
    endpoint: Endpoint,
    profiles_root: PathBuf,
    serving: JoinHandle<()>,
    _upstream: UpstreamProxy,
}

const PORTAL: &str = "https://portal.example.test/start";

fn endpoint(dir: &std::path::Path) -> Endpoint {
    #[cfg(unix)]
    {
        Endpoint::unix(dir.join("run").join("agent.sock"))
    }
    #[cfg(windows)]
    {
        Endpoint::pipe(&format!(
            "gateinto-test-{}",
            dir.file_name().unwrap().to_str().unwrap()
        ))
    }
}

impl TestAgent {
    async fn start(limits: AgentLimits) -> Self {
        Self::start_with(limits, Some(fake_browser())).await
    }

    async fn start_with(limits: AgentLimits, browser: Option<PathBuf>) -> Self {
        let dir = temp_dir("agent");
        let ca = TestCa::new();
        let upstream = UpstreamProxy::start(ca.server_config(PROXY_NAME), Behavior::Tunnel).await;
        let proxy: Config = agent_config(upstream.addr, ca.roots(), PROXY_NAME);
        let plans = BTreeMap::from([
            (
                "main".parse().unwrap(),
                BrowserSessionPlan {
                    proxy: proxy.clone(),
                    portal_url: Some(PORTAL.parse::<PortalUrl>().unwrap()),
                },
            ),
            (
                "bare".parse().unwrap(),
                BrowserSessionPlan {
                    proxy,
                    portal_url: None,
                },
            ),
        ]);
        let profiles_root = dir.join("state").join("profiles");
        let agent = Agent::new(
            AgentOptions {
                browser,
                profiles_root: profiles_root.clone(),
                limits,
            },
            TestProfiles(plans),
        );
        let endpoint = endpoint(&dir);
        let server = Server::bind(&endpoint).unwrap();
        let serving =
            tokio::spawn(async move { agent.serve(server, std::future::pending()).await });
        Self {
            endpoint,
            profiles_root,
            serving,
            _upstream: upstream,
        }
    }

    async fn send(&self, request: Request) -> Response {
        ipc::send(&self.endpoint, &request).await.unwrap()
    }

    async fn launch(&self, profile: &str) -> Response {
        self.send(Request::Launch(
            LaunchRequest::new(profile, "basic_tofu").unwrap(),
        ))
        .await
    }

    async fn launched(&self, profile: &str) -> (Vec<String>, FakeBrowser) {
        let lines = match self.launch(profile).await {
            Response::Ok(lines) => lines,
            Response::Error(error) => panic!("launch failed: {error}"),
        };
        let listen: SocketAddr = field(&lines, "listen").parse().unwrap();
        let browser = wait_for_browser(&self.profiles_root, listen).await;
        (lines, browser)
    }

    async fn list(&self) -> Vec<String> {
        match self.send(Request::List).await {
            Response::Ok(lines) => lines,
            Response::Error(error) => panic!("list failed: {error}"),
        }
    }

    async fn raw(&self, bytes: &[u8]) -> String {
        let mut stream = ipc::connect(&self.endpoint).await.unwrap();
        let _ = stream.write_all(bytes).await;
        let response = ipc::read_to_close(&mut stream, ipc::MAX_RESPONSE_BYTES)
            .await
            .unwrap_or_default();
        String::from_utf8_lossy(&response).into_owned()
    }

    async fn stop(self) {
        assert_eq!(self.send(Request::Stop).await, Response::Ok(Vec::new()));
        tokio::time::timeout(WAIT, self.serving)
            .await
            .unwrap()
            .unwrap();
    }
}

fn limits() -> AgentLimits {
    AgentLimits {
        launches: 10,
        launch_window: Duration::from_secs(60),
        max_browser_sessions: 4,
    }
}

async fn tunnel_echoes(proxy: SocketAddr, credential: &str) {
    let target = echo_server().await.to_string();
    let (mut stream, response) = send(
        proxy,
        &connect_with(&target, Some(&basic("me", credential))),
    )
    .await;
    assert_eq!(response.status, 200, "{}", response.head);
    stream.write_all(b"through the session").await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(
        read_to_end_within(&mut stream, WAIT).await,
        b"through the session"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_launch_opens_the_portal_in_a_browser_with_its_own_profile_and_session_proxy() {
    let agent = TestAgent::start(limits()).await;

    let (lines, browser) = agent.launched("main").await;

    let listen: SocketAddr = field(&lines, "listen").parse().unwrap();
    assert!(listen.ip().is_loopback());
    assert_eq!(field(&lines, "gateway"), "main");
    assert!(field(&lines, "realm").starts_with("Gateinto "));
    assert_eq!(browser.proxy(), listen);
    assert_eq!(browser.start_page(), PORTAL);
    for flag in [
        "--no-first-run",
        "--no-default-browser-check",
        "--new-window",
    ] {
        assert!(browser.args.iter().any(|arg| arg == flag), "{flag}");
    }
    let profile = browser.profile();
    assert_eq!(profile.parent(), Some(agent.profiles_root.as_path()));
    assert_eq!(PathBuf::from(field(&lines, "profile")), profile);
    assert!(profile.join("Default").join("Preferences").is_file());
    tunnel_echoes(listen, "browser secret").await;
    let (_, other) = send(
        listen,
        &connect_with("127.0.0.1:1", Some(&basic("me", "other"))),
    )
    .await;
    assert_eq!(other.status, 407, "{}", other.head);

    browser.exit();

    wait_until("the profile is removed", || !profile.exists()).await;
    let id = field(&lines, "session").to_owned();
    assert!(
        !agent
            .list()
            .await
            .iter()
            .any(|line| line.starts_with(&format!("session: {id} "))),
    );
    agent.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn without_a_portal_url_the_browser_starts_blank() {
    let agent = TestAgent::start(limits()).await;
    let (_, browser) = agent.launched("bare").await;
    assert_eq!(browser.start_page(), "about:blank");
    agent.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn repeated_launches_open_separate_sessions_profiles_and_browsers() {
    let agent = TestAgent::start(limits()).await;

    let (first, first_browser) = agent.launched("main").await;
    let (second, second_browser) = agent.launched("main").await;

    assert_ne!(field(&first, "session"), field(&second, "session"));
    assert_ne!(field(&first, "listen"), field(&second, "listen"));
    assert_ne!(field(&first, "realm"), field(&second, "realm"));
    assert_ne!(first_browser.profile(), second_browser.profile());
    assert_ne!(first_browser.pid, second_browser.pid);
    let list = agent.list().await;
    for lines in [&first, &second] {
        let expected = format!(
            "session: {} browser main {}",
            field(lines, "session"),
            field(lines, "listen")
        );
        assert!(list.contains(&expected), "{list:?}");
    }
    tunnel_echoes(first_browser.proxy(), "one").await;
    tunnel_echoes(second_browser.proxy(), "two").await;
    agent.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn closing_a_session_stops_its_browser_and_removes_its_profile() {
    let agent = TestAgent::start(limits()).await;
    let (lines, browser) = agent.launched("main").await;
    let (_, other) = agent.launched("main").await;
    let id = field(&lines, "session").parse().unwrap();

    assert_eq!(
        agent.send(Request::Close(id)).await,
        Response::Ok(Vec::new())
    );

    assert!(!browser.profile().exists());
    let list = agent.list().await;
    assert!(
        !list
            .iter()
            .any(|line| line.starts_with(&format!("session: {id} "))),
        "{list:?}"
    );
    assert!(other.profile().exists());
    tunnel_echoes(other.proxy(), "still open").await;
    assert!(matches!(
        agent.send(Request::Close(id)).await,
        Response::Error(error) if error.contains("no session")
    ));
    agent.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn stopping_the_agent_closes_every_session_and_removes_every_profile() {
    let agent = TestAgent::start(limits()).await;
    let (_, first) = agent.launched("main").await;
    let (_, second) = agent.launched("bare").await;
    let (endpoint, root) = (agent.endpoint.clone(), agent.profiles_root.clone());

    agent.stop().await;

    for browser in [&first, &second] {
        assert!(!browser.profile().exists());
    }
    assert_eq!(std::fs::read_dir(root).unwrap().count(), 0);
    assert!(matches!(
        ipc::send(&endpoint, &Request::List).await,
        Err(RequestError::NotRunning)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn launches_beyond_the_rate_limit_are_refused() {
    let agent = TestAgent::start(AgentLimits {
        launches: 2,
        ..limits()
    })
    .await;
    agent.launched("main").await;

    assert!(matches!(
        agent.launch("nope").await,
        Response::Error(error) if error.contains("unknown gateway")
    ));
    let refused = agent.launch("main").await;

    assert!(
        matches!(&refused, Response::Error(error) if error.contains("too many launch requests")),
        "{refused:?}"
    );
    assert_eq!(browsers(&agent.profiles_root).len(), 1);
    agent.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_browser_sessions_are_capped() {
    let agent = TestAgent::start(AgentLimits {
        max_browser_sessions: 1,
        ..limits()
    })
    .await;
    let (lines, _) = agent.launched("main").await;

    let refused = agent.launch("main").await;
    assert!(
        matches!(&refused, Response::Error(error) if error.contains("already open")),
        "{refused:?}"
    );
    agent
        .send(Request::Close(field(&lines, "session").parse().unwrap()))
        .await;
    agent.launched("main").await;
    agent.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_agent_validates_requests_itself() {
    let agent = TestAgent::start(limits()).await;

    assert!(matches!(
        agent.launch("nope").await,
        Response::Error(error) if error.contains("unknown gateway \"nope\"")
    ));
    for request in [
        b"launch ../main basic_tofu\n".as_slice(),
        b"launch -main basic_tofu\n",
        b"launch main none\n",
        b"launch main basic_tofu --config x\n",
        b"open gateinto://connect?profile=main\n",
        b"\xff\n",
        b"list\r\n",
    ] {
        let response = agent.raw(request).await;
        assert!(response.starts_with("error: "), "{request:?}: {response}");
    }
    let flood = vec![b'a'; 4 * ipc::MAX_REQUEST_BYTES];
    assert!(agent.raw(&flood).await.starts_with("error: "));
    assert!(browsers(&agent.profiles_root).is_empty());
    assert!(agent.list().await.is_empty());
    agent.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_browser_that_cannot_start_leaves_no_session_or_profile_behind() {
    let missing = temp_dir("missing-browser").join("no-such-browser");
    let agent = TestAgent::start_with(limits(), Some(missing)).await;

    let response = agent.launch("main").await;

    assert!(
        matches!(&response, Response::Error(error) if error.contains("not found")),
        "{response:?}"
    );
    assert!(agent.list().await.is_empty());
    let leftovers = std::fs::read_dir(&agent.profiles_root)
        .map(|entries| entries.count())
        .unwrap_or(0);
    assert_eq!(leftovers, 0);
    agent.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn only_one_agent_serves_an_endpoint() {
    let dir = temp_dir("endpoint");
    let endpoint = endpoint(&dir);
    let _server = Server::bind(&endpoint).unwrap();
    assert!(matches!(
        Server::bind(&endpoint),
        Err(BindError::AlreadyRunning(_))
    ));
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_stale_socket_left_by_a_crashed_agent_is_replaced() {
    use std::os::unix::fs::PermissionsExt;

    let dir = temp_dir("stale");
    let path = dir.join("run").join("agent.sock");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::set_permissions(
        path.parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
    assert!(path.exists());

    let _server = Server::bind(&Endpoint::unix(path.clone())).unwrap();

    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_shared_runtime_directory_is_refused() {
    use std::os::unix::fs::PermissionsExt;

    let dir = temp_dir("shared");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        Server::bind(&Endpoint::unix(dir.join("agent.sock"))),
        Err(BindError::Io(..))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn serving_removes_profiles_left_behind_by_a_crashed_agent() {
    let dir = temp_dir("crashed");
    let root = dir.join("profiles");
    let stale = ProfileDir::create(&root, "1".parse().unwrap()).unwrap();
    std::fs::write(stale.path().join("Cookies"), b"x").unwrap();
    let foreign = root.join("Default");
    std::fs::create_dir(&foreign).unwrap();
    let agent = Agent::new(
        AgentOptions {
            browser: None,
            profiles_root: root,
            limits: limits(),
        },
        TestProfiles(BTreeMap::new()),
    );
    let endpoint = endpoint(&dir);
    let server = Server::bind(&endpoint).unwrap();
    let serving = tokio::spawn(async move { agent.serve(server, std::future::pending()).await });

    assert_eq!(
        ipc::send(&endpoint, &Request::List).await.unwrap(),
        Response::Ok(Vec::new())
    );

    assert!(!stale.path().exists());
    assert!(foreign.exists());
    ipc::send(&endpoint, &Request::Stop).await.unwrap();
    tokio::time::timeout(WAIT, serving).await.unwrap().unwrap();
}

#[cfg(windows)]
#[test]
fn the_default_pipe_is_named_after_the_user_sid() {
    let name = Endpoint::for_current_user().unwrap().to_string();
    assert!(name.starts_with(r"\\.\pipe\gateinto-agent-S-1-"), "{name}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_to_an_agent_that_never_answers_times_out() {
    let dir = temp_dir("hung");
    let endpoint = endpoint(&dir);
    let _server = Server::bind(&endpoint).unwrap();

    let result =
        ipc::send_with_timeout(&endpoint, &Request::List, Duration::from_millis(300)).await;

    assert!(matches!(result, Err(RequestError::TimedOut)), "{result:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_connection_closed_without_an_answer_is_reported_as_closed() {
    let dir = temp_dir("closed");
    let endpoint = endpoint(&dir);
    let mut server = Server::bind(&endpoint).unwrap();
    let accepting = tokio::spawn(async move {
        drop(server.accept().await.unwrap());
        server
    });

    let result = ipc::send(&endpoint, &Request::List).await;

    assert!(matches!(result, Err(RequestError::Closed)), "{result:?}");
    drop(accepting.await.unwrap());
}

#[cfg(unix)]
fn private_run_dir(dir: &std::path::Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let run = dir.join("run");
    std::fs::create_dir_all(&run).unwrap();
    std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).unwrap();
    run
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_bind_lock_left_by_a_crashed_agent_is_taken_over_and_released() {
    let run = private_run_dir(&temp_dir("lock"));
    let lock = run.join("agent.sock.lock");
    let stale = std::fs::File::create(&lock).unwrap();
    stale
        .set_modified(std::time::SystemTime::now() - Duration::from_secs(120))
        .unwrap();
    drop(stale);

    let _server = Server::bind(&Endpoint::unix(run.join("agent.sock"))).unwrap();

    assert!(!lock.exists());
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_runtime_directory_owned_by_another_user_is_refused() {
    let run = private_run_dir(&temp_dir("owner"));
    if std::os::unix::fs::chown(&run, Some(4242), None).is_err() {
        return;
    }

    let result = Server::bind(&Endpoint::unix(run.join("agent.sock")));

    assert!(
        matches!(&result, Err(BindError::Io(_, error)) if error.to_string().contains("owned")),
        "{result:?}"
    );
    assert!(!run.join("agent.sock").exists());
}
