#[allow(dead_code)]
mod fixture;
#[allow(dead_code)]
mod launch_support;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fixture::*;
use gateinto::agent::{Agent, AgentLimits, AgentOptions, BrowserSessionPlan, Profiles};
use gateinto::browser::ProfileDir;
use gateinto::config::{GatewayName, PortalUrl};
use gateinto::ipc::{
    self, BindError, ConfirmToken, Endpoint, Request, RequestError, Response, Server, SessionAuth,
    SessionInfo, SessionKind, SessionRoute,
};
use gateinto::link::{Known, KnownGateway, LinkedGateway, Source};
use gateinto::proxy::Config;
use gateinto::sessions::SessionId;
use gateinto::uri::LaunchRequest;
use launch_support::*;
use tokio::io::AsyncWriteExt;
use tokio::task::JoinHandle;

type Linked = Arc<Mutex<Vec<LinkedGateway>>>;

struct TestProfiles {
    plans: BTreeMap<GatewayName, (BrowserSessionPlan, Option<PortalUrl>)>,
    template: Config,
    linked: Linked,
}

impl Profiles for TestProfiles {
    fn known(&self) -> Result<Known, String> {
        let configured = self
            .plans
            .iter()
            .map(|(name, (plan, portal))| KnownGateway {
                name: name.clone(),
                host: Some(plan.proxy.upstream.host.clone()),
                port: Some(plan.proxy.upstream.port),
                portal_url: portal.clone(),
                source: Source::Config,
            });
        let linked = self.linked.lock().unwrap().clone();
        let linked = linked.into_iter().map(|gateway| KnownGateway {
            name: gateway.name,
            host: Some(gateway.address.host()),
            port: Some(gateway.address.port()),
            portal_url: gateway.portal_url,
            source: Source::Linked,
        });
        Ok(Known {
            gateways: configured.chain(linked).collect(),
            ..Known::default()
        })
    }

    fn link(&self, gateway: &LinkedGateway) -> Result<(), String> {
        self.linked.lock().unwrap().push(gateway.clone());
        Ok(())
    }

    fn browser_session(&self, gateway: &GatewayName) -> Result<BrowserSessionPlan, String> {
        if let Some((plan, _)) = self.plans.get(gateway) {
            return Ok(plan.clone());
        }
        let linked = self.linked.lock().unwrap();
        let linked = linked
            .iter()
            .find(|linked| &linked.name == gateway)
            .ok_or_else(|| format!("unknown gateway \"{gateway}\""))?;
        let mut proxy = self.template.clone();
        proxy.upstream.host = linked.address.host();
        proxy.upstream.port = linked.address.port();
        Ok(BrowserSessionPlan { proxy })
    }
}

struct TestAgent {
    endpoint: Endpoint,
    profiles_root: PathBuf,
    serving: JoinHandle<()>,
    linked: Linked,
    upstream_port: u16,
    _upstream: UpstreamProxy,
}

const PORTAL: &str = "https://portal.example.test/start";
const NEW_PORTAL: &str = "https://portal.newco.example/home";

fn link(
    profile: &str,
    url: Option<&str>,
    gateway: Option<&str>,
    portal: Option<&str>,
) -> LaunchRequest {
    LaunchRequest::new(profile, "session_credentials")
        .unwrap()
        .with_link(url, gateway, portal)
        .unwrap()
}

fn refused(response: &Response, text: &str) -> bool {
    matches!(response, Response::Error(error) if error.contains(text))
}

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
                (
                    BrowserSessionPlan {
                        proxy: proxy.clone(),
                    },
                    Some(PORTAL.parse::<PortalUrl>().unwrap()),
                ),
            ),
            (
                "bare".parse().unwrap(),
                (
                    BrowserSessionPlan {
                        proxy: proxy.clone(),
                    },
                    None,
                ),
            ),
        ]);
        let linked = Linked::default();
        let profiles_root = dir.join("state").join("profiles");
        let agent = Agent::new(
            AgentOptions {
                browser,
                profiles_root: profiles_root.clone(),
                limits,
            },
            TestProfiles {
                plans,
                template: proxy,
                linked: linked.clone(),
            },
        );
        let endpoint = endpoint(&dir);
        let server = Server::bind(&endpoint).unwrap();
        let serving =
            tokio::spawn(async move { agent.serve(server, std::future::pending()).await });
        Self {
            endpoint,
            profiles_root,
            serving,
            linked,
            upstream_port: upstream.addr.port(),
            _upstream: upstream,
        }
    }

    fn linked(&self) -> Vec<LinkedGateway> {
        self.linked.lock().unwrap().clone()
    }

    async fn opened(&self, request: Request) -> (Vec<String>, FakeBrowser) {
        let lines = match self.send(request).await {
            Response::Ok(lines) => lines,
            Response::Error(error) => panic!("launch failed: {error}"),
        };
        assert_eq!(ipc::confirm_token(&lines), None, "{lines:?}");
        let lines = self.with_credentials(lines).await;
        let listen: SocketAddr = field(&lines, "listen").parse().unwrap();
        let browser = wait_for_browser(&self.profiles_root, listen).await;
        (lines, browser)
    }

    async fn with_credentials(&self, mut lines: Vec<String>) -> Vec<String> {
        let launched = ipc::issued_credentials(&lines);
        assert_eq!(
            launched.is_some(),
            !cfg!(windows),
            "a launch shows credentials only when os_user is not offered: {lines:?}"
        );
        if launched.is_none() {
            let id = field(&lines, "session").parse().unwrap();
            let Response::Ok(shown) = self.send(Request::Credentials(id)).await else {
                panic!("the credentials of session {id} were not shown");
            };
            lines.extend(ipc::credential_lines(
                &ipc::issued_credentials(&shown).unwrap(),
            ));
        }
        lines
    }

    async fn asks(&self, request: LaunchRequest) -> (Vec<String>, ConfirmToken) {
        let lines = match self.send(Request::Launch(request)).await {
            Response::Ok(lines) => lines,
            Response::Error(error) => panic!("launch failed: {error}"),
        };
        let token = ipc::confirm_token(&lines).unwrap_or_else(|| panic!("{lines:?}"));
        (lines, token)
    }

    fn gateway(&self) -> String {
        format!("localhost:{}", self.upstream_port)
    }

    fn new_link(&self, url: Option<&str>) -> LaunchRequest {
        link("newco", url, Some(&self.gateway()), Some(NEW_PORTAL))
    }

    async fn send(&self, request: Request) -> Response {
        ipc::send(&self.endpoint, &request).await.unwrap()
    }

    async fn launch(&self, profile: &str) -> Response {
        self.send(Request::Launch(
            LaunchRequest::new(profile, "session_credentials").unwrap(),
        ))
        .await
    }

    async fn launched(&self, profile: &str) -> (Vec<String>, FakeBrowser) {
        let lines = match self.launch(profile).await {
            Response::Ok(lines) => lines,
            Response::Error(error) => panic!("launch failed: {error}"),
        };
        let lines = self.with_credentials(lines).await;
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
        let response = self.send(Request::Stop).await;
        assert_eq!(
            response,
            Response::Ok(vec![format!("agent-pid: {}", std::process::id())])
        );
        let Response::Ok(lines) = response else {
            unreachable!()
        };
        assert_eq!(ipc::agent_pid(&lines), Some(std::process::id()));
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
        confirm_timeout: Duration::from_secs(60),
    }
}

async fn tunnel_echoes(proxy: SocketAddr, lines: &[String]) {
    let target = echo_server().await.to_string();
    let (mut stream, response) =
        send(proxy, &connect_with(&target, Some(&session_auth(lines)))).await;
    assert_eq!(response.status, 200, "{}", response.head);
    stream.write_all(b"through the session").await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(
        read_to_end_within(&mut stream, WAIT).await,
        b"through the session"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn approving_a_gateway_preserves_mixed_mode_without_storing_it() {
    let agent = TestAgent::start(limits()).await;
    let request = agent.new_link(None).with_route("mixed").unwrap();
    let (echo, token) = agent.asks(request).await;
    assert_eq!(field(&echo, "route"), "mixed");
    let (lines, browser) = agent.opened(Request::Approve(token)).await;
    assert_eq!(field(&lines, "route"), "mixed");
    let target = echo_server_on(std::net::Ipv4Addr::new(127, 0, 0, 2)).await;
    let (mut stream, response) = send(
        browser.proxy(),
        &connect_with(&target.to_string(), Some(&session_auth(&lines))),
    )
    .await;
    assert_eq!(response.status, 200);
    stream.write_all(b"mixed approval").await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(
        read_to_end_within(&mut stream, WAIT).await,
        b"mixed approval"
    );
    assert!(agent._upstream.requests().is_empty());
    let (plain, plain_browser) = agent
        .opened(Request::Launch(
            LaunchRequest::new("newco", "session_credentials").unwrap(),
        ))
        .await;
    assert!(!plain.iter().any(|line| line.starts_with("route:")));
    let (mut stream, response) = send(
        plain_browser.proxy(),
        &connect_with(&target.to_string(), Some(&session_auth(&plain))),
    )
    .await;
    assert_eq!(response.status, 200);
    stream.shutdown().await.unwrap();
    assert!(read_to_end_within(&mut stream, WAIT).await.is_empty());
    assert_eq!(agent._upstream.requests().len(), 1);
    agent.stop().await;
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
    tunnel_echoes(listen, &lines).await;
    for line in ["username", "password"] {
        assert!(!field(&lines, line).is_empty());
    }
    let (_, other) = send(
        listen,
        &connect_with("127.0.0.1:1", Some(&basic("me", "other"))),
    )
    .await;
    assert_eq!(other.status, 407, "{}", other.head);

    browser.exit();

    wait_until("the profile is removed", || !profile.exists()).await;
    let id: u64 = field(&lines, "session").parse().unwrap();
    assert!(
        !agent
            .sessions()
            .await
            .iter()
            .any(|session| session.id == id)
    );
    agent.stop().await;
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

impl TestAgent {
    async fn sessions(&self) -> Vec<SessionInfo> {
        SessionInfo::parse_list(&self.list().await).unwrap()
    }

    async fn listed(&self, lines: &[String]) -> SessionInfo {
        let id: u64 = field(lines, "session").parse().unwrap();
        let sessions = self.sessions().await;
        sessions
            .iter()
            .find(|session| session.id == id)
            .cloned()
            .unwrap_or_else(|| panic!("{sessions:?}"))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_session_list_is_one_json_object_per_session_without_secrets() {
    let agent = TestAgent::start(limits()).await;
    let before = unix_now();
    let (lines, browser) = agent.launched("main").await;
    let after = unix_now();

    let listed = agent.listed(&lines).await;
    assert!((before..=after).contains(&listed.started), "{listed:?}");
    let auth = if cfg!(windows) {
        SessionAuth::OsUser
    } else {
        SessionAuth::Password
    };
    let expected = SessionInfo {
        id: field(&lines, "session").parse().unwrap(),
        kind: SessionKind::Browser,
        gateway: "main".to_owned(),
        upstream: agent._upstream.addr.to_string(),
        listen: field(&lines, "listen").parse().unwrap(),
        route: SessionRoute::All,
        auth,
        started: listed.started,
        tunnels: 0,
        browser: None,
    };
    assert_eq!(listed, expected);
    let list = agent.list().await;
    assert_eq!(list, [expected.to_line()]);
    for secret in ["username", "password", "realm"] {
        let value = field(&lines, secret);
        assert!(list.iter().all(|line| !line.contains(value)), "{list:?}");
    }

    let target = echo_server().await.to_string();
    let (mut stream, response) = send(
        browser.proxy(),
        &connect_with(&target, Some(&session_auth(&lines))),
    )
    .await;
    assert_eq!(response.status, 200, "{}", response.head);
    assert_eq!(agent.listed(&lines).await.tunnels, 1);
    stream.shutdown().await.unwrap();
    assert!(read_to_end_within(&mut stream, WAIT).await.is_empty());
    let deadline = std::time::Instant::now() + WAIT;
    while agent.listed(&lines).await.tunnels != 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "the tunnel is still listed"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
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
    assert_eq!(field(&first, "username"), field(&second, "username"));
    assert_ne!(field(&first, "password"), field(&second, "password"));
    assert_ne!(first_browser.profile(), second_browser.profile());
    assert_ne!(first_browser.pid, second_browser.pid);
    for lines in [&first, &second] {
        let listed = agent.listed(lines).await;
        assert_eq!(listed.kind, SessionKind::Browser);
        assert_eq!(listed.gateway, "main");
        assert_eq!(listed.listen.to_string(), field(lines, "listen"));
    }
    tunnel_echoes(first_browser.proxy(), &first).await;
    tunnel_echoes(second_browser.proxy(), &second).await;
    let (_, crossed) = send(
        second_browser.proxy(),
        &connect_with("127.0.0.1:1", Some(&session_auth(&first))),
    )
    .await;
    assert_eq!(crossed.status, 407, "{}", crossed.head);
    agent.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn closing_a_session_stops_its_browser_and_removes_its_profile() {
    let agent = TestAgent::start(limits()).await;
    let (lines, browser) = agent.launched("main").await;
    let (other_lines, other) = agent.launched("main").await;
    let id = field(&lines, "session").parse().unwrap();

    assert_eq!(
        agent.send(Request::Close(id)).await,
        Response::Ok(Vec::new())
    );

    assert!(!browser.profile().exists());
    let sessions = agent.sessions().await;
    assert!(
        !sessions
            .iter()
            .any(|session| session.id.to_string() == id.to_string()),
        "{sessions:?}"
    );
    assert!(other.profile().exists());
    tunnel_echoes(other.proxy(), &other_lines).await;
    assert!(matches!(
        agent.send(Request::Close(id)).await,
        Response::Error(error) if error.contains("no session")
    ));
    agent.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_credentials_of_a_session_can_be_shown_again_until_it_closes() {
    let agent = TestAgent::start(limits()).await;
    let (lines, _browser) = agent.launched("main").await;
    let (other_lines, _other) = agent.launched("main").await;
    let id: SessionId = field(&lines, "session").parse().unwrap();

    let Response::Ok(again) = agent.send(Request::Credentials(id)).await else {
        panic!("the credentials were not shown again");
    };
    assert_eq!(
        again,
        [
            format!("listen: {}", field(&lines, "listen")),
            format!("username: {}", field(&lines, "username")),
            format!("password: {}", field(&lines, "password")),
        ]
    );
    assert_eq!(
        ipc::issued_credentials(&again),
        ipc::issued_credentials(&lines)
    );

    assert_eq!(
        agent.send(Request::Close(id)).await,
        Response::Ok(Vec::new())
    );
    let unknown: SessionId = "999".parse().unwrap();
    for id in [id, unknown] {
        let Response::Error(error) = agent.send(Request::Credentials(id)).await else {
            panic!("credentials of a closed or unknown session were shown");
        };
        assert_eq!(error, format!("no session {id}"));
    }
    let other_id = field(&other_lines, "session").parse().unwrap();
    assert!(matches!(
        agent.send(Request::Credentials(other_id)).await,
        Response::Ok(shown) if ipc::issued_credentials(&shown) == ipc::issued_credentials(&other_lines)
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
        b"launch ../main session_credentials\n".as_slice(),
        b"launch -main session_credentials\n",
        b"launch main none\n",
        b"launch main session_credentials --config x\n",
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
        TestProfiles {
            plans: BTreeMap::new(),
            template: agent_config(
                SocketAddr::from((LOOPBACK, 1)),
                rustls::RootCertStore::empty(),
                PROXY_NAME,
            ),
            linked: Linked::default(),
        },
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

#[tokio::test(flavor = "multi_thread")]
async fn a_link_opens_a_start_page_on_the_portal_origin_only() {
    let agent = TestAgent::start(limits()).await;
    let start = "https://portal.example.test/deep?x=1";

    let (_, browser) = agent
        .opened(Request::Launch(link("main", Some(start), None, None)))
        .await;
    assert_eq!(browser.start_page(), start);

    for (profile, url, error) in [
        ("main", "https://evil.example/", "not on the origin"),
        (
            "main",
            "https://portal.example.test:8443/",
            "not on the origin",
        ),
        ("bare", "https://portal.example.test/", "has no portal_url"),
    ] {
        let response = agent
            .send(Request::Launch(link(profile, Some(url), None, None)))
            .await;
        assert!(refused(&response, error), "{url}: {response:?}");
    }
    assert_eq!(browsers(&agent.profiles_root).len(), 1);
    agent.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_link_that_disagrees_with_a_local_gateway_is_refused_without_asking() {
    let agent = TestAgent::start(limits()).await;
    for (gateway, portal) in [
        ("evil.example:443", PORTAL),
        (
            agent.gateway().as_str(),
            "https://portal.example.test/other",
        ),
    ] {
        let response = agent
            .send(Request::Launch(link(
                "main",
                None,
                Some(gateway),
                Some(portal),
            )))
            .await;
        assert!(refused(&response, "differs"), "{response:?}");
    }
    let upstream = format!("127.0.0.1:{}", agent.upstream_port);
    let response = agent
        .send(Request::Launch(link(
            "other",
            None,
            Some(&upstream),
            Some(NEW_PORTAL),
        )))
        .await;
    assert!(refused(&response, "already set up as"), "{response:?}");
    assert!(agent.linked().is_empty());
    assert!(browsers(&agent.profiles_root).is_empty());
    agent.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_gateway_is_stored_only_after_approval_and_relays_the_session() {
    let agent = TestAgent::start(limits()).await;
    let start = "https://portal.newco.example/app";

    let (lines, token) = agent.asks(agent.new_link(Some(start))).await;
    assert_eq!(field(&lines, "gateway"), "newco");
    assert_eq!(field(&lines, "address"), agent.gateway());
    assert_eq!(field(&lines, "portal"), "https://portal.newco.example");
    assert!(agent.linked().is_empty());
    assert!(browsers(&agent.profiles_root).is_empty());

    let (lines, browser) = agent.opened(Request::Approve(token)).await;
    assert_eq!(field(&lines, "gateway"), "newco");
    assert_eq!(browser.start_page(), start);
    tunnel_echoes(browser.proxy(), &lines).await;
    let linked = agent.linked();
    assert_eq!(linked.len(), 1);
    assert_eq!(linked[0].name.as_str(), "newco");
    assert_eq!(linked[0].address.to_string(), agent.gateway());
    assert_eq!(linked[0].portal_url.as_ref().unwrap().as_str(), NEW_PORTAL);
    assert!(linked[0].approved_at.is_some());

    assert!(refused(
        &agent.send(Request::Approve(token)).await,
        "no gateway confirmation"
    ));
    let (_, again) = agent
        .opened(Request::Launch(link(
            "newco",
            None,
            Some(&agent.gateway()),
            Some(NEW_PORTAL),
        )))
        .await;
    assert_eq!(again.start_page(), NEW_PORTAL);
    let (_, plain) = agent
        .opened(Request::Launch(link("newco", None, None, None)))
        .await;
    assert_eq!(plain.start_page(), NEW_PORTAL);
    assert_eq!(agent.linked().len(), 1);
    agent.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_denied_gateway_is_not_stored_and_cannot_be_approved_afterwards() {
    let agent = TestAgent::start(limits()).await;
    let (_, token) = agent.asks(agent.new_link(None)).await;

    assert_eq!(
        agent.send(Request::Deny(token)).await,
        Response::Ok(Vec::new())
    );
    assert!(refused(
        &agent.send(Request::Approve(token)).await,
        "no gateway confirmation"
    ));
    assert!(agent.linked().is_empty());
    assert!(browsers(&agent.profiles_root).is_empty());
    let response = agent.launch("newco").await;
    assert!(
        refused(&response, "unknown gateway \"newco\""),
        "{response:?}"
    );
    agent.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn only_one_confirmation_waits_at_a_time_until_it_is_answered() {
    let agent = TestAgent::start(AgentLimits {
        confirm_timeout: Duration::from_secs(30),
        ..limits()
    })
    .await;
    let (_, first) = agent.asks(agent.new_link(None)).await;
    let other = link(
        "other",
        None,
        Some("localhost:1"),
        Some("https://other.example/"),
    );

    let response = agent.send(Request::Launch(other.clone())).await;
    assert!(refused(&response, "already waiting"), "{response:?}");
    let wrong = ConfirmToken::random().unwrap();
    assert!(refused(
        &agent.send(Request::Approve(wrong)).await,
        "no gateway confirmation"
    ));
    assert!(refused(
        &agent.send(Request::Deny(wrong)).await,
        "no gateway confirmation"
    ));
    assert_eq!(
        agent.send(Request::Deny(first)).await,
        Response::Ok(Vec::new())
    );

    let (_, second) = agent.asks(other).await;
    assert_ne!(second, first);
    assert!(agent.linked().is_empty());
    agent.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unanswered_confirmation_expires() {
    let agent = TestAgent::start(AgentLimits {
        confirm_timeout: Duration::from_millis(300),
        ..limits()
    })
    .await;
    let (_, first) = agent.asks(agent.new_link(None)).await;
    tokio::time::sleep(Duration::from_millis(1200)).await;

    assert!(refused(
        &agent.send(Request::Approve(first)).await,
        "no gateway confirmation"
    ));
    let (_, second) = agent.asks(agent.new_link(None)).await;
    assert_ne!(second, first);
    assert!(agent.linked().is_empty());
    assert!(browsers(&agent.profiles_root).is_empty());
    agent.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_rate_limit_applies_before_any_confirmation_is_asked() {
    let agent = TestAgent::start(AgentLimits {
        launches: 1,
        ..limits()
    })
    .await;
    let (_, token) = agent.asks(agent.new_link(None)).await;
    assert_eq!(
        agent.send(Request::Deny(token)).await,
        Response::Ok(Vec::new())
    );

    let response = agent.send(Request::Launch(agent.new_link(None))).await;
    assert!(
        refused(&response, "too many launch requests"),
        "{response:?}"
    );
    agent.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_approval_is_kept_when_the_session_cap_is_reached_meanwhile() {
    let agent = TestAgent::start(AgentLimits {
        launches: 100,
        max_browser_sessions: 1,
        ..limits()
    })
    .await;
    let (_, token) = agent.asks(agent.new_link(None)).await;
    let (_, browser) = agent.launched("main").await;

    let response = agent.send(Request::Approve(token)).await;
    assert!(refused(&response, "was added"), "{response:?}");
    assert!(refused(&response, "already open"), "{response:?}");
    assert_eq!(agent.linked().len(), 1);
    assert_eq!(browsers(&agent.profiles_root).len(), 1);

    browser.exit();
    let deadline = std::time::Instant::now() + WAIT;
    let lines = loop {
        match agent.send(Request::Launch(agent.new_link(None))).await {
            Response::Ok(lines) => break lines,
            Response::Error(error) if error.contains("already open") => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the session never closed"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Response::Error(error) => panic!("launch failed: {error}"),
        }
    };
    assert_eq!(ipc::confirm_token(&lines), None, "{lines:?}");
    let listen: SocketAddr = field(&lines, "listen").parse().unwrap();
    let again = wait_for_browser(&agent.profiles_root, listen).await;
    assert_eq!(again.start_page(), NEW_PORTAL);
    agent.stop().await;
}
