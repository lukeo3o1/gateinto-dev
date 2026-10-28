use std::ffi::OsStr;
use std::path::PathBuf;

use gateinto::config::{ConfigFile, GatewayName};
use gateinto::identity::device_key::{Backend, KeyName};
use gateinto::ipc::{
    BrowserKind, LogEvent, LogLevel, LogPage, Request, RequestError, Response, SessionAuth,
    SessionInfo, SessionKind, SessionRoute,
};
use gateinto::link::{Known, KnownGateway, Source};
use gateinto::proxy::DEFAULT_LISTEN;

use crate::credentials::{Issued, Reveal};
use crate::device::{Key, KeyState, Probe, System};
use crate::i18n::Text;
use crate::settings;
use crate::worker::{Command, Loaded};

pub const FLAG: &str = "--demo";
pub const TITLE: Text = Text::DemoTitle;
pub const NOT_STARTED: Text = Text::DemoNotStarted;
pub const NOT_REVOKED: Text = Text::DemoNotRevoked;
pub const NOT_STOPPED: Text = Text::DemoNotStopped;
pub const IGNORED: Text = Text::DemoIgnored;
pub const NOT_SAVED: Text = Text::DemoNotSaved;
pub const NOT_OPENED: Text = Text::DemoNotOpened;

const PROFILE: &str = "g-4f0c2a9d7e1b83c56a0d9e2f4b7c1a3e5d8f0b2c4a6e8d1f3b5c7e9a0c2e4d";
const PID: u32 = 4242;
const FINGERPRINT: &str = "9c4e1a7f3b2d8e6c0a5f9b1d7e3c2a8f6b4d0e9c1a7f5b3d2e8c6a4f0b9d1e7c";
const CONFIG: &str = r#"
[gateways.office]
host = "proxy.example.com"
port = 8443
tls_mode = "hybrid_required"
client_certificate = "required"

[gateways.lab]
host = "lab.example.net"
port = 443
"#;

struct Sample {
    id: u64,
    kind: SessionKind,
    gateway: &'static str,
    upstream: &'static str,
    port: u16,
    route: SessionRoute,
    auth: SessionAuth,
    age: u64,
    tunnels: u64,
    browser: Option<BrowserKind>,
}

const SESSIONS: [Sample; 3] = [
    Sample {
        id: 3,
        kind: SessionKind::Device,
        gateway: "office",
        upstream: "proxy.example.com:8443",
        port: 8080,
        route: SessionRoute::All,
        auth: SessionAuth::Password,
        age: 7_380,
        tunnels: 4,
        browser: None,
    },
    Sample {
        id: 5,
        kind: SessionKind::Browser,
        gateway: PROFILE,
        upstream: "gw.northwind.example:443",
        port: 49_731,
        route: SessionRoute::Mixed,
        auth: SessionAuth::OsUser,
        age: 1_500,
        tunnels: 2,
        browser: Some(BrowserKind::Edge),
    },
    Sample {
        id: 6,
        kind: SessionKind::Browser,
        gateway: "lab",
        upstream: "lab.example.net:443",
        port: 49_744,
        route: SessionRoute::All,
        auth: SessionAuth::Password,
        age: 30,
        tunnels: 0,
        browser: Some(BrowserKind::Chrome),
    },
];

const LOG: [(u64, LogLevel, &str, &str); 8] = [
    (
        7_400,
        LogLevel::Info,
        "agent",
        "agent started, listening on 127.0.0.1:8080",
    ),
    (
        7_380,
        LogLevel::Info,
        "session 3",
        "device proxy opened to proxy.example.com:8443",
    ),
    (
        5_200,
        LogLevel::Warn,
        "session 3",
        "upstream connect took 4.2 s",
    ),
    (
        1_500,
        LogLevel::Info,
        "session 5",
        "browser session opened to gw.northwind.example",
    ),
    (
        900,
        LogLevel::Error,
        "session 5",
        "tunnel to intranet.northwind.example:443 was refused by the gateway",
    ),
    (240, LogLevel::Info, "session 3", "4 tunnels open"),
    (
        30,
        LogLevel::Info,
        "session 6",
        "browser session opened to lab.example.net",
    ),
    (
        5,
        LogLevel::Warn,
        "session 6",
        "idle tunnel closed after 300 s",
    ),
];

pub fn requested<I: IntoIterator<Item = S>, S: AsRef<OsStr>>(args: I) -> bool {
    args.into_iter().skip(1).any(|arg| arg.as_ref() == FLAG)
}

fn sessions(now: u64) -> Vec<SessionInfo> {
    SESSIONS
        .iter()
        .map(|s| SessionInfo {
            id: s.id,
            kind: s.kind,
            gateway: s.gateway.to_owned(),
            upstream: s.upstream.to_owned(),
            listen: (DEFAULT_LISTEN.ip(), s.port).into(),
            route: s.route,
            auth: s.auth,
            started: now - s.age,
            tunnels: s.tunnels,
            browser: s.browser,
        })
        .collect()
}

fn log(after: u64, now: u64) -> Vec<String> {
    let page = LogPage {
        last: LOG.len() as u64,
        events: (1..)
            .zip(LOG)
            .filter(|(seq, _)| *seq > after)
            .map(|(seq, (age, level, scope, message))| LogEvent {
                seq,
                time: (now - age) * 1_000,
                level,
                scope: scope.to_owned(),
                message: message.to_owned(),
            })
            .collect(),
    };
    let mut lines = vec![format!("{}{PID}", gateinto::ipc::AGENT_PID)];
    lines.extend(page.to_lines());
    lines
}

pub fn answer(request: Request, now: u64) -> Response {
    match request {
        Request::List => Response::Ok(sessions(now).iter().map(SessionInfo::to_line).collect()),
        Request::Log { after } => Response::Ok(log(after, now)),
        Request::Credentials(_) => Response::Ok(Vec::new()),
        Request::Launch(_) => Response::Error(NOT_STARTED.english().to_owned()),
        Request::Close(_) => Response::Error(NOT_REVOKED.english().to_owned()),
        Request::Stop => Response::Error(NOT_STOPPED.english().to_owned()),
        Request::Approve(_) | Request::Deny(_) => Response::Error(IGNORED.english().to_owned()),
    }
}

pub fn refusal(command: &Command) -> Option<Text> {
    match command {
        Command::Launch(_) => Some(NOT_STARTED),
        Command::Close(_) => Some(NOT_REVOKED),
        Command::Stop => Some(NOT_STOPPED),
        Command::Probe | Command::Watch(_) | Command::Credentials(..) => None,
    }
}

pub fn send(request: Request) -> std::future::Ready<Result<Response, RequestError>> {
    std::future::ready(Ok(answer(request, gateinto::clock::unix_now())))
}

fn gateway(
    name: &str,
    host: &str,
    port: u16,
    portal: Option<&str>,
    source: Source,
) -> KnownGateway {
    KnownGateway {
        name: name
            .parse::<GatewayName>()
            .expect("sample gateway names are valid"),
        host: Some(host.to_owned()),
        port: Some(port),
        portal_url: portal.map(|url| url.parse().expect("sample portal URLs are valid")),
        source,
    }
}

pub fn loaded() -> Loaded {
    let file = ConfigFile::parse(CONFIG).expect("the sample config parses");
    let browser = PathBuf::from(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe");
    Loaded {
        gateways: Ok(Known {
            gateways: vec![
                gateway("office", "proxy.example.com", 8443, None, Source::Config),
                gateway(
                    PROFILE,
                    "gw.northwind.example",
                    443,
                    Some("https://portal.northwind.example/start"),
                    Source::Linked,
                ),
                gateway("lab", "lab.example.net", 443, None, Source::Config),
            ],
            ..Known::default()
        }),
        agent: Ok(settings::agent(&file, || Some(browser))),
        sections: file.gateways,
        listen: Ok(DEFAULT_LISTEN),
    }
}

pub fn probe() -> Probe {
    Probe {
        key: KeyState::Present(Key {
            backend: Backend::Tpm,
            name: KeyName::default(),
            fingerprint: FINGERPRINT.to_owned(),
        }),
        system: System {
            computer: Some("DEMO-PC".to_owned()),
            account: Some("demo".to_owned()),
            product: Some("Windows 11 Pro".to_owned()),
            build: Some(26_100),
            arch: Some(9),
        },
    }
}

pub fn reveal(reveal: Reveal) -> Reveal {
    Reveal {
        credentials: Some(Issued::Demo),
        ..reveal
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::time::Duration;

    use gateinto::ipc::{LogPage, SessionAuth, SessionInfo, SessionKind};
    use gateinto::sessions::SessionId;
    use gateinto::uri::{LaunchAuth, LaunchRequest};
    use tokio::sync::mpsc::unbounded_channel;
    use tokio::time::timeout;

    use super::*;
    use crate::agent::AgentState;
    use crate::device::KeyState;
    use crate::gateways;
    use crate::sessions;
    use crate::worker::{Update, serve_with};

    const NOW: u64 = 1_800_000_000;

    fn listed() -> Vec<SessionInfo> {
        let Response::Ok(lines) = answer(Request::List, NOW) else {
            panic!("the demo agent refused to list its sessions");
        };
        SessionInfo::parse_list(&lines).unwrap()
    }

    fn refused(request: Request) -> String {
        match answer(request, NOW) {
            Response::Error(message) => message,
            Response::Ok(lines) => panic!("the demo agent accepted a request: {lines:?}"),
        }
    }

    #[test]
    fn only_the_demo_flag_asks_for_the_demo() {
        assert!(requested(["gateinto-gui.exe", "--demo"]));
        assert!(!requested(["gateinto-gui.exe"]));
        assert!(!requested(["--demo"]));
        assert!(!requested(["gateinto-gui.exe", "--demo=1"]));
    }

    #[test]
    fn the_sample_sessions_cover_each_kind_and_some_relay_traffic() {
        let sessions = listed();
        assert!(sessions.iter().any(|s| s.kind == SessionKind::Device));
        assert!(sessions.iter().any(|s| s.kind == SessionKind::Browser));
        assert!(sessions.iter().any(|s| s.auth == SessionAuth::Password));
        assert!(sessions.iter().any(|s| s.tunnels > 0));
        assert!(sessions.iter().any(|s| s.tunnels == 0));
        assert!(sessions.iter().all(|s| s.started < NOW));
        assert!(sessions.iter().all(|s| s.listen.ip().is_loopback()));
    }

    #[test]
    fn actions_are_refused_with_a_demo_notice() {
        let launch = LaunchRequest::new("office", LaunchAuth::SessionCredentials.as_str()).unwrap();
        assert_eq!(refused(Request::Launch(launch)), NOT_STARTED.english());
        assert_eq!(
            refused(Request::Close(SessionId::from(3))),
            NOT_REVOKED.english()
        );
        assert_eq!(refused(Request::Stop), NOT_STOPPED.english());
        let token = "0123456789abcdef0123456789abcdef".parse().unwrap();
        assert_eq!(refused(Request::Approve(token)), IGNORED.english());
        let token = "0123456789abcdef0123456789abcdef".parse().unwrap();
        assert_eq!(refused(Request::Deny(token)), IGNORED.english());
    }

    #[test]
    fn the_sample_log_pages_from_any_point() {
        let page = |after| {
            let Response::Ok(lines) = answer(Request::Log { after }, NOW) else {
                panic!("the demo agent refused its log");
            };
            assert!(gateinto::ipc::agent_pid(&lines).is_some());
            LogPage::parse(&lines).unwrap()
        };
        let all = page(0);
        assert!(all.events.len() >= 6);
        assert_eq!(all.last, all.events.last().unwrap().seq);
        assert!(all.events.iter().all(|e| e.time < NOW * 1_000));
        assert_eq!(page(all.last - 2).events.len(), 2);
        assert!(page(all.last).events.is_empty());
    }

    #[test]
    fn the_sample_shows_hosts_and_never_profile_names() {
        let loaded = loaded();
        let known = loaded.gateways.as_ref().unwrap();
        assert!(known.gateways.len() >= 3);
        assert!(
            known
                .gateways
                .iter()
                .any(|g| g.name.as_str().starts_with("g-"))
        );
        assert!(known.gateways.iter().any(|g| g.portal_url.is_some()));
        for gateway in &known.gateways {
            assert!(gateway.host.is_some());
            assert!(!gateways::label(gateway).starts_with("g-"));
        }
        let names = gateways::names(&loaded.gateways);
        for session in listed() {
            assert!(names.iter().any(|name| name.as_str() == session.gateway));
            assert!(!sessions::row(&session, NOW).gateway.starts_with("g-"));
        }
        assert!(loaded.agent.is_ok());
        assert!(loaded.listen.is_ok());
    }

    #[test]
    fn the_sample_device_has_a_key_and_a_named_computer() {
        let probe = probe();
        let KeyState::Present(key) = &probe.key else {
            panic!("the sample device has no key");
        };
        assert_eq!(key.fingerprint.len(), 64);
        assert!(key.fingerprint.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(probe.system.computer.is_some());
        assert!(crate::device::os(&probe.system).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn the_worker_serves_the_sample_and_demo_credentials_without_an_agent() {
        let asked = RefCell::new(Vec::new());
        let agent = |request: Request| {
            asked.borrow_mut().push(request.clone());
            send(request)
        };
        let (tx, rx) = unbounded_channel();
        tx.send(Command::Watch(true)).unwrap();
        tx.send(Command::Probe).unwrap();
        tx.send(Command::Credentials(3, 1)).unwrap();
        tx.send(Command::Launch("office".parse().unwrap())).unwrap();
        let updates = RefCell::new(Vec::<Update>::new());
        let reveals = RefCell::new(Vec::new());
        let run = serve_with(
            refusal,
            rx,
            agent,
            loaded,
            probe,
            |u| updates.borrow_mut().push(u),
            |r| reveals.borrow_mut().push(reveal(r)),
        );
        assert!(timeout(Duration::from_millis(500), run).await.is_err());
        let updates = updates.borrow();
        let last = updates.last().unwrap();
        assert!(matches!(&last.state, AgentState::Running(s) if !s.is_empty()));
        assert!(last.device.is_some());
        assert!(!last.log.events().is_empty());
        assert!(
            updates
                .iter()
                .any(|u| u.failure == Some(NOT_STARTED.into()))
        );
        let reveals = reveals.borrow();
        let issued = reveals[0].credentials.as_ref().unwrap();
        assert_eq!(
            (issued.username(), issued.password()),
            ("demo-user", "demo-password")
        );
        assert!(
            asked
                .borrow()
                .iter()
                .all(|r| !matches!(r, Request::Approve(_)))
        );
    }

    #[test]
    fn demo_refusals_and_the_title_read_in_chinese_when_shown() {
        let _zh = crate::i18n::speaking(crate::i18n::Language::Chinese);
        let shown = |command| refusal(&command).map(crate::i18n::tr);
        let launch = Command::Launch("office".parse().unwrap());
        assert_eq!(shown(launch), Some("示範：未啟動任何項目"));
        assert_eq!(shown(Command::Close(3)), Some("示範：未撤銷任何項目"));
        assert_eq!(shown(Command::Stop), Some("示範：未停止代理程式"));
        assert_eq!(shown(Command::Probe), None);
        assert_eq!(shown(Command::Credentials(3, 1)), None);
        assert_eq!(crate::i18n::tr(IGNORED), "示範：範例代理程式會忽略這個要求");
        assert_eq!(crate::i18n::tr(NOT_SAVED), "示範：未儲存任何項目");
        assert_eq!(crate::i18n::tr(NOT_OPENED), "示範：未開啟任何項目");
        assert_eq!(crate::i18n::tr(TITLE), "Gateinto 示範");
    }
}
