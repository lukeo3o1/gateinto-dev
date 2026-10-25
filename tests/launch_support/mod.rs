use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

pub const WAIT: Duration = Duration::from_secs(30);

pub fn temp_dir(name: &str) -> PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("gi-{name}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

pub fn fake_browser() -> PathBuf {
    let deps = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned();
    let is_fake_browser = |name: &str| {
        name.strip_prefix("fake_browser-")
            .and_then(|rest| rest.strip_suffix(std::env::consts::EXE_SUFFIX))
            .is_some_and(|hash| !hash.is_empty() && hash.bytes().all(|b| b.is_ascii_hexdigit()))
    };
    std::fs::read_dir(&deps)
        .unwrap()
        .flatten()
        .filter(|entry| entry.file_name().to_str().is_some_and(is_fake_browser))
        .max_by_key(|entry| entry.metadata().and_then(|m| m.modified()).ok())
        .map(|entry| entry.path())
        .unwrap_or_else(|| {
            panic!(
                "no fake_browser test executable in {}; run the tests with cargo test",
                deps.display()
            )
        })
}

pub struct FakeBrowser {
    pub pid: String,
    pub args: Vec<String>,
    dir: PathBuf,
}

impl FakeBrowser {
    pub fn arg(&self, prefix: &str) -> &str {
        self.args
            .iter()
            .find_map(|arg| arg.strip_prefix(prefix))
            .unwrap_or_else(|| panic!("no {prefix} argument in {:?}", self.args))
    }

    pub fn profile(&self) -> PathBuf {
        PathBuf::from(self.arg("--user-data-dir="))
    }

    pub fn proxy(&self) -> SocketAddr {
        self.arg("--proxy-server=http://").parse().unwrap()
    }

    pub fn start_page(&self) -> &str {
        self.args.last().unwrap()
    }

    pub fn exit(&self) {
        std::fs::write(self.dir.join(format!("{}.exit", self.pid)), b"").unwrap();
    }
}

pub fn browsers(profiles_root: &Path) -> Vec<FakeBrowser> {
    let dir = profiles_root.parent().unwrap().join("fake-browser");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut browsers: Vec<FakeBrowser> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            let pid = name.strip_suffix(".args")?.to_owned();
            let args = std::fs::read_to_string(entry.path()).ok()?;
            Some(FakeBrowser {
                pid,
                args: args.lines().map(str::to_owned).collect(),
                dir: dir.clone(),
            })
        })
        .collect();
    browsers.sort_by(|a, b| a.pid.cmp(&b.pid));
    browsers
}

pub async fn wait_for_browser(profiles_root: &Path, proxy: SocketAddr) -> FakeBrowser {
    let deadline = Instant::now() + WAIT;
    loop {
        if let Some(browser) = browsers(profiles_root)
            .into_iter()
            .find(|browser| browser.proxy() == proxy)
        {
            return browser;
        }
        assert!(
            Instant::now() < deadline,
            "no browser was started for {proxy}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub async fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting until {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub fn field<'a>(lines: &'a [String], name: &str) -> &'a str {
    lines
        .iter()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(": "))
        .unwrap_or_else(|| panic!("no {name} in {lines:?}"))
}

pub fn session_auth(lines: &[String]) -> String {
    let credentials = gateinto::ipc::issued_credentials(lines)
        .unwrap_or_else(|| panic!("no session credentials in {lines:?}"));
    crate::fixture::basic(credentials.username(), credentials.password())
}
