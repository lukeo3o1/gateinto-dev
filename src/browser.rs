use std::ffi::OsString;
use std::fmt;
use std::fs::DirBuilder;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use tokio::process::{Child, Command};
use tracing::warn;

use crate::config::PortalUrl;
use crate::job::{Job, SpawnError};
use crate::sessions::SessionId;

pub const MARKER: &str = "gateinto-profile";
const MARKER_CONTENT: &[u8] =
    b"Gateinto browser session profile; deleted when the session closes\n";
const RANDOM_HEX_LEN: usize = 16;

#[derive(Debug)]
pub enum BrowserError {
    NotFound(PathBuf),
    NoBrowser,
}

impl fmt::Display for BrowserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(path) => write!(f, "browser executable {} not found", path.display()),
            Self::NoBrowser => f.write_str(
                "neither Chrome nor Edge was found; set executable in the [browser] section",
            ),
        }
    }
}

impl std::error::Error for BrowserError {}

pub fn browser_args(
    user_data_dir: &Path,
    proxy: SocketAddr,
    start: Option<&PortalUrl>,
) -> Vec<OsString> {
    let mut user_data = OsString::from("--user-data-dir=");
    user_data.push(user_data_dir);
    vec![
        user_data,
        OsString::from(format!("--proxy-server=http://{proxy}")),
        OsString::from("--no-first-run"),
        OsString::from("--no-default-browser-check"),
        OsString::from("--new-window"),
        OsString::from(start.map_or("about:blank", PortalUrl::as_str)),
    ]
}

pub fn browser_name(executable: &Path) -> Option<&'static str> {
    let name = executable.file_name()?.to_str()?.to_ascii_lowercase();
    match name.strip_suffix(".exe").unwrap_or(&name) {
        "chrome" | "google-chrome" | "google-chrome-stable" => Some("chrome"),
        "msedge" | "microsoft-edge" | "microsoft-edge-stable" => Some("edge"),
        "chromium" | "chromium-browser" => Some("chromium"),
        _ => None,
    }
}

pub fn find_browser(configured: Option<&Path>) -> Result<PathBuf, BrowserError> {
    if let Some(path) = configured {
        return if path.is_file() {
            Ok(path.to_owned())
        } else {
            Err(BrowserError::NotFound(path.to_owned()))
        };
    }
    candidates()
        .into_iter()
        .find(|path| path.is_file())
        .ok_or(BrowserError::NoBrowser)
}

#[cfg(windows)]
fn candidates() -> Vec<PathBuf> {
    windows_candidates(|name| std::env::var_os(name), crate::registry::app_path)
}

#[cfg(not(windows))]
fn candidates() -> Vec<PathBuf> {
    let names = [
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
        "microsoft-edge",
    ];
    let path = std::env::var_os("PATH").unwrap_or_default();
    names
        .iter()
        .flat_map(|name| std::env::split_paths(&path).map(move |dir| dir.join(name)))
        .collect()
}

pub fn windows_candidates(
    env: impl Fn(&str) -> Option<OsString>,
    app_path: impl Fn(&str) -> Option<PathBuf>,
) -> Vec<PathBuf> {
    let browsers: [(&str, &[&str], &[&str]); 2] = [
        (
            "chrome.exe",
            &["Google", "Chrome", "Application"],
            &[
                "ProgramW6432",
                "ProgramFiles",
                "ProgramFiles(x86)",
                "LOCALAPPDATA",
            ],
        ),
        (
            "msedge.exe",
            &["Microsoft", "Edge", "Application"],
            &["ProgramFiles(x86)", "ProgramW6432", "ProgramFiles"],
        ),
    ];
    let mut candidates = Vec::new();
    for (executable, folders, bases) in browsers {
        candidates.extend(app_path(executable));
        for base in bases.iter().filter_map(|name| env(name)) {
            let dir = folders
                .iter()
                .fold(PathBuf::from(base), |path, folder| path.join(folder));
            let candidate = dir.join(executable);
            if !candidates.contains(&candidate) {
                candidates.push(candidate);
            }
        }
    }
    candidates
}

pub fn profiles_root() -> Option<PathBuf> {
    profiles_root_from(|name| std::env::var_os(name))
}

pub fn profiles_root_from(env: impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    let profiles = match crate::ipc::instance_from(&env).ok()? {
        Some(instance) => format!("profiles-{instance}"),
        None => "profiles".to_owned(),
    };
    let absolute = |name| {
        env(name)
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
    };
    let base = if cfg!(windows) {
        absolute("LOCALAPPDATA").map(|dir| dir.join("Gateinto"))
    } else {
        absolute("XDG_STATE_HOME")
            .or_else(|| absolute("HOME").map(|home| home.join(".local").join("state")))
            .map(|dir| dir.join("gateinto"))
    };
    base.map(|dir| dir.join(profiles))
}

#[derive(Debug)]
pub enum BrowserProcess {
    Child(Box<Child>),
    #[cfg(windows)]
    Job(crate::job::Process),
}

impl BrowserProcess {
    pub async fn wait(&mut self) -> io::Result<ExitStatus> {
        match self {
            Self::Child(child) => child.wait().await,
            #[cfg(windows)]
            Self::Job(process) => process.wait().await,
        }
    }

    pub async fn kill(&mut self) -> io::Result<()> {
        match self {
            Self::Child(child) => child.kill().await,
            #[cfg(windows)]
            Self::Job(process) => process.kill().await,
        }
    }

    pub async fn release(&mut self) -> io::Result<()> {
        match self {
            Self::Child(_) => Ok(()),
            #[cfg(windows)]
            Self::Job(process) => process.kill().await,
        }
    }
}

pub fn spawn(
    executable: &Path,
    args: Vec<OsString>,
    job: Option<&Arc<Job>>,
) -> Result<BrowserProcess, SpawnError> {
    #[cfg(windows)]
    if let Some(job) = job {
        return job.spawn(executable, &args).map(BrowserProcess::Job);
    }
    #[cfg(not(windows))]
    let _ = job;
    Command::new(executable)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map(|child| BrowserProcess::Child(Box::new(child)))
        .map_err(SpawnError::Process)
}

#[derive(Debug)]
pub struct ProfileDir {
    root: PathBuf,
    path: PathBuf,
}

impl ProfileDir {
    pub fn create(root: &Path, session: SessionId) -> io::Result<Self> {
        create_private_dir(root, true)?;
        let mut random = [0; RANDOM_HEX_LEN / 2];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| io::Error::other("the system random number generator failed"))?;
        let random: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = root.join(format!("{session}-{random}"));
        create_private_dir(&path, false)?;
        let profile = Self {
            root: root.to_owned(),
            path,
        };
        if let Err(error) = std::fs::write(profile.path.join(MARKER), MARKER_CONTENT) {
            let _ = std::fs::remove_dir_all(&profile.path);
            return Err(error);
        }
        Ok(profile)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn remove(&self) -> io::Result<()> {
        remove_profile(&self.root, &self.path)
    }
}

pub(crate) fn create_private_dir(path: &Path, recursive: bool) -> io::Result<()> {
    let mut builder = DirBuilder::new();
    builder.recursive(recursive);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(path)
}

fn is_profile_name(name: &str) -> bool {
    name.split_once('-').is_some_and(|(id, random)| {
        !id.is_empty()
            && id.bytes().all(|byte| byte.is_ascii_digit())
            && random.len() == RANDOM_HEX_LEN
            && random
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn is_marked_profile(root: &Path, path: &Path) -> bool {
    path.parent() == Some(root)
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(is_profile_name)
        && std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir())
        && std::fs::symlink_metadata(path.join(MARKER)).is_ok_and(|metadata| metadata.is_file())
        && std::fs::read(path.join(MARKER)).is_ok_and(|content| content == MARKER_CONTENT)
}

fn remove_profile(root: &Path, path: &Path) -> io::Result<()> {
    if !is_marked_profile(root, path) {
        return Err(io::Error::other(format!(
            "{} is not a Gateinto browser profile; leaving it in place",
            path.display()
        )));
    }
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_name() == MARKER {
            continue;
        }
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_dir() {
            std::fs::remove_dir_all(path)?;
        } else if file_type.is_symlink() {
            std::fs::remove_file(&path).or_else(|_| std::fs::remove_dir(&path))?;
        } else {
            std::fs::remove_file(path)?;
        }
    }
    std::fs::remove_file(path.join(MARKER))?;
    std::fs::remove_dir(path)
}

pub fn sweep(root: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(root) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|entry| is_marked_profile(root, &entry.path()))
        .filter(|entry| match remove_profile(root, &entry.path()) {
            Ok(()) => true,
            Err(error) => {
                warn!(
                    "removing the stale browser profile {} failed: {error}",
                    entry.path().display()
                );
                false
            }
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn temp_root(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("gateinto-browser-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn env(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let vars: HashMap<String, OsString> = vars
            .iter()
            .map(|(name, value)| (name.to_string(), OsString::from(value)))
            .collect();
        move |name| vars.get(name).cloned()
    }

    #[test]
    fn the_browser_gets_an_isolated_profile_the_session_proxy_and_the_portal() {
        let dir = Path::new("profiles").join("1-00112233aabbccdd");
        let proxy: SocketAddr = "127.0.0.1:49152".parse().unwrap();
        let portal: PortalUrl = "https://portal.example.test/start".parse().unwrap();
        let mut user_data_dir = OsString::from("--user-data-dir=");
        user_data_dir.push(&dir);
        let expected = |start: &str| {
            vec![
                user_data_dir.clone(),
                OsString::from("--proxy-server=http://127.0.0.1:49152"),
                OsString::from("--no-first-run"),
                OsString::from("--no-default-browser-check"),
                OsString::from("--new-window"),
                OsString::from(start),
            ]
        };

        assert_eq!(
            browser_args(&dir, proxy, Some(&portal)),
            expected("https://portal.example.test/start")
        );
        assert_eq!(browser_args(&dir, proxy, None), expected("about:blank"));
    }

    #[test]
    fn known_browser_executables_are_named_and_others_are_not() {
        for (path, name) in [
            (
                r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                Some("chrome"),
            ),
            (
                r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                Some("edge"),
            ),
            ("/usr/bin/google-chrome", Some("chrome")),
            ("/usr/bin/google-chrome-stable", Some("chrome")),
            ("/usr/bin/chromium", Some("chromium")),
            ("/usr/bin/chromium-browser", Some("chromium")),
            ("/usr/bin/microsoft-edge", Some("edge")),
            ("/opt/CHROME.EXE", Some("chrome")),
            ("/opt/brave", None),
            ("", None),
        ] {
            let path = PathBuf::from(path.replace('\\', std::path::MAIN_SEPARATOR_STR));
            assert_eq!(browser_name(&path), name, "{}", path.display());
        }
    }

    #[test]
    fn chrome_is_preferred_over_edge_and_app_paths_over_install_folders() {
        let env = env(&[
            ("ProgramFiles", r"C:\PF"),
            ("ProgramFiles(x86)", r"C:\PF86"),
            ("LOCALAPPDATA", r"C:\Users\me\AppData\Local"),
        ]);
        let app_path = |name: &str| Some(PathBuf::from(format!(r"C:\AppPaths\{name}")));
        let install = |base: &str, parts: &[&str]| {
            parts
                .iter()
                .fold(PathBuf::from(base), |path, part| path.join(part))
        };
        let chrome = ["Google", "Chrome", "Application", "chrome.exe"];
        let edge = ["Microsoft", "Edge", "Application", "msedge.exe"];

        assert_eq!(
            windows_candidates(env, app_path),
            vec![
                PathBuf::from(r"C:\AppPaths\chrome.exe"),
                install(r"C:\PF", &chrome),
                install(r"C:\PF86", &chrome),
                install(r"C:\Users\me\AppData\Local", &chrome),
                PathBuf::from(r"C:\AppPaths\msedge.exe"),
                install(r"C:\PF86", &edge),
                install(r"C:\PF", &edge),
            ]
        );
    }

    #[test]
    fn a_64_bit_process_lists_each_install_folder_once() {
        let env = env(&[
            ("ProgramFiles", r"C:\PF"),
            ("ProgramFiles(x86)", r"C:\PF86"),
            ("ProgramW6432", r"C:\PF"),
        ]);
        let install = |base: &str, parts: &[&str]| {
            parts
                .iter()
                .fold(PathBuf::from(base), |path, part| path.join(part))
        };
        let chrome = ["Google", "Chrome", "Application", "chrome.exe"];
        let edge = ["Microsoft", "Edge", "Application", "msedge.exe"];

        assert_eq!(
            windows_candidates(env, |_| None),
            vec![
                install(r"C:\PF", &chrome),
                install(r"C:\PF86", &chrome),
                install(r"C:\PF86", &edge),
                install(r"C:\PF", &edge),
            ]
        );
    }

    #[test]
    fn a_32_bit_process_on_64_bit_windows_finds_64_bit_browsers() {
        let env = env(&[
            ("ProgramFiles", r"C:\PF86"),
            ("ProgramFiles(x86)", r"C:\PF86"),
            ("ProgramW6432", r"C:\PF"),
        ]);
        let install = |base: &str, parts: &[&str]| {
            parts
                .iter()
                .fold(PathBuf::from(base), |path, part| path.join(part))
        };
        let chrome = ["Google", "Chrome", "Application", "chrome.exe"];
        let edge = ["Microsoft", "Edge", "Application", "msedge.exe"];

        assert_eq!(
            windows_candidates(env, |_| None),
            vec![
                install(r"C:\PF", &chrome),
                install(r"C:\PF86", &chrome),
                install(r"C:\PF86", &edge),
                install(r"C:\PF", &edge),
            ]
        );
    }

    #[test]
    fn missing_variables_and_app_paths_are_skipped() {
        let candidates = windows_candidates(env(&[("ProgramFiles", r"C:\PF")]), |_| None);
        assert_eq!(candidates.len(), 2, "{candidates:?}");
        assert!(windows_candidates(env(&[]), |_| None).is_empty());
    }

    #[test]
    fn profiles_live_in_the_per_user_application_data() {
        if cfg!(windows) {
            assert_eq!(
                profiles_root_from(env(&[("LOCALAPPDATA", r"C:\Local")])),
                Some(PathBuf::from(r"C:\Local").join("Gateinto").join("profiles"))
            );
            assert_eq!(profiles_root_from(env(&[("HOME", "/home/me")])), None);
        } else {
            assert_eq!(
                profiles_root_from(env(&[("XDG_STATE_HOME", "/state"), ("HOME", "/home/me")])),
                Some(PathBuf::from("/state/gateinto/profiles"))
            );
            assert_eq!(
                profiles_root_from(env(&[("HOME", "/home/me")])),
                Some(PathBuf::from("/home/me/.local/state/gateinto/profiles"))
            );
            assert_eq!(
                profiles_root_from(env(&[("XDG_STATE_HOME", "relative"), ("HOME", "/h")])),
                Some(PathBuf::from("/h/.local/state/gateinto/profiles"))
            );
            assert_eq!(profiles_root_from(env(&[])), None);
        }
    }

    #[test]
    fn each_agent_instance_has_its_own_profiles_directory() {
        let (base, root) = if cfg!(windows) {
            (
                ("LOCALAPPDATA", r"C:\Local"),
                PathBuf::from(r"C:\Local").join("Gateinto"),
            )
        } else {
            (
                ("XDG_STATE_HOME", "/state"),
                PathBuf::from("/state/gateinto"),
            )
        };
        assert_eq!(
            profiles_root_from(env(&[base, ("GATEINTO_INSTANCE", "test-1")])),
            Some(root.join("profiles-test-1"))
        );
        assert_eq!(
            profiles_root_from(env(&[base, ("GATEINTO_INSTANCE", "../x")])),
            None
        );
    }

    #[test]
    fn sweeping_one_instance_leaves_another_instances_profiles_alone() {
        let state = temp_root("instances");
        let root = |instance| {
            let vars = [
                ("LOCALAPPDATA", state.to_str().unwrap()),
                ("XDG_STATE_HOME", state.to_str().unwrap()),
                ("GATEINTO_INSTANCE", instance),
            ];
            profiles_root_from(env(&vars)).unwrap()
        };
        let other = ProfileDir::create(&root("b"), SessionId(1)).unwrap();

        assert_eq!(sweep(&root("a")), 0);

        assert!(other.path().join(MARKER).exists());
    }

    #[test]
    fn a_profile_directory_is_marked_unique_and_removed_completely() {
        let root = temp_root("create");
        let first = ProfileDir::create(&root, SessionId(7)).unwrap();
        let second = ProfileDir::create(&root, SessionId(7)).unwrap();

        assert_ne!(first.path(), second.path());
        for profile in [&first, &second] {
            assert_eq!(profile.path().parent(), Some(root.as_path()));
            let name = profile.path().file_name().unwrap().to_str().unwrap();
            let (id, random) = name.split_once('-').unwrap();
            assert_eq!(id, "7");
            assert_eq!(random.len(), 16);
            assert!(profile.path().join(MARKER).is_file());
        }

        let nested = first.path().join("Default").join("Cache");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("data"), b"cached").unwrap();
        std::fs::write(first.path().join("Local State"), b"{}").unwrap();
        first.remove().unwrap();

        assert!(!first.path().exists());
        assert!(second.path().exists());
        second.remove().unwrap();
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn profile_directories_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_root("private").join("profiles");
        let profile = ProfileDir::create(&root, SessionId(1)).unwrap();
        for dir in [&root, &profile.path().to_owned()] {
            let mode = std::fs::metadata(dir).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700, "{}", dir.display());
        }
    }

    #[test]
    fn a_profile_whose_marker_is_gone_is_not_removed() {
        let root = temp_root("unmarked");
        let profile = ProfileDir::create(&root, SessionId(1)).unwrap();
        std::fs::write(profile.path().join("keep"), b"x").unwrap();
        std::fs::remove_file(profile.path().join(MARKER)).unwrap();

        assert!(profile.remove().is_err());
        assert!(profile.path().join("keep").exists());
    }

    #[test]
    fn sweeping_removes_only_marked_gateinto_profiles() {
        let root = temp_root("sweep");
        let stale = ProfileDir::create(&root, SessionId(3)).unwrap();
        std::fs::write(stale.path().join("Cookies"), b"x").unwrap();
        let unmarked = root.join("4-0011223344556677");
        std::fs::create_dir(&unmarked).unwrap();
        let wrong_marker = root.join("5-0011223344556677");
        std::fs::create_dir(&wrong_marker).unwrap();
        std::fs::write(wrong_marker.join(MARKER), b"something else").unwrap();
        let wrong_name = root.join("Default");
        std::fs::create_dir(&wrong_name).unwrap();
        std::fs::write(
            wrong_name.join(MARKER),
            std::fs::read(stale.path().join(MARKER)).unwrap(),
        )
        .unwrap();
        std::fs::write(root.join("6-0011223344556677"), b"a file").unwrap();

        assert_eq!(sweep(&root), 1);

        assert!(!stale.path().exists());
        for kept in [&unmarked, &wrong_marker, &wrong_name] {
            assert!(kept.exists(), "{}", kept.display());
        }
        assert!(root.join("6-0011223344556677").exists());
        assert_eq!(sweep(&root.join("missing")), 0);
    }

    #[cfg(unix)]
    #[test]
    fn removal_does_not_follow_symbolic_links() {
        let root = temp_root("symlink");
        let outside = temp_root("symlink-outside");
        std::fs::write(outside.join("precious"), b"x").unwrap();
        let profile = ProfileDir::create(&root, SessionId(1)).unwrap();
        std::os::unix::fs::symlink(&outside, profile.path().join("link")).unwrap();
        let linked = root.join("9-0011223344556677");
        std::os::unix::fs::symlink(profile.path(), &linked).unwrap();

        assert_eq!(sweep(&root), 1);

        assert!(outside.join("precious").exists());
        assert!(!profile.path().exists());
        assert!(std::fs::symlink_metadata(&linked).is_ok());
    }
}
