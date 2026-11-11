#![cfg(target_os = "linux")]

mod isolated;

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

const ROOT_WARNING: &str = "warning: running as root, which can bypass every check Gateinto \
                            makes and is outside its security model; run Gateinto as the user \
                            who uses it";

struct Home {
    dir: PathBuf,
    scheme: String,
}

impl Home {
    fn new() -> Self {
        static RUNS: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "gateinto-uri-registration-{}-{}",
            std::process::id(),
            RUNS.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self {
            dir,
            scheme: format!("gateinto-test-{}", std::process::id()),
        }
    }

    fn env(&self, command: &mut Command) {
        command
            .env("HOME", &self.dir)
            .env("XDG_CONFIG_HOME", self.dir.join(".config"))
            .env("XDG_DATA_HOME", self.dir.join(".local/share"));
    }

    fn gateinto(&self, args: &[&str]) -> Output {
        let mut command = isolated::gateinto();
        self.env(&mut command);
        command.args(args).args(["--scheme", &self.scheme]);
        command.output().unwrap()
    }

    fn status(&self, desktop: Option<&str>) -> String {
        let mut command = isolated::gateinto();
        self.env(&mut command);
        if let Some(desktop) = desktop {
            command.env("XDG_CURRENT_DESKTOP", desktop);
        }
        command
            .arg("status")
            .env("GATEINTO_INSTANCE", format!("uri-{}", std::process::id()));
        stdout(&command.output().unwrap())
    }

    fn stderr(&self, output: &Output) -> String {
        let stderr = String::from_utf8(output.stderr.clone()).unwrap();
        if std::fs::metadata(&self.dir).unwrap().uid() == 0 {
            stderr
                .strip_prefix(&format!("{ROOT_WARNING}\n"))
                .unwrap_or_else(|| panic!("{stderr}"))
                .to_owned()
        } else {
            stderr
        }
    }

    fn entry(&self) -> PathBuf {
        self.dir
            .join(".local/share/applications")
            .join(format!("{}.desktop", self.scheme))
    }

    fn list(&self) -> PathBuf {
        self.dir.join(".config/mimeapps.list")
    }

    fn gio_default(&self, gio: &Path) -> Option<String> {
        let mut command = Command::new(gio);
        self.env(&mut command);
        command
            .env("XDG_CONFIG_DIRS", isolated::isolated_root())
            .env("XDG_DATA_DIRS", isolated::isolated_root())
            .env_remove("XDG_CURRENT_DESKTOP")
            .env("LC_ALL", "C")
            .args(["mime", &format!("x-scheme-handler/{}", self.scheme)]);
        let output = command.output().unwrap();
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .find(|line| line.starts_with("Default application for"))
            .and_then(|line| line.rsplit_once(": "))
            .map(|(_, id)| id.to_owned())
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn gio() -> Option<&'static Path> {
    ["/usr/bin/gio", "/bin/gio"]
        .into_iter()
        .map(Path::new)
        .find(|path| path.is_file())
}

fn stdout(output: &Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone()).unwrap()
}

#[test]
fn registering_a_test_scheme_writes_a_handler_that_unregistering_removes() {
    let home = Home::new();
    let registered = home.gateinto(&["uri", "register"]);
    assert!(
        stdout(&registered).starts_with(&format!(
            "registered {}:// for the current user: \"",
            home.scheme
        )),
        "{registered:?}"
    );
    assert_eq!(home.stderr(&registered), "", "{registered:?}");
    let entry = std::fs::read_to_string(home.entry()).unwrap();
    assert!(
        entry.contains(&format!("MimeType=x-scheme-handler/{};\n", home.scheme)),
        "{entry}"
    );
    assert_eq!(
        std::fs::read_to_string(home.list()).unwrap(),
        format!(
            "[Default Applications]\nx-scheme-handler/{0}={0}.desktop\n",
            home.scheme
        )
    );
    if let Some(gio) = gio() {
        assert_eq!(
            home.gio_default(gio),
            Some(format!("{}.desktop", home.scheme))
        );
    }

    assert_eq!(
        stdout(&home.gateinto(&["uri", "unregister"])),
        format!(
            "removed the {}:// handler of the current user\n",
            home.scheme
        )
    );
    assert!(!home.entry().exists());
    assert_eq!(
        std::fs::read_to_string(home.list()).unwrap(),
        "[Default Applications]\n"
    );
    if let Some(gio) = gio() {
        assert_eq!(home.gio_default(gio), None);
    }
    assert_eq!(
        stdout(&home.gateinto(&["uri", "unregister"])),
        format!(
            "no {}:// handler is registered for the current user\n",
            home.scheme
        )
    );
}

#[test]
fn status_reports_the_registered_handler_and_a_default_that_overrides_it() {
    let home = Home::new();
    let mut command = isolated::gateinto();
    home.env(&mut command);
    let registered = command.args(["uri", "register"]).output().unwrap();
    let handler = format!("\"{}\" open -- %u", env!("CARGO_BIN_EXE_gateinto"));
    assert_eq!(
        stdout(&registered),
        format!("registered gateinto:// for the current user: {handler}\n")
    );
    assert_eq!(home.stderr(&registered), "");

    let status = home.status(None);
    assert!(
        status.contains(&format!(
            "\nuri-handler: gateinto: {handler}\nterminal-sessions: "
        )),
        "{status}"
    );
    assert!(!status.contains("warning"), "{status}");

    let kde = home.dir.join(".config/kde-mimeapps.list");
    std::fs::write(
        &kde,
        "[Default Applications]\nx-scheme-handler/gateinto=other.desktop\n",
    )
    .unwrap();
    std::fs::write(
        home.dir.join(".local/share/applications/other.desktop"),
        "[Desktop Entry]\nExec=other %u\n",
    )
    .unwrap();
    let status = home.status(None);
    assert!(
        status.contains(&format!(
            "\nuri-handler: gateinto: {handler}\nterminal-sessions: "
        )),
        "{status}"
    );
    let status = home.status(Some("KDE"));
    assert!(
        status.contains(&format!(
            "\nuri-handler: another program: other %u\n\
             uri-handler-warning: {} sets \"other.desktop\" as the default for \
             x-scheme-handler/gateinto, so gateinto:// links may open that application instead \
             of Gateinto\n\
             terminal-sessions: ",
            kde.display()
        )),
        "{status}"
    );
}

#[test]
fn setup_and_registering_refuse_the_directories_of_another_user() {
    let home = Home::new();
    let foreign = if std::fs::metadata(&home.dir).unwrap().uid() == 0 {
        let foreign = home.dir.join("foreign");
        std::fs::create_dir(&foreign).unwrap();
        std::os::unix::fs::chown(&foreign, Some(65534), Some(65534)).unwrap();
        foreign
    } else {
        PathBuf::from("/")
    };
    for args in [&["uri", "register"][..], &["setup"]] {
        let output = isolated::gateinto()
            .env("HOME", &foreign)
            .env("XDG_CONFIG_HOME", foreign.join(".config"))
            .env("XDG_DATA_HOME", foreign.join(".local/share"))
            .args(args)
            .arg("--config")
            .arg(home.dir.join("missing.toml"))
            .output()
            .unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(!output.status.success(), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        assert!(
            stderr.contains(&format!(
                "directory {} is owned by uid {}, not by the current user; Gateinto registers \
                 its gateinto:// handler only for the user who owns the per-user directories, \
                 so run it as that user, not through sudo or su",
                foreign.display(),
                std::fs::metadata(&foreign).unwrap().uid()
            )),
            "{args:?}: {stderr}"
        );
    }
    let key_init = isolated::gateinto()
        .env("HOME", &foreign)
        .env("XDG_CONFIG_HOME", foreign.join(".config"))
        .env("XDG_DATA_HOME", foreign.join(".local/share"))
        .args(["key", "init"])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8(key_init.stderr).unwrap(),
        "error: device keys are only supported on Windows\n"
    );
    assert!(!foreign.join(".config").exists());
    assert!(!foreign.join(".local").exists());
}

#[test]
fn only_test_schemes_can_be_chosen() {
    let home = Home::new();
    for scheme in ["https", "gateinto-test-UPPER", "gateinto-test-"] {
        let output = isolated::gateinto()
            .args(["uri", "unregister", "--scheme", scheme])
            .env("HOME", &home.dir)
            .output()
            .unwrap();
        assert!(!output.status.success(), "{scheme}");
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("expected gateinto or gateinto-test-<name>"),
            "{scheme}: {output:?}"
        );
    }
}
