#![cfg(target_os = "linux")]

mod isolated;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

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
    assert!(registered.stderr.is_empty(), "{registered:?}");
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
