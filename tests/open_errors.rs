#![cfg(feature = "test-hooks")]

mod isolated;

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

struct Launch {
    dir: PathBuf,
    notification: PathBuf,
    instance: String,
}

impl Launch {
    fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let instance = format!(
            "open-error-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let dir = std::env::temp_dir().join(&instance);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self {
            notification: dir.join("notification.txt"),
            dir,
            instance,
        }
    }

    fn command(&self) -> Command {
        let mut command = isolated::gateinto();
        command
            .env("GATEINTO_TEST_OPEN_ERROR_FILE", &self.notification)
            .env("GATEINTO_INSTANCE", &self.instance)
            .env("XDG_RUNTIME_DIR", &self.dir);
        command
    }

    fn notification(&self) -> String {
        let text = std::fs::read_to_string(&self.notification)
            .expect("a failed URI launch must report its error to the notification sink");
        assert_eq!(
            text.matches("Gateinto could not open the link.").count(),
            1,
            "{text}"
        );
        text
    }
}

impl Drop for Launch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

#[test]
fn a_failed_open_keeps_stderr_and_reports_the_complete_error() {
    let launch = Launch::new();
    let output = launch
        .command()
        .args(["open", "--", "https://example.test/"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let error = stderr(&output);
    assert!(error.contains("invalid launch URI"), "{error}");
    let notification = launch.notification();
    assert!(notification.contains(error.trim()), "{notification}");
    assert!(
        notification.contains("could not open the link"),
        "{notification}"
    );
}

#[test]
fn open_argument_errors_are_visible_and_keep_claps_exit_status() {
    for args in [
        vec!["open"],
        vec!["open", "--config"],
        vec!["open", "--not-an-option"],
    ] {
        let launch = Launch::new();
        let output = launch.command().args(args).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        let error = stderr(&output);
        assert!(error.contains("error:"), "{error}");
        assert!(launch.notification().contains(error.trim()));
    }
}

#[test]
fn help_version_and_other_commands_do_not_notify() {
    for args in [
        vec!["--help"],
        vec!["--version"],
        vec!["open", "--help"],
        vec!["proxy"],
        vec!["agent", "--not-an-option"],
    ] {
        let launch = Launch::new();
        let output = launch.command().args(&args).output().unwrap();
        if args.contains(&"--help") || args.contains(&"--version") {
            assert!(output.status.success());
            assert!(!output.stdout.is_empty());
            assert!(output.stderr.is_empty());
        } else {
            assert!(!output.status.success());
        }
        assert!(!launch.notification.exists(), "{args:?}");
    }
}

#[test]
fn agent_start_failure_notification_names_the_configuration_to_diagnose() {
    let launch = Launch::new();
    let config = launch.dir.join("broken config.toml");
    std::fs::write(&config, "this is not TOML").unwrap();
    let output = launch
        .command()
        .arg("open")
        .arg("--config")
        .arg(&config)
        .args(["--", "gateinto://connect?profile=main&auth=basic_tofu"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let error = stderr(&output);
    assert!(error.contains("the agent exited"), "{error}");
    let notification = launch.notification();
    assert!(notification.contains(error.trim()), "{notification}");
    assert!(notification.contains("gateinto agent"), "{notification}");
    assert!(notification.contains("--config"), "{notification}");
    assert!(
        notification.contains(&config.display().to_string()),
        "{notification}"
    );
}

#[cfg(unix)]
#[test]
fn open_errors_still_notify_when_stderr_is_closed() {
    for args in [vec!["open"], vec!["open", "--", "https://example.test/"]] {
        let launch = Launch::new();
        let original = launch.command();
        let mut command = Command::new("sh");
        command
            .args(["-c", "exec 2>&-; exec \"$@\"", "gateinto-closed-stderr"])
            .arg(original.get_program())
            .args(&args);
        for (name, value) in original.get_envs() {
            if let Some(value) = value {
                command.env(name, value);
            }
        }
        let output = command.output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(if args.len() == 1 { 2 } else { 1 })
        );
        assert!(output.stderr.is_empty());
        assert!(launch.notification().contains("error:"));
    }
}
