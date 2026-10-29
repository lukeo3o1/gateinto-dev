use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader};
use tokio::process::Command;

pub const GUI: &str = "gateinto-gui.exe";
pub const FLAG: &str = "--open";
pub const HANDED: &str = "handed";
pub const REFUSED: &str = "refused";
pub const TIMEOUT: Duration = Duration::from_secs(15);

const LONGEST: u64 = 64;

pub fn gui_beside(exe: &Path) -> Option<PathBuf> {
    exe.parent().map(|dir| dir.join(GUI))
}

pub fn installed(exe: &Path) -> Option<PathBuf> {
    gui_beside(exe).filter(|gui| gui.is_file())
}

pub async fn offer<E>(
    gui: Option<&Path>,
    ensure_agent: impl AsyncFnOnce() -> Result<(), E>,
    hand: impl AsyncFnOnce(&Path) -> bool,
) -> Result<bool, E> {
    let Some(gui) = gui else {
        return Ok(false);
    };
    ensure_agent().await?;
    Ok(hand(gui).await)
}

pub async fn acknowledged(out: impl AsyncRead + Unpin, timeout: Duration) -> bool {
    let mut line = String::new();
    let mut out = BufReader::new(out.take(LONGEST));
    let read = tokio::time::timeout(timeout, out.read_line(&mut line)).await;
    matches!(read, Ok(Ok(_))) && line.trim_end_matches(['\r', '\n']) == HANDED
}

pub async fn hand(gui: &Path, uri: &str, timeout: Duration) -> bool {
    let mut command = Command::new(gui);
    command
        .arg(FLAG)
        .arg(uri)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    command.creation_flags(windows_sys::Win32::System::Threading::CREATE_NEW_PROCESS_GROUP);
    let Ok(mut child) = command.spawn() else {
        return false;
    };
    let handed = match child.stdout.take() {
        Some(out) => acknowledged(out, timeout).await,
        None => false,
    };
    if !handed {
        let _ = child.start_kill();
    }
    handed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_gui_is_looked_for_beside_the_command() {
        let exe = Path::new("dir").join("gateinto.exe");

        assert_eq!(
            gui_beside(&exe),
            Some(Path::new("dir").join("gateinto-gui.exe"))
        );
    }

    #[test]
    fn only_an_installed_gui_is_offered_the_link() {
        let dir = std::env::temp_dir().join(format!("gateinto-installed-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("empty")).unwrap();
        std::fs::write(dir.join(GUI), "").unwrap();
        std::fs::create_dir_all(dir.join("empty").join(GUI)).unwrap();

        assert_eq!(installed(&dir.join("gateinto.exe")), Some(dir.join(GUI)));
        assert_eq!(installed(&dir.join("empty").join("gateinto.exe")), None);
        assert_eq!(installed(&dir.join("missing").join("gateinto.exe")), None);
    }

    #[tokio::test]
    async fn without_a_gui_nothing_is_started_and_the_link_stays_here() {
        let handed = offer(
            None,
            async || -> Result<(), &str> { panic!("the agent was started") },
            async |_: &Path| -> bool { panic!("a gui was started") },
        )
        .await;

        assert_eq!(handed, Ok(false));
    }

    #[tokio::test]
    async fn the_agent_runs_before_the_gui_is_offered_the_link() {
        let order = std::sync::Mutex::new(Vec::new());
        let handed = offer(
            Some(Path::new(GUI)),
            async || -> Result<(), &str> {
                order.lock().unwrap().push("agent");
                Ok(())
            },
            async |gui: &Path| {
                order
                    .lock()
                    .unwrap()
                    .push(if gui == Path::new(GUI) { "gui" } else { "?" });
                true
            },
        )
        .await;

        assert_eq!(handed, Ok(true));
        assert_eq!(*order.lock().unwrap(), ["agent", "gui"]);
    }

    #[tokio::test]
    async fn a_gui_that_does_not_take_the_link_leaves_it_here() {
        let handed = offer(
            Some(Path::new(GUI)),
            async || -> Result<(), &str> { Ok(()) },
            async |_: &Path| false,
        )
        .await;

        assert_eq!(handed, Ok(false));
    }

    #[tokio::test]
    async fn an_agent_that_cannot_start_is_reported_and_no_gui_is_started() {
        let handed = offer(
            Some(Path::new(GUI)),
            async || Err("no agent"),
            async |_: &Path| -> bool { panic!("a gui was started") },
        )
        .await;

        assert_eq!(handed, Err("no agent"));
    }

    #[tokio::test]
    async fn only_the_handed_line_acknowledges() {
        assert!(acknowledged(&b"handed\n"[..], TIMEOUT).await);
        assert!(acknowledged(&b"handed\r\nmore"[..], TIMEOUT).await);
        assert!(acknowledged(&b"handed"[..], TIMEOUT).await);
        assert!(!acknowledged(&b"refused\n"[..], TIMEOUT).await);
        assert!(!acknowledged(&b"handed later\n"[..], TIMEOUT).await);
        assert!(!acknowledged(&b""[..], TIMEOUT).await);
    }

    #[tokio::test]
    async fn an_endless_line_does_not_acknowledge() {
        let endless = tokio::io::repeat(b'x');

        assert!(!acknowledged(endless, TIMEOUT).await);
    }

    #[tokio::test(start_paused = true)]
    async fn silence_until_the_timeout_does_not_acknowledge() {
        let (_writer, silent) = tokio::io::duplex(64);

        assert!(!acknowledged(silent, Duration::from_secs(5)).await);
    }

    #[cfg(unix)]
    mod gui {
        use std::os::unix::fs::PermissionsExt;
        use std::time::Instant;

        use super::*;

        const URI: &str = "gateinto://connect?profile=work&auth=session-credentials;$(false)";
        const PROBE: &str = "--probe";

        fn fake(name: &str, body: &str) -> PathBuf {
            let dir = std::env::temp_dir()
                .join(format!("gateinto-handoff-{}-{name}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join(GUI);
            std::fs::write(
                &path,
                format!("#!/bin/sh\n[ \"$1\" = {PROBE} ] && exit 0\n{body}\n"),
            )
            .unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            settle(&path);
            path
        }

        // A process forked by a parallel test while the script was open for writing
        // briefly keeps it busy for execution.
        fn settle(path: &Path) {
            const BUSY: i32 = 26;
            for _ in 0..100 {
                match std::process::Command::new(path).arg(PROBE).status() {
                    Err(error) if error.raw_os_error() == Some(BUSY) => {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    _ => return,
                }
            }
        }

        #[tokio::test]
        async fn a_gui_that_takes_the_link_as_one_argument_and_acknowledges_has_it() {
            let gui = fake(
                "handed",
                &format!(
                    r#"[ "$#" = 2 ] && [ "$1" = --open ] && [ "$2" = '{URI}' ] && echo handed"#
                ),
            );

            assert!(hand(&gui, URI, TIMEOUT).await);
        }

        #[tokio::test]
        async fn a_gui_that_refuses_or_exits_silently_does_not_have_it() {
            for (name, body) in [("refused", "echo refused"), ("silent", "exit 0")] {
                let gui = fake(name, body);

                assert!(!hand(&gui, URI, TIMEOUT).await, "{name}");
            }
        }

        #[tokio::test]
        async fn a_gui_that_does_not_answer_in_time_is_stopped() {
            let gui = fake("hung", "exec sleep 30");
            let started = Instant::now();

            assert!(!hand(&gui, URI, Duration::from_millis(200)).await);
            assert!(started.elapsed() < Duration::from_secs(10));
        }

        #[tokio::test]
        async fn a_missing_gui_does_not_have_it() {
            let gui = std::env::temp_dir()
                .join("gateinto-handoff-missing")
                .join(GUI);

            assert!(!hand(&gui, URI, TIMEOUT).await);
        }
    }
}
