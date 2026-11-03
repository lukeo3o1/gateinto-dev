use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader};
use tokio::process::Command;

pub const GUI: &str = "gateinto-gui.exe";
pub const FLAG: &str = "--open";
pub const HANDED: &str = "handed";
pub const REFUSED: &str = "refused";
pub const PENDING: &str = "pending";
pub const PENDING_HELP: &str = "the link was sent to Gateinto but it did not answer in time; check the Gateinto window to confirm or cancel it";
pub const TIMEOUT: Duration = Duration::from_secs(15);

const LONGEST: u64 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handoff {
    Kept,
    Pending,
    Handed,
}

pub fn gui_beside(exe: &Path) -> Option<PathBuf> {
    exe.parent().map(|dir| dir.join(GUI))
}

pub fn installed(exe: &Path) -> Option<PathBuf> {
    gui_beside(exe).filter(|gui| gui.is_file())
}

pub async fn offer<E>(
    gui: Option<&Path>,
    ensure_agent: impl AsyncFnOnce() -> Result<(), E>,
    hand: impl AsyncFnOnce(&Path) -> Handoff,
) -> Result<Handoff, E> {
    let Some(gui) = gui else {
        return Ok(Handoff::Kept);
    };
    ensure_agent().await?;
    Ok(hand(gui).await)
}

pub async fn acknowledged(out: impl AsyncRead + Unpin, timeout: Duration) -> Handoff {
    let mut line = String::new();
    let mut out = BufReader::new(out.take(LONGEST));
    let read = tokio::time::timeout(timeout, out.read_line(&mut line)).await;
    if !matches!(read, Ok(Ok(_))) {
        return Handoff::Kept;
    }
    match line.trim_end_matches(['\r', '\n']) {
        HANDED => Handoff::Handed,
        PENDING => Handoff::Pending,
        _ => Handoff::Kept,
    }
}

pub async fn hand(gui: &Path, uri: &str, timeout: Duration) -> Handoff {
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
        return Handoff::Kept;
    };
    let handoff = match child.stdout.take() {
        Some(out) => acknowledged(out, timeout).await,
        None => Handoff::Kept,
    };
    if handoff == Handoff::Kept {
        let _ = child.start_kill();
    }
    handoff
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

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("gateinto-handoff-{}-{name}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn only_an_installed_gui_is_offered_the_link() {
        let scratch = Scratch::new("installed");
        let dir = &scratch.0;
        std::fs::create_dir_all(dir.join("empty")).unwrap();
        std::fs::write(dir.join(GUI), "").unwrap();
        std::fs::create_dir_all(dir.join("empty").join(GUI)).unwrap();

        assert_eq!(installed(&dir.join("gateinto.exe")), Some(dir.join(GUI)));
        assert_eq!(installed(&dir.join("empty").join("gateinto.exe")), None);
        assert_eq!(installed(&dir.join("missing").join("gateinto.exe")), None);
    }

    #[test]
    fn scratch_directories_are_removed() {
        let dir = Scratch::new("removed").0.clone();

        assert!(!dir.exists());
    }

    #[tokio::test]
    async fn without_a_gui_nothing_is_started_and_the_link_stays_here() {
        let handoff = offer(
            None,
            async || -> Result<(), &str> { panic!("the agent was started") },
            async |_: &Path| -> Handoff { panic!("a gui was started") },
        )
        .await;

        assert_eq!(handoff, Ok(Handoff::Kept));
    }

    #[tokio::test]
    async fn the_agent_runs_before_the_gui_is_offered_the_link() {
        let order = std::sync::Mutex::new(Vec::new());
        let handoff = offer(
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
                Handoff::Handed
            },
        )
        .await;

        assert_eq!(handoff, Ok(Handoff::Handed));
        assert_eq!(*order.lock().unwrap(), ["agent", "gui"]);
    }

    #[tokio::test]
    async fn the_gui_decides_where_the_link_goes() {
        for outcome in [Handoff::Kept, Handoff::Pending, Handoff::Handed] {
            let handoff = offer(
                Some(Path::new(GUI)),
                async || -> Result<(), &str> { Ok(()) },
                async |_: &Path| outcome,
            )
            .await;

            assert_eq!(handoff, Ok(outcome));
        }
    }

    #[tokio::test]
    async fn an_agent_that_cannot_start_is_reported_and_no_gui_is_started() {
        let handoff = offer(
            Some(Path::new(GUI)),
            async || Err("no agent"),
            async |_: &Path| -> Handoff { panic!("a gui was started") },
        )
        .await;

        assert_eq!(handoff, Err("no agent"));
    }

    #[tokio::test]
    async fn the_first_line_tells_where_the_link_went() {
        for (out, outcome) in [
            (&b"handed\n"[..], Handoff::Handed),
            (b"handed\r\nmore", Handoff::Handed),
            (b"handed", Handoff::Handed),
            (b"pending\n", Handoff::Pending),
            (b"pending\r\n", Handoff::Pending),
            (b"refused\n", Handoff::Kept),
            (b"handed later\n", Handoff::Kept),
            (b"pending later\n", Handoff::Kept),
            (b"\nhanded\n", Handoff::Kept),
            (b"", Handoff::Kept),
        ] {
            assert_eq!(
                acknowledged(out, TIMEOUT).await,
                outcome,
                "{}",
                String::from_utf8_lossy(out)
            );
        }
    }

    #[tokio::test]
    async fn an_endless_line_keeps_the_link_here() {
        let endless = tokio::io::repeat(b'x');

        assert_eq!(acknowledged(endless, TIMEOUT).await, Handoff::Kept);
    }

    #[tokio::test(start_paused = true)]
    async fn silence_until_the_timeout_keeps_the_link_here() {
        let (_writer, silent) = tokio::io::duplex(64);

        assert_eq!(
            acknowledged(silent, Duration::from_secs(5)).await,
            Handoff::Kept
        );
    }

    #[test]
    fn a_pending_link_points_to_the_window() {
        assert!(PENDING_HELP.contains("Gateinto window"));
        assert!(!PENDING_HELP.contains("gateinto:"));
    }

    #[cfg(unix)]
    mod gui {
        use std::os::unix::fs::PermissionsExt;
        use std::time::Instant;

        use super::*;

        const URI: &str = "gateinto://connect?profile=work&auth=session-credentials;$(false)";
        const PROBE: &str = "--probe";

        fn fake(name: &str, body: &str) -> (Scratch, PathBuf) {
            let scratch = Scratch::new(name);
            let path = scratch.0.join(GUI);
            std::fs::write(
                &path,
                format!("#!/bin/sh\n[ \"$1\" = {PROBE} ] && exit 0\n{body}\n"),
            )
            .unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            settle(&path);
            (scratch, path)
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
            let (_scratch, gui) = fake(
                "handed",
                &format!(
                    r#"[ "$#" = 2 ] && [ "$1" = --open ] && [ "$2" = '{URI}' ] && echo handed"#
                ),
            );

            assert_eq!(hand(&gui, URI, TIMEOUT).await, Handoff::Handed);
        }

        #[tokio::test]
        async fn a_gui_whose_window_did_not_answer_leaves_the_link_pending() {
            let (_scratch, gui) = fake("pending", "echo pending");

            assert_eq!(hand(&gui, URI, TIMEOUT).await, Handoff::Pending);
        }

        #[tokio::test]
        async fn a_gui_that_refuses_or_exits_silently_does_not_have_it() {
            for (name, body) in [("refused", "echo refused"), ("silent", "exit 0")] {
                let (_scratch, gui) = fake(name, body);

                assert_eq!(hand(&gui, URI, TIMEOUT).await, Handoff::Kept, "{name}");
            }
        }

        #[tokio::test]
        async fn a_gui_that_does_not_answer_in_time_is_stopped() {
            let (_scratch, gui) = fake("hung", "exec sleep 30");
            let started = Instant::now();

            assert_eq!(
                hand(&gui, URI, Duration::from_millis(200)).await,
                Handoff::Kept
            );
            assert!(started.elapsed() < Duration::from_secs(10));
        }

        #[tokio::test]
        async fn a_missing_gui_does_not_have_it() {
            let gui = std::env::temp_dir()
                .join("gateinto-handoff-missing")
                .join(GUI);

            assert_eq!(hand(&gui, URI, TIMEOUT).await, Handoff::Kept);
        }
    }
}
