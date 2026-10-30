use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

use crate::i18n::{Note, Text};

pub const CLI: &str = "gateinto.exe";
pub const WAIT: Duration = Duration::from_secs(45);
pub const FAILED: Text = Text::AgentStartFailed;
pub const MISSING: Text = Text::AgentCommandMissing;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Starting {
    #[default]
    Idle,
    InFlight,
    Failed(Note),
}

pub fn beside(gui: &Path) -> Option<PathBuf> {
    gui.parent()
        .map(|dir| dir.join(CLI))
        .filter(|cli| cli.is_file())
}

pub fn command(cli: &Path) -> Command {
    let mut command = Command::new(cli);
    command
        .args(["agent", "--detach"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(windows)]
    command.creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW);
    command
}

pub fn spawn(cli: &Path) -> io::Result<impl Future<Output = io::Result<bool>> + use<>> {
    let mut child = command(cli).spawn()?;
    Ok(async move { child.wait().await.map(|status| status.success()) })
}

pub async fn start<W>(
    cli: Option<PathBuf>,
    spawn: impl FnOnce(&Path) -> io::Result<W>,
) -> Option<Note>
where
    W: Future<Output = io::Result<bool>>,
{
    let Some(cli) = cli else {
        return Some(MISSING.into());
    };
    let Ok(exited) = spawn(&cli) else {
        return Some(FAILED.into());
    };
    match tokio::time::timeout(WAIT, exited).await {
        Ok(Ok(true)) => None,
        _ => Some(FAILED.into()),
    }
}

pub async fn agent() -> Option<Note> {
    let cli = std::env::current_exe().ok().and_then(|gui| beside(&gui));
    start(cli, spawn).await
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::future::{Future, pending, ready};
    use std::io;
    use std::path::{Path, PathBuf};

    use tokio::time::Instant;

    use super::*;

    fn scratch(test: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("gateinto-gui-start-{}-{test}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn only_a_file_beside_the_gui_is_the_command() {
        let dir = scratch("beside");
        std::fs::write(dir.join(CLI), "").unwrap();
        std::fs::create_dir_all(dir.join("folder").join(CLI)).unwrap();
        let gui = |sub: &str| dir.join(sub).join("gateinto-gui.exe");
        assert_eq!(beside(&dir.join("gateinto-gui.exe")), Some(dir.join(CLI)));
        assert_eq!(beside(&gui("folder")), None);
        assert_eq!(beside(&gui("missing")), None);
        std::fs::remove_dir_all(dir).unwrap();
    }

    use std::collections::BTreeSet;

    use crate::uninstall::wxs::{WXS, attribute, ids};

    const GUI_FILE: &str = r#"<File Id="GateintoGuiExe" Name="gateinto-gui.exe""#;
    const SHORTCUT: &str = r#"<Shortcut Id="GuiShortcut" Name="Gateinto" "#;

    fn component_of(element: &str) -> &'static str {
        let at = WXS.find(element).unwrap();
        let start = WXS[..at].rfind("<Component ").unwrap();
        let end = start + WXS[start..].find('>').unwrap();
        &WXS[start..end]
    }

    #[test]
    fn the_installer_puts_the_gui_beside_the_command() {
        let folder = r#"Directory="INSTALLFOLDER""#;
        assert!(component_of(&format!(r#"Name="{CLI}""#)).contains(folder));
        assert!(component_of(GUI_FILE).contains(folder));
    }

    #[test]
    fn the_installer_adds_a_start_menu_shortcut_and_runs_the_gui_only_to_quit_or_uninstall_it() {
        let file = &WXS[WXS.find(GUI_FILE).unwrap()..];
        let file = &file[..file.find("</File>").unwrap()];
        let shortcut = &file[file.find(SHORTCUT).unwrap()..];
        let shortcut = &shortcut[..shortcut.find("/>").unwrap()];
        assert!(shortcut.contains(r#"Directory="ProgramMenuFolder""#));
        assert!(shortcut.contains(r#"Advertise="no""#));
        assert_eq!(WXS.matches("<Shortcut ").count(), 1);
        let refs = |file: &'static str| {
            ids("CustomAction", "Id", move |a| {
                attribute(a, "FileRef") == Some(file)
            })
        };
        let gui = refs("GateintoGuiExe");
        assert_eq!(gui, BTreeSet::from(["UninstallGui", "QuitGui"]));
        assert_eq!(refs("GateintoExe"), BTreeSet::from(["StopAgent"]));
        assert_eq!(WXS.matches("GateintoGuiExe").count(), 1 + gui.len());
        assert!(!WXS.contains("InstallUISequence"));
        assert!(!WXS.contains("ExitDialog"));
        assert!(!WXS.contains("LaunchApplication"));
    }

    #[test]
    fn the_command_detaches_an_agent_by_absolute_path_without_a_config() {
        let cli = std::env::temp_dir().join(CLI);
        let command = command(&cli);
        let command = command.as_std();
        assert_eq!(command.get_program(), cli.as_os_str());
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(args, ["agent", "--detach"]);
        assert_eq!(command.get_current_dir(), None);
    }

    #[test]
    fn the_wait_is_longer_than_the_cli_s_30_second_start_timeout() {
        assert!(WAIT > std::time::Duration::from_secs(30));
    }

    fn exits(code: io::Result<bool>) -> impl Future<Output = io::Result<bool>> {
        ready(code)
    }

    #[tokio::test(start_paused = true)]
    async fn a_missing_command_is_never_spawned() {
        let spawned = Cell::new(false);
        let note = start(None, |_: &Path| {
            spawned.set(true);
            Ok(exits(Ok(true)))
        })
        .await;
        assert_eq!(note, Some(MISSING.into()));
        assert!(!spawned.get());
    }

    #[tokio::test(start_paused = true)]
    async fn a_clean_exit_starts_the_agent_without_a_note() {
        let cli = PathBuf::from("dir").join(CLI);
        let asked = Cell::new(None);
        let note = start(Some(cli.clone()), |path: &Path| {
            asked.set(Some(path.to_owned()));
            Ok(exits(Ok(true)))
        })
        .await;
        assert_eq!(note, None);
        assert_eq!(asked.take(), Some(cli));
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_exit_spawn_or_wait_shows_the_fixed_note() {
        let cli = || Some(PathBuf::from(CLI));
        let failed = Some(FAILED.into());
        assert_eq!(start(cli(), |_: &Path| Ok(exits(Ok(false)))).await, failed);
        let broken = || Err(io::Error::other("wait failed"));
        assert_eq!(start(cli(), |_: &Path| Ok(exits(broken()))).await, failed);
        let refused = |_: &Path| -> io::Result<std::future::Ready<io::Result<bool>>> {
            Err(io::Error::other("spawn failed"))
        };
        assert_eq!(start(cli(), refused).await, failed);
    }

    struct Child<'a>(&'a Cell<bool>);

    impl Drop for Child<'_> {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_command_that_outlasts_the_wait_is_killed_and_fails() {
        let killed = Cell::new(false);
        let begun = Instant::now();
        let note = start(Some(PathBuf::from(CLI)), |_: &Path| {
            let child = Child(&killed);
            Ok(async move {
                let _child = child;
                pending::<io::Result<bool>>().await
            })
        })
        .await;
        assert_eq!(note, Some(FAILED.into()));
        assert!(killed.get());
        assert_eq!(begun.elapsed(), WAIT);
    }

    #[test]
    fn the_notes_read_in_chinese() {
        let _zh = crate::i18n::speaking(crate::i18n::Language::Chinese);
        assert_eq!(
            crate::i18n::tr(FAILED),
            "無法啟動代理程式。請執行 `gateinto agent` 查看原因。"
        );
        assert_eq!(
            crate::i18n::tr(MISSING),
            "在 Gateinto 旁找不到 gateinto.exe。"
        );
    }
}
