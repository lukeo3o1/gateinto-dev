use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;

use crate::settings::{self, RegValue};

pub const UNINSTALL: &str = "--uninstall";
pub const QUIT: &str = "--quit";
pub const GUI: &str = "gateinto-gui.exe";
pub const WAIT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Show,
    Quit,
    Uninstall,
    Ignored,
}

pub fn requested<I: IntoIterator<Item = S>, S: AsRef<OsStr>>(args: I) -> Mode {
    let args: Vec<S> = args.into_iter().skip(1).collect();
    let flag = |arg: &S| [UNINSTALL, QUIT].map(OsStr::new).contains(&arg.as_ref());
    match &args[..] {
        [only] if only.as_ref() == UNINSTALL => Mode::Uninstall,
        [only] if only.as_ref() == QUIT => Mode::Quit,
        _ if args.iter().any(flag) => Mode::Ignored,
        _ => Mode::Show,
    }
}

pub fn removes(run: &Result<RegValue, ()>, exe: &Path) -> bool {
    let named = exe
        .to_str()
        .and_then(|exe| exe.rsplit(['\\', '/']).next())
        .is_some_and(|name| name.eq_ignore_ascii_case(GUI));
    named && matches!(run, Ok(RegValue::Text(value)) if settings::launches(value, exe))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    use super::*;

    const EXE: &str = r"C:\Users\me\AppData\Local\Programs\Gateinto\gateinto-gui.exe";

    #[test]
    fn only_an_exact_flag_alone_quits_or_uninstalls() {
        assert_eq!(requested([GUI]), Mode::Show);
        assert_eq!(requested([GUI, "--demo"]), Mode::Show);
        assert_eq!(requested([GUI, UNINSTALL]), Mode::Uninstall);
        assert_eq!(requested([GUI, QUIT]), Mode::Quit);
        assert_eq!(requested([UNINSTALL]), Mode::Show);
        assert_eq!(requested([GUI, "--UNINSTALL"]), Mode::Show);
        assert_eq!(requested([GUI, "--uninstall=1"]), Mode::Show);
    }

    #[test]
    fn a_flag_with_anything_else_does_nothing_and_never_shows_the_window() {
        for args in [
            &[GUI, UNINSTALL, "--demo"][..],
            &[GUI, "--demo", QUIT],
            &[GUI, UNINSTALL, QUIT],
            &[GUI, UNINSTALL, UNINSTALL],
            &[GUI, "--open", "gateinto://x", QUIT],
        ] {
            assert_eq!(requested(args), Mode::Ignored, "{args:?}");
        }
    }

    fn text(value: &str) -> Result<RegValue, ()> {
        Ok(RegValue::Text(value.to_owned()))
    }

    #[test]
    fn the_value_the_sign_in_switch_writes_is_removed() {
        let exe = PathBuf::from(EXE);
        let written = crate::settings::command(&exe).unwrap();
        assert!(removes(&text(&written), &exe));
        assert!(removes(
            &text(r#""c:\users\ME\appdata\local\programs\gateinto\GATEINTO-GUI.EXE""#),
            &exe
        ));
        assert!(removes(
            &text(r#"  "C:/Users/me/AppData/Local/Programs/Gateinto/gateinto-gui.exe"  "#),
            &exe
        ));
    }

    #[test]
    fn a_value_for_another_program_or_copy_is_kept() {
        let exe = PathBuf::from(EXE);
        for value in [
            r#""C:\Other\gateinto-gui.exe""#,
            r#""C:\Users\me\AppData\Local\Programs\Gateinto\gateinto.exe" agent --detach"#,
            r#""C:\Users\me\AppData\Local\Programs\Gateinto\gateinto-gui.exe" --demo"#,
            r#""C:\Users\me\AppData\Local\Programs\Gateinto\gateinto-gui.exe"#,
            "",
            "notepad.exe",
        ] {
            assert!(!removes(&text(value), &exe), "{value}");
        }
    }

    #[test]
    fn an_absent_unreadable_or_non_string_value_is_kept() {
        let exe = PathBuf::from(EXE);
        assert!(!removes(&Ok(RegValue::Absent), &exe));
        assert!(!removes(&Err(()), &exe));
        assert!(!removes(&Ok(RegValue::Other), &exe));
        let bytes = EXE.encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert!(!removes(&Ok(RegValue::Binary(bytes)), &exe));
    }

    #[test]
    fn only_a_running_gui_named_as_installed_removes_its_value() {
        let exe = PathBuf::from(r"C:\Users\me\AppData\Local\Programs\Gateinto\renamed.exe");
        let written = crate::settings::command(&exe).unwrap();
        assert!(!removes(&text(&written), &exe));
    }

    use super::wxs::{action, attribute, elements, ids, scheduled};

    const REMOVING: &str = "REMOVE~=&quot;ALL&quot;";

    #[test]
    fn the_installer_runs_the_gui_only_to_quit_or_uninstall_it_on_removal() {
        assert_eq!(
            ids("CustomAction", "Id", |a| attribute(a, "FileRef")
                == Some("GateintoGuiExe")),
            set(&["UninstallGui", "QuitGui"])
        );
        for (id, argument) in [("UninstallGui", UNINSTALL), ("QuitGui", QUIT)] {
            let action = action(id);
            assert_eq!(attribute(action, "ExeCommand"), Some(argument));
            assert_eq!(attribute(action, "Execute"), Some("deferred"));
            assert_eq!(attribute(action, "Impersonate"), Some("yes"));
            assert_eq!(attribute(action, "Return"), Some("ignore"));
            let custom = scheduled(id);
            assert_eq!(attribute(custom, "Before"), Some("RemoveFiles"));
            assert!(
                attribute(custom, "Condition")
                    .unwrap()
                    .starts_with(REMOVING)
            );
        }
    }

    #[test]
    fn the_sign_in_value_is_removed_on_a_full_uninstall_but_kept_on_an_upgrade() {
        assert_eq!(
            attribute(scheduled("UninstallGui"), "Condition"),
            Some("REMOVE~=&quot;ALL&quot; AND NOT UPGRADINGPRODUCTCODE")
        );
        assert_eq!(
            attribute(scheduled("QuitGui"), "Condition"),
            Some("REMOVE~=&quot;ALL&quot; AND UPGRADINGPRODUCTCODE")
        );
    }

    fn set(ids: &[&'static str]) -> BTreeSet<&'static str> {
        ids.iter().copied().collect()
    }

    #[test]
    fn every_scheduled_action_runs_only_on_removal() {
        let actions = set(&["StopAgent", "UninstallGui", "QuitGui"]);
        assert_eq!(ids("CustomAction", "Id", |_| true), actions);
        assert_eq!(ids("Custom", "Action", |_| true), actions);
        for custom in elements("Custom") {
            assert!(
                attribute(custom, "Condition")
                    .unwrap()
                    .starts_with(REMOVING),
                "{custom}"
            );
        }
        assert_eq!(
            attribute(action("StopAgent"), "FileRef"),
            Some("GateintoExe")
        );
    }
}

#[cfg(test)]
pub mod wxs {
    use std::collections::BTreeSet;

    pub const WXS: &str = include_str!("../../packaging/wix/gateinto.wxs");

    pub fn elements(tag: &str) -> Vec<&'static str> {
        let open = format!("<{tag}\n");
        let inline = format!("<{tag} ");
        let mut found = Vec::new();
        let mut rest = WXS;
        while let Some(at) = [rest.find(&open), rest.find(&inline)]
            .into_iter()
            .flatten()
            .min()
        {
            let element = &rest[at..];
            let end = element.find("/>").unwrap();
            found.push(&element[..end]);
            rest = &element[end..];
        }
        found
    }

    pub fn attribute(element: &'static str, name: &str) -> Option<&'static str> {
        let at = element
            .split_whitespace()
            .find_map(|word| word.strip_prefix(name)?.strip_prefix("=\""))?;
        let value = &element[at.as_ptr() as usize - element.as_ptr() as usize..];
        Some(&value[..value.find('"').unwrap()])
    }

    pub fn ids(tag: &str, id: &str, keep: impl Fn(&'static str) -> bool) -> BTreeSet<&'static str> {
        elements(tag)
            .into_iter()
            .filter(|&element| keep(element))
            .filter_map(|element| attribute(element, id))
            .collect()
    }

    pub fn action(id: &str) -> &'static str {
        let found: Vec<_> = elements("CustomAction")
            .into_iter()
            .filter(|a| attribute(a, "Id") == Some(id))
            .collect();
        assert_eq!(found.len(), 1, "{id}");
        found[0]
    }

    pub fn scheduled(id: &str) -> &'static str {
        let found: Vec<_> = elements("Custom")
            .into_iter()
            .filter(|c| attribute(c, "Action") == Some(id))
            .collect();
        assert_eq!(found.len(), 1, "{id}");
        found[0]
    }
}
