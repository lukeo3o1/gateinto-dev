use std::num::{NonZeroU32, NonZeroU64};
use std::path::{Path, PathBuf};

use gateinto::browser::browser_name;
use gateinto::config::{ConfigFile, LimitSettings};

use crate::i18n::{Choice as Language, Text, fill, tr};
use crate::sessions::browser_title;
use crate::theme::Choice;

pub const NOT_FOUND: Text = Text::NotFound;
pub const NO_PATH: Text = Text::NoConfigPath;
pub const OPEN: Text = Text::OpenConfig;
pub const OPEN_FAILED: Text = Text::OpenConfigFailed;
pub const APP: Text = Text::App;
pub const THEME: Text = Text::Theme;
pub const THEME_FAILED: Text = Text::ThemeFailed;
pub const LANGUAGE: Text = Text::LanguageRow;
pub const LANGUAGE_FAILED: Text = Text::LanguageFailed;
pub const SIGN_IN: Text = Text::SignIn;
pub const SIGN_IN_NOTE: Text = Text::SignInNote;
pub const SIGN_IN_UNREAD: Text = Text::SignInUnread;
pub const SIGN_IN_FAILED: Text = Text::SignInFailed;
pub const RUN_VALUE: &str = "Gateinto App";
pub const AGENT: Text = Text::Agent;
pub const FROM_CONFIG: Text = Text::FromConfig;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page {
    pub line: String,
    pub failed: bool,
    pub agent: Result<Vec<(&'static str, String)>, String>,
    pub sign_in: bool,
    pub theme: Choice,
    pub language: Language,
}

pub fn page(
    path: &str,
    agent: &Result<Agent, String>,
    failure: Option<&str>,
    sign_in: bool,
    theme: Choice,
    language: Language,
) -> Page {
    Page {
        line: failure.unwrap_or(path).to_owned(),
        failed: failure.is_some(),
        agent: match agent {
            Ok(agent) => Ok(rows(agent)),
            Err(error) => Err(error.lines().next().unwrap_or_default().to_owned()),
        },
        sign_in,
        theme,
        language,
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Browser {
    Configured(PathBuf),
    Detected(PathBuf),
    #[default]
    Missing,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Agent {
    pub browser: Browser,
    pub limits: LimitSettings,
}

pub fn agent(file: &ConfigFile, detect: impl FnOnce() -> Option<PathBuf>) -> Agent {
    let browser = match &file.browser.executable {
        Some(path) => Browser::Configured(path.clone()),
        None => detect().map_or(Browser::Missing, Browser::Detected),
    };
    let (set, defaults) = (&file.limits, LimitSettings::default());
    Agent {
        browser,
        limits: LimitSettings {
            max_concurrent_tunnels: set
                .max_concurrent_tunnels
                .map_or(defaults.max_concurrent_tunnels, NonZeroU32::get),
            connect_timeout_seconds: set
                .connect_timeout_seconds
                .map_or(defaults.connect_timeout_seconds, NonZeroU64::get),
            idle_timeout_seconds: set
                .idle_timeout_seconds
                .map_or(defaults.idle_timeout_seconds, NonZeroU64::get),
            header_max_bytes: set
                .header_max_bytes
                .map_or(defaults.header_max_bytes, NonZeroU32::get),
        },
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .unwrap_or(path.as_os_str())
        .to_string_lossy()
        .into_owned()
}

fn browser(browser: &Browser) -> String {
    match browser {
        Browser::Configured(path) => file_name(path),
        Browser::Detected(path) => {
            let name = match browser_name(path) {
                Some(kind) => browser_title(Some(kind)).to_owned(),
                None => file_name(path),
            };
            fill(Text::Detected, &[&name])
        }
        Browser::Missing => tr(NOT_FOUND).to_owned(),
    }
}

fn bytes(n: u32) -> String {
    if n.is_multiple_of(1024) {
        fill(Text::Kilobytes, &[&(n / 1024)])
    } else {
        fill(Text::Bytes, &[&n])
    }
}

fn seconds(n: u64) -> String {
    fill(Text::Seconds, &[&n])
}

pub fn rows(agent: &Agent) -> Vec<(&'static str, String)> {
    let limits = &agent.limits;
    vec![
        (tr(Text::Browser), browser(&agent.browser)),
        (
            tr(Text::ConcurrentTunnels),
            limits.max_concurrent_tunnels.to_string(),
        ),
        (
            tr(Text::ConnectTimeout),
            seconds(limits.connect_timeout_seconds),
        ),
        (tr(Text::IdleTimeout), seconds(limits.idle_timeout_seconds)),
        (tr(Text::HeaderLimit), bytes(limits.header_max_bytes)),
    ]
}

pub fn shown(path: Option<&Path>, appdata: Option<&Path>) -> String {
    let Some(path) = path else {
        return tr(NO_PATH).to_owned();
    };
    match appdata.and_then(|dir| path.strip_prefix(dir).ok()) {
        Some(rest) => Path::new("%APPDATA%").join(rest).display().to_string(),
        None => path.display().to_string(),
    }
}

pub fn config_line(
    demo: bool,
    path: impl FnOnce() -> Option<PathBuf>,
    appdata: impl FnOnce() -> Option<PathBuf>,
) -> String {
    if demo {
        return crate::demo::CONFIG_PATH.to_owned();
    }
    shown(path().as_deref(), appdata().as_deref())
}

pub fn command(exe: &Path) -> Option<String> {
    let exe = exe.to_str()?;
    (!exe.contains('"')).then(|| format!("\"{exe}\""))
}

fn comparable(path: &str) -> String {
    path.replace('/', "\\").to_lowercase()
}

pub fn launches(value: &str, exe: &Path) -> bool {
    let value = value.trim();
    let program = match value.strip_prefix('"') {
        Some(quoted) => match quoted.split_once('"') {
            Some((program, "")) => program,
            _ => return false,
        },
        None => value,
    };
    let Some(exe) = exe.to_str() else {
        return false;
    };
    !program.is_empty() && comparable(program) == comparable(exe)
}

#[cfg(test)]
mod tests {
    use std::path::MAIN_SEPARATOR_STR;

    use super::*;
    use crate::i18n::Choice as Language;

    #[test]
    fn the_sign_in_value_is_not_the_installer_agent_value() {
        let wxs = include_str!("../../packaging/wix/gateinto.wxs");
        let run = r#"Key="Software\Microsoft\Windows\CurrentVersion\Run" Name="Gateinto""#;
        assert!(wxs.contains(run));
        assert_eq!(RUN_VALUE, "Gateinto App");
        assert!(!wxs.contains(&format!(r#"Name="{RUN_VALUE}""#)));
    }

    fn parsed(text: &str) -> ConfigFile {
        ConfigFile::parse(text).unwrap()
    }

    fn none() -> Option<PathBuf> {
        None
    }

    #[test]
    fn the_page_shows_the_path_rows_and_sign_in_state() {
        let page = page(
            "%APPDATA%\\g.toml",
            &Ok(Agent::default()),
            None,
            true,
            Choice::Dark,
            Language::Chinese,
        );
        assert_eq!(
            page,
            Page {
                line: "%APPDATA%\\g.toml".to_owned(),
                failed: false,
                agent: Ok(rows(&Agent::default())),
                sign_in: true,
                theme: Choice::Dark,
                language: Language::Chinese,
            }
        );
    }

    #[test]
    fn a_failure_replaces_the_path_line_in_the_current_language() {
        let failed = || {
            page(
                "p",
                &Ok(Agent::default()),
                Some(crate::i18n::Note::from(OPEN_FAILED).shown()),
                false,
                Choice::System,
                Language::System,
            )
        };
        let page = failed();
        assert_eq!(
            (page.line.as_str(), page.failed),
            (OPEN_FAILED.english(), true)
        );
        let _zh = crate::i18n::speaking(crate::i18n::Language::Chinese);
        assert_eq!(failed().line, "無法開啟設定檔");
    }

    #[test]
    fn a_config_error_shows_its_first_line_instead_of_values() {
        let error = Err("config file c.toml: TOML parse error\n  |\n1 | x".to_owned());
        let page = page("p", &error, None, false, Choice::System, Language::System);
        assert_eq!(
            page.agent,
            Err("config file c.toml: TOML parse error".to_owned())
        );
    }

    #[test]
    fn an_empty_config_shows_the_agent_defaults() {
        let agent = agent(&ConfigFile::default(), none);
        assert_eq!(
            rows(&agent),
            [
                ("Browser", "Not found".to_owned()),
                ("Concurrent tunnels", "64".to_owned()),
                ("Connect timeout", "10 s".to_owned()),
                ("Idle timeout", "300 s".to_owned()),
                ("Request header limit", "16 KB".to_owned()),
            ]
        );
    }

    #[test]
    fn configured_limits_replace_the_defaults() {
        let file = parsed(
            "[limits]\nmax_concurrent_tunnels = 8\nconnect_timeout_seconds = 3\n\
             idle_timeout_seconds = 60\nheader_max_bytes = 32768\n",
        );
        let values: Vec<String> = rows(&agent(&file, none)).into_iter().map(|r| r.1).collect();
        assert_eq!(values[1..], ["8", "3 s", "60 s", "32 KB"]);
    }

    #[test]
    fn a_header_limit_off_a_kilobyte_is_shown_in_bytes() {
        let file = parsed("[limits]\nheader_max_bytes = 20000\n");
        assert_eq!(rows(&agent(&file, none))[4].1, "20000 bytes");
    }

    #[test]
    fn the_settings_rows_speak_chinese() {
        let _zh = crate::i18n::speaking(crate::i18n::Language::Chinese);
        let chrome = || Some(PathBuf::from("/opt/google/chrome.exe"));
        let file = parsed("[limits]\nheader_max_bytes = 20000\n");
        let mut agent = agent(&file, chrome);
        assert_eq!(
            rows(&agent),
            [
                ("瀏覽器", "Chrome（已偵測）".to_owned()),
                ("同時通道數", "64".to_owned()),
                ("連線逾時", "10 秒".to_owned()),
                ("閒置逾時", "300 秒".to_owned()),
                ("請求標頭上限", "20000 位元組".to_owned()),
            ]
        );
        agent.browser = Browser::Missing;
        agent.limits.header_max_bytes = 16384;
        let values: Vec<String> = rows(&agent).into_iter().map(|r| r.1).collect();
        assert_eq!(
            (values[0].as_str(), values[4].as_str()),
            ("找不到", "16 KB")
        );
        assert_eq!(shown(None, None), "沒有設定檔位置");
    }

    #[test]
    fn a_configured_browser_shows_its_file_name_without_detecting() {
        let file = parsed("[browser]\nexecutable = \"/opt/browsers/vivaldi.exe\"\n");
        let agent = agent(&file, || panic!("detected despite a configured browser"));
        assert_eq!(
            agent.browser,
            Browser::Configured(PathBuf::from("/opt/browsers/vivaldi.exe"))
        );
        assert_eq!(rows(&agent)[0], ("Browser", "vivaldi.exe".to_owned()));
    }

    #[test]
    fn a_detected_browser_is_named_and_marked_detected() {
        let chrome = || Some(PathBuf::from("/opt/google/chrome.exe"));
        assert_eq!(
            rows(&agent(&ConfigFile::default(), chrome))[0].1,
            "Chrome (detected)"
        );
        let edge = || Some(PathBuf::from("/opt/msedge.exe"));
        assert_eq!(
            rows(&agent(&ConfigFile::default(), edge))[0].1,
            "Edge (detected)"
        );
        let other = || Some(PathBuf::from("/opt/other-browser"));
        assert_eq!(
            rows(&agent(&ConfigFile::default(), other))[0].1,
            "other-browser (detected)"
        );
    }

    #[test]
    fn a_path_under_appdata_is_shown_with_the_variable() {
        let appdata = Path::new("/users/me/appdata");
        let path = appdata.join("Gateinto").join("gateinto.toml");
        let expected = ["%APPDATA%", "Gateinto", "gateinto.toml"].join(MAIN_SEPARATOR_STR);
        assert_eq!(shown(Some(&path), Some(appdata)), expected);
    }

    #[test]
    fn other_paths_are_shown_in_full() {
        let path = Path::new("/etc/gateinto/gateinto.toml");
        assert_eq!(
            shown(Some(path), Some(Path::new("/users/me/appdata"))),
            "/etc/gateinto/gateinto.toml"
        );
        assert_eq!(shown(Some(path), None), "/etc/gateinto/gateinto.toml");
        assert_eq!(shown(None, None), NO_PATH.english());
    }

    #[test]
    fn the_sign_in_command_is_the_quoted_executable() {
        let exe = Path::new(r"C:\Program Files\Gateinto\gateinto-gui.exe");
        assert_eq!(
            command(exe).as_deref(),
            Some(r#""C:\Program Files\Gateinto\gateinto-gui.exe""#)
        );
        assert_eq!(command(Path::new("C:\\odd\"name.exe")), None);
    }

    #[test]
    fn a_run_value_matches_only_this_executable() {
        let exe = Path::new(r"C:\Program Files\Gateinto\gateinto-gui.exe");
        for value in [
            r#""C:\Program Files\Gateinto\gateinto-gui.exe""#,
            r#"  "c:\program files\gateinto\GATEINTO-GUI.EXE"  "#,
            r#""C:/Program Files/Gateinto/gateinto-gui.exe""#,
            r"C:\Program Files\Gateinto\gateinto-gui.exe",
        ] {
            assert!(launches(value, exe), "{value}");
        }
        for value in [
            "",
            r#""C:\Other\gateinto-gui.exe""#,
            r#""C:\Program Files\Gateinto\gateinto-gui.exe" --tray"#,
            r#""C:\Program Files\Gateinto\gateinto-gui.exe"#,
            r"C:\Program Files\Gateinto\gateinto-gui.exe.bak",
        ] {
            assert!(!launches(value, exe), "{value}");
        }
    }
}
