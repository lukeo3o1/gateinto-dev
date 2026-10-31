use std::num::{NonZeroU32, NonZeroU64};
use std::path::{Path, PathBuf};
use std::time::Instant;

use gateinto::browser::browser_name;
use gateinto::config::{ConfigFile, LimitSettings};
use gateinto::ipc::ConfigSource;

use crate::agent::Config;
use crate::i18n::{Choice as Language, Text, fill, tr};
use crate::sessions::browser_title;
use crate::theme::Choice;

pub const NOT_FOUND: Text = Text::NotFound;
pub const NO_PATH: Text = Text::NoConfigPath;
pub const AGENT_CONFIG: Text = Text::AgentConfig;
pub const NOT_CREATED: Text = Text::ConfigNotCreated;
pub const RESTART: Text = Text::ConfigRestart;
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
pub const AGENT_RUN_VALUE: &str = "Gateinto";
pub const AGENT_SIGN_IN: Text = Text::AgentSignIn;
pub const AGENT_SIGN_IN_NOTE: Text = Text::AgentSignInNote;
pub const AGENT: Text = Text::Agent;
pub const FROM_CONFIG: Text = Text::FromConfig;
pub const BUILT_IN: Text = Text::BuiltInDefaults;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page {
    pub line: String,
    pub failed: bool,
    pub agent: Result<Vec<(&'static str, String)>, String>,
    pub source: Text,
    pub sign_in: bool,
    pub agent_start: AgentStart,
    pub theme: Choice,
    pub language: Language,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigView {
    pub line: String,
    pub source: Text,
}

pub fn page(
    config: &ConfigView,
    agent: &Result<Agent, String>,
    failure: Option<&str>,
    sign_in: bool,
    agent_start: AgentStart,
    theme: Choice,
    language: Language,
) -> Page {
    Page {
        line: failure.unwrap_or(&config.line).to_owned(),
        failed: failure.is_some(),
        agent: match agent {
            Ok(agent) => Ok(rows(agent)),
            Err(error) => Err(error.lines().next().unwrap_or_default().to_owned()),
        },
        source: config.source,
        sign_in,
        agent_start,
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
    config: &Config,
    default: impl FnOnce() -> Option<PathBuf>,
    appdata: impl FnOnce() -> Option<PathBuf>,
    exists: impl FnOnce(&Path) -> bool,
) -> String {
    if demo {
        return crate::demo::CONFIG_PATH.to_owned();
    }
    let default = default();
    if let Config::Reported(ConfigSource::Defaults) = config {
        let line = shown(default.as_deref(), appdata().as_deref());
        return match default {
            Some(path) if exists(&path) => fill(RESTART, &[&line]),
            Some(_) => fill(NOT_CREATED, &[&line]),
            None => line,
        };
    }
    let path = config.path(|| default.clone());
    let line = shown(path.as_deref(), appdata().as_deref());
    match config {
        Config::Reported(_) if path != default => fill(AGENT_CONFIG, &[&line]),
        Config::Reported(_) | Config::Unreported => line,
    }
}

pub fn source(
    demo: bool,
    config: &Config,
    default: impl FnOnce() -> Option<PathBuf>,
    exists: impl FnOnce(&Path) -> bool,
) -> Text {
    if demo {
        return FROM_CONFIG;
    }
    match config.path(default) {
        Some(path) if exists(&path) => FROM_CONFIG,
        _ => BUILT_IN,
    }
}

pub fn opened(
    path: Option<PathBuf>,
    is_file: impl Fn(&Path) -> bool,
    is_dir: impl Fn(&Path) -> bool,
) -> Option<PathBuf> {
    let path = path?;
    if is_file(&path) {
        return Some(path);
    }
    let folder = path.parent().filter(|dir| !dir.as_os_str().is_empty())?;
    is_dir(folder).then(|| folder.to_owned())
}

pub fn command(exe: &Path) -> Option<String> {
    let exe = exe.to_str()?;
    (!exe.contains('"')).then(|| format!("\"{exe}\""))
}

fn comparable(path: &str) -> String {
    path.replace('/', "\\").to_lowercase()
}

fn split(value: &str) -> Option<(&str, &str)> {
    let value = value.trim();
    let (program, rest) = match value.strip_prefix('"') {
        Some(quoted) => quoted.split_once('"')?,
        None => value.split_once(char::is_whitespace).unwrap_or((value, "")),
    };
    (!program.is_empty()).then_some((program, rest))
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AgentStart {
    On,
    Off,
    #[default]
    Unknown,
}

impl AgentStart {
    pub fn text(self) -> Text {
        match self {
            AgentStart::On => Text::On,
            AgentStart::Off => Text::Off,
            AgentStart::Unknown => Text::Unknown,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegValue {
    Absent,
    Text(String),
    Binary(Vec<u8>),
    Other,
}

pub fn reg_text(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&pair| u16::from_le_bytes(pair))
        .take_while(|&unit| unit != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

pub fn agent_start(run: Result<RegValue, ()>, approved: Result<RegValue, ()>) -> AgentStart {
    match run {
        Ok(RegValue::Absent) => AgentStart::Off,
        Ok(RegValue::Text(value)) if installed(&value) => approval(approved),
        _ => AgentStart::Unknown,
    }
}

fn approval(approved: Result<RegValue, ()>) -> AgentStart {
    match approved {
        Ok(RegValue::Absent) => AgentStart::On,
        Ok(RegValue::Binary(bytes)) => match bytes.first() {
            Some(0x02) => AgentStart::On,
            Some(0x03) => AgentStart::Off,
            _ => AgentStart::Unknown,
        },
        _ => AgentStart::Unknown,
    }
}

fn installed(value: &str) -> bool {
    let Some((program, args)) = split(value) else {
        return false;
    };
    let program = comparable(program);
    let name = program.rsplit('\\').next().unwrap_or_default();
    name == "gateinto.exe" && args.split_whitespace().eq(["agent", "--detach"])
}

pub fn read_agent_start(
    demo: bool,
    run: impl FnOnce() -> Result<RegValue, ()>,
    approved: impl FnOnce() -> Result<RegValue, ()>,
) -> AgentStart {
    if demo {
        return crate::demo::AGENT_START;
    }
    agent_start(run(), approved())
}

pub fn reread(last: Option<Instant>, now: Instant) -> bool {
    last.is_none_or(|last| now.saturating_duration_since(last) >= crate::worker::POLL)
}

#[cfg(test)]
mod tests {
    use std::path::MAIN_SEPARATOR_STR;
    use std::time::Duration;

    use crate::worker::POLL;

    use super::*;
    use crate::i18n::Choice as Language;

    #[test]
    fn the_agent_run_value_is_the_one_the_installer_writes() {
        let wxs = include_str!("../../packaging/wix/gateinto.wxs");
        let run = format!(
            r#"Key="Software\Microsoft\Windows\CurrentVersion\Run" Name="{AGENT_RUN_VALUE}" Type="string" Value="&quot;[INSTALLFOLDER]gateinto.exe&quot; agent --detach""#
        );
        assert!(wxs.contains(&run));
        assert_ne!(AGENT_RUN_VALUE, RUN_VALUE);
    }

    fn text(value: &str) -> Result<RegValue, ()> {
        Ok(RegValue::Text(value.to_owned()))
    }

    fn approved(bytes: &[u8]) -> Result<RegValue, ()> {
        Ok(RegValue::Binary(bytes.to_vec()))
    }

    const INSTALLED: &str = r#""C:\G\gateinto.exe" agent --detach"#;

    #[test]
    fn the_installer_command_means_the_agent_starts_at_sign_in() {
        for value in [
            r#""C:\Users\me\AppData\Local\Programs\Gateinto\gateinto.exe" agent --detach"#,
            r#"  "D:\Tools\GATEINTO.EXE"   agent   --detach  "#,
            r#""C:/Programs/Gateinto/gateinto.exe" agent --detach"#,
            r"C:\Gateinto\gateinto.exe agent --detach",
        ] {
            assert_eq!(
                agent_start(text(value), Ok(RegValue::Absent)),
                AgentStart::On,
                "{value}"
            );
        }
    }

    #[test]
    fn only_a_missing_run_value_means_the_agent_does_not_start_at_sign_in() {
        for approval in [
            Ok(RegValue::Absent),
            approved(&[2]),
            approved(&[3]),
            Err(()),
        ] {
            assert_eq!(agent_start(Ok(RegValue::Absent), approval), AgentStart::Off);
        }
    }

    #[test]
    fn a_run_value_of_another_type_is_unknown() {
        for run in [
            Ok(RegValue::Other),
            Ok(RegValue::Binary(
                INSTALLED
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect(),
            )),
        ] {
            assert_eq!(agent_start(run, Ok(RegValue::Absent)), AgentStart::Unknown);
        }
    }

    #[test]
    fn any_other_command_or_a_read_error_is_unknown() {
        for value in [
            "",
            r#""C:\Gateinto\gateinto.exe""#,
            r#""C:\Gateinto\gateinto.exe" agent"#,
            r#""C:\Gateinto\gateinto.exe" agent --detach --config x.toml"#,
            r#""C:\Gateinto\gateinto.exe" --detach agent"#,
            r#""C:\Gateinto\gateinto-gui.exe" agent --detach"#,
            r#""C:\Gateinto\not-gateinto.exe" agent --detach"#,
            r#""C:\Gateinto\gateinto.exe agent --detach"#,
            r"C:\Program Files\Gateinto\gateinto.exe agent --detach",
            r#"cmd /c "C:\Gateinto\gateinto.exe" agent --detach"#,
        ] {
            assert_eq!(
                agent_start(text(value), Ok(RegValue::Absent)),
                AgentStart::Unknown,
                "{value}"
            );
        }
        assert_eq!(
            agent_start(Err(()), Ok(RegValue::Absent)),
            AgentStart::Unknown
        );
    }

    #[test]
    fn the_startup_approved_value_can_turn_the_installer_command_off() {
        let start = |approval| agent_start(text(INSTALLED), approval);
        assert_eq!(start(Ok(RegValue::Absent)), AgentStart::On);
        assert_eq!(
            start(approved(&[0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
            AgentStart::On
        );
        assert_eq!(start(approved(&[0x02])), AgentStart::On);
        assert_eq!(
            start(approved(&[0x03, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])),
            AgentStart::Off
        );
        assert_eq!(start(approved(&[0x03])), AgentStart::Off);
    }

    #[test]
    fn any_other_startup_approved_value_is_unknown() {
        for approval in [
            approved(&[0x00]),
            approved(&[0x01]),
            approved(&[0x06, 0, 0, 0]),
            approved(&[]),
            text("02"),
            Ok(RegValue::Other),
            Err(()),
        ] {
            assert_eq!(agent_start(text(INSTALLED), approval), AgentStart::Unknown);
        }
    }

    #[test]
    fn registry_text_is_read_up_to_its_terminator() {
        let bytes =
            |value: &str| -> Vec<u8> { value.encode_utf16().flat_map(u16::to_le_bytes).collect() };
        assert_eq!(
            reg_text(&bytes("gateinto.exe agent\0junk")),
            "gateinto.exe agent"
        );
        assert_eq!(reg_text(&bytes("代理程式")), "代理程式");
        let mut odd = bytes("ab");
        odd.push(b'c');
        assert_eq!(reg_text(&odd), "ab");
        assert_eq!(reg_text(&[]), "");
    }

    #[test]
    fn each_agent_start_state_has_a_fixed_text_in_both_languages() {
        let shown =
            || [AgentStart::On, AgentStart::Off, AgentStart::Unknown].map(|state| tr(state.text()));
        assert_eq!(shown(), ["On", "Off", "Unknown"]);
        let _zh = crate::i18n::speaking(crate::i18n::Language::Chinese);
        assert_eq!(shown(), ["開啟", "關閉", "未知"]);
    }

    #[test]
    fn the_demo_shows_a_fixed_agent_start_without_reading_the_registry() {
        let unasked = || -> Result<RegValue, ()> { panic!("the demo read the registry") };
        assert_eq!(
            read_agent_start(true, unasked, unasked),
            crate::demo::AGENT_START
        );
        assert_eq!(crate::demo::AGENT_START, AgentStart::On);
        let absent = || Ok(RegValue::Absent);
        assert_eq!(
            read_agent_start(false, || text(INSTALLED), absent),
            AgentStart::On
        );
        assert_eq!(
            read_agent_start(false, || text(INSTALLED), || approved(&[3])),
            AgentStart::Off
        );
        assert_eq!(read_agent_start(false, absent, absent), AgentStart::Off);
        assert_eq!(
            read_agent_start(false, || Err(()), absent),
            AgentStart::Unknown
        );
    }

    #[test]
    fn the_agent_run_value_is_read_again_at_most_once_per_poll() {
        let start = Instant::now();
        assert!(reread(None, start));
        assert!(!reread(Some(start), start));
        assert!(!reread(
            Some(start),
            start + POLL - Duration::from_millis(1)
        ));
        assert!(reread(Some(start), start + POLL));
    }

    #[test]
    fn the_sign_in_value_is_not_the_installer_agent_value() {
        let wxs = include_str!("../../packaging/wix/gateinto.wxs");
        let run = r#"Key="Software\Microsoft\Windows\CurrentVersion\Run" Name="Gateinto""#;
        assert!(wxs.contains(run));
        assert_eq!(RUN_VALUE, "Gateinto App");
        assert!(!wxs.contains(RUN_VALUE));
        assert!(!wxs.contains("StartupApproved"));
    }

    fn parsed(text: &str) -> ConfigFile {
        ConfigFile::parse(text).unwrap()
    }

    fn none() -> Option<PathBuf> {
        None
    }

    fn view(line: &str) -> ConfigView {
        ConfigView {
            line: line.to_owned(),
            source: FROM_CONFIG,
        }
    }

    #[test]
    fn the_page_shows_the_path_rows_and_both_sign_in_states() {
        let config = ConfigView {
            line: "%APPDATA%\\g.toml".to_owned(),
            source: BUILT_IN,
        };
        let page = page(
            &config,
            &Ok(Agent::default()),
            None,
            true,
            AgentStart::On,
            Choice::Dark,
            Language::Chinese,
        );
        assert_eq!(
            page,
            Page {
                line: "%APPDATA%\\g.toml".to_owned(),
                failed: false,
                agent: Ok(rows(&Agent::default())),
                source: BUILT_IN,
                sign_in: true,
                agent_start: AgentStart::On,
                theme: Choice::Dark,
                language: Language::Chinese,
            }
        );
    }

    #[test]
    fn a_failure_replaces_the_path_line_in_the_current_language() {
        let failed = || {
            page(
                &view("p"),
                &Ok(Agent::default()),
                Some(crate::i18n::Note::from(OPEN_FAILED).shown()),
                false,
                AgentStart::Unknown,
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
        let page = page(
            &view("p"),
            &error,
            None,
            false,
            AgentStart::Off,
            Choice::System,
            Language::System,
        );
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

    fn file(path: &Path) -> Config {
        Config::Reported(ConfigSource::File(path.to_owned()))
    }

    #[test]
    fn the_config_line_names_the_file_the_running_agent_loaded() {
        let appdata = Path::new("/users/me/appdata");
        let default = appdata.join("gateinto.toml");
        let line = |config: &Config| {
            config_line(
                false,
                config,
                || Some(default.clone()),
                || Some(appdata.to_owned()),
                |_| panic!("checked whether a reported file exists"),
            )
        };
        let ours = ["%APPDATA%", "gateinto.toml"].join(MAIN_SEPARATOR_STR);
        assert_eq!(line(&Config::Unreported), ours);
        assert_eq!(line(&file(&default)), ours);
        let other = Path::new("/srv/gateinto/agent.toml");
        assert_eq!(
            line(&file(other)),
            "/srv/gateinto/agent.toml (used by the running agent)"
        );
        let _zh = crate::i18n::speaking(crate::i18n::Language::Chinese);
        assert_eq!(
            line(&file(other)),
            "/srv/gateinto/agent.toml（執行中的代理程式所用）"
        );
    }

    #[test]
    fn with_built_in_defaults_the_config_line_shows_the_default_path_and_its_state() {
        let appdata = Path::new("/users/me/appdata");
        let default = appdata.join("Gateinto").join("gateinto.toml");
        let line = |exists: bool| {
            config_line(
                false,
                &Config::Reported(ConfigSource::Defaults),
                || Some(default.clone()),
                || Some(appdata.to_owned()),
                |path| {
                    assert_eq!(path, default);
                    exists
                },
            )
        };
        let ours = ["%APPDATA%", "Gateinto", "gateinto.toml"].join(MAIN_SEPARATOR_STR);
        assert_eq!(line(false), format!("{ours} (not created yet)"));
        assert_eq!(line(true), format!("{ours} (restart the agent to use it)"));
        let none = config_line(
            false,
            &Config::Reported(ConfigSource::Defaults),
            || None,
            || Some(appdata.to_owned()),
            |_| panic!("checked a missing path"),
        );
        assert_eq!(none, NO_PATH.english());
        let _zh = crate::i18n::speaking(crate::i18n::Language::Chinese);
        assert_eq!(line(false), format!("{ours}（尚未建立）"));
        assert_eq!(line(true), format!("{ours}（請重新啟動代理程式以使用）"));
    }

    #[test]
    fn the_agent_card_names_where_its_values_come_from() {
        let default = PathBuf::from("/users/me/appdata/Gateinto/gateinto.toml");
        let other = Path::new("/srv/gateinto/agent.toml");
        let source = |config: &Config, exists: bool| {
            super::source(false, config, || Some(default.clone()), |_| exists)
        };
        assert_eq!(source(&file(other), true), FROM_CONFIG);
        assert_eq!(source(&Config::Unreported, true), FROM_CONFIG);
        assert_eq!(source(&Config::Unreported, false), BUILT_IN);
        assert_eq!(
            source(&Config::Reported(ConfigSource::Defaults), true),
            BUILT_IN
        );
        assert_eq!(
            super::source(false, &Config::Unreported, || None, |_| true),
            BUILT_IN
        );
        let unasked = || -> Option<PathBuf> { panic!("the demo looked up a real path") };
        assert_eq!(
            super::source(true, &Config::Unreported, unasked, |_| false),
            FROM_CONFIG
        );
        assert_eq!(
            (BUILT_IN.english(), BUILT_IN.chinese()),
            ("Built-in defaults", "內建預設值")
        );
    }

    #[test]
    fn the_demo_config_line_ignores_what_the_agent_reports() {
        let unasked = || -> Option<PathBuf> { panic!("the demo looked up a real path") };
        let other = file(Path::new("/srv/gateinto/agent.toml"));
        assert_eq!(
            config_line(true, &other, unasked, unasked, |_| panic!("probed a file")),
            crate::demo::CONFIG_PATH
        );
    }

    #[test]
    fn open_config_falls_back_to_the_folder_of_a_missing_file() {
        let dir = Path::new("/users/me/appdata/Gateinto");
        let path = dir.join("gateinto.toml");
        fn is(wanted: &Path) -> impl Fn(&Path) -> bool + '_ {
            move |p| p == wanted
        }
        let never = |_: &Path| false;
        assert_eq!(
            opened(Some(path.clone()), is(&path), is(dir)),
            Some(path.clone())
        );
        assert_eq!(
            opened(Some(path.clone()), never, is(dir)),
            Some(dir.to_owned())
        );
        assert_eq!(opened(Some(path.clone()), never, never), None);
        assert_eq!(opened(None, |_: &Path| true, |_: &Path| true), None);
        assert_eq!(
            opened(Some(PathBuf::from("gateinto.toml")), never, |_: &Path| true),
            None
        );
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
