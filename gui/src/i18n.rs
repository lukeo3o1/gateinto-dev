use std::borrow::Cow;
use std::cell::Cell;
use std::fmt;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Language {
    #[default]
    English,
    Chinese,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Choice {
    #[default]
    System,
    English,
    Chinese,
}

pub const KEY: &str = "Software\\Gateinto\\App";
pub const VALUE: &str = "Language";

impl Choice {
    pub const ALL: [Choice; 3] = [Choice::System, Choice::English, Choice::Chinese];

    pub fn name(self) -> &'static str {
        match self {
            Choice::System => "System",
            Choice::English => "English",
            Choice::Chinese => "zh-TW",
        }
    }

    pub fn parse(value: Option<&str>) -> Choice {
        Choice::ALL
            .into_iter()
            .find(|c| Some(c.name()) == value)
            .unwrap_or_default()
    }

    pub fn label(self) -> &'static str {
        match self {
            Choice::System => tr(Text::System),
            Choice::English => "English",
            Choice::Chinese => "繁體中文",
        }
    }

    pub fn language(self, system: Language) -> Language {
        match self {
            Choice::System => system,
            Choice::English => Language::English,
            Choice::Chinese => Language::Chinese,
        }
    }
}

pub fn from_tags<S: AsRef<str>>(tags: &[S]) -> Option<Language> {
    let tag = tags.first()?.as_ref().to_ascii_lowercase();
    let mut parts = tag.split('-');
    let traditional = parts.next() == Some("zh")
        && parts
            .next()
            .is_some_and(|part| ["tw", "hant", "hk", "mo"].contains(&part));
    Some(if traditional {
        Language::Chinese
    } else {
        Language::English
    })
}

pub fn from_langid(id: u16) -> Language {
    match id {
        0x0404 | 0x0C04 | 0x1404 | 0x7C04 => Language::Chinese,
        _ => Language::English,
    }
}

thread_local! {
    static CURRENT: Cell<Language> = const { Cell::new(Language::English) };
}

pub fn set(language: Language) {
    CURRENT.set(language);
}

pub fn current() -> Language {
    CURRENT.get()
}

#[cfg(test)]
pub struct Speaking;

#[cfg(test)]
pub fn speaking(language: Language) -> Speaking {
    set(language);
    Speaking
}

#[cfg(test)]
impl Drop for Speaking {
    fn drop(&mut self) {
        set(Language::English);
    }
}

macro_rules! table {
    ($($key:ident => $en:literal, $zh:literal;)*) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Text {
            $($key,)*
        }

        impl Text {
            #[cfg(test)]
            pub const ALL: &[Text] = &[$(Text::$key,)*];
            const ENGLISH: &[&str] = &[$($en,)*];
            const CHINESE: &[&str] = &[$($zh,)*];
        }
    };
}

table! {
    System => "System", "系統";
    Sessions => "Sessions", "工作階段";
    Gateways => "Gateways", "閘道";
    Device => "Device", "裝置";
    Log => "Log", "記錄";
    Settings => "Settings", "設定";
    ThisDevice => "This device", "這部裝置";
    Demo => "Demo", "示範";
    DemoNote => "Sample data only", "僅為範例資料";
    Relaying => "Relaying", "轉送中";
    Idle => "Idle", "閒置";
    RunningOne => "Agent running on loopback only · {0} session · {1} active", "代理程式僅在本機回送位址執行 · {0} 個工作階段 · {1} 個使用中";
    RunningMany => "Agent running on loopback only · {0} sessions · {1} active", "代理程式僅在本機回送位址執行 · {0} 個工作階段 · {1} 個使用中";
    Stopped => "Stopped", "已停止";
    AgentStopped => "The agent is not running", "代理程式未執行";
    AgentUnreachable => "Agent unreachable", "無法連線到代理程式";
    Browser => "Browser", "瀏覽器";
    DeviceProxy => "Device proxy", "裝置代理";
    Session => "Session", "工作階段";
    OsUser => "OS user", "作業系統使用者";
    Password => "Password", "密碼";
    NoAuthentication => "No authentication", "不驗證";
    Unknown => "Unknown", "未知";
    All => "All", "全部";
    Mixed => "Mixed", "混合";
    UnderMinute => "<1 min", "<1 分鐘";
    Minutes => "{0} min", "{0} 分鐘";
    Hours => "{0} h", "{0} 小時";
    Days => "{0} d", "{0} 天";
    NoSessionsHint => "No sessions. Start one from a gateinto:// link.", "沒有工作階段。請從 gateinto:// 連結啟動。";
    StopAgent => "Stop agent", "停止代理程式";
    StartBrowser => "Start browser", "啟動瀏覽器";
    RevokeSession => "Revoke session", "撤銷工作階段";
    More => "More", "更多";
    ShowPassword => "Show password", "顯示密碼";
    HidePassword => "Hide password", "隱藏密碼";
    Gateway => "Gateway", "閘道";
    Uptime => "Uptime", "運作時間";
    Activity => "Activity", "活動";
    Active => "Active", "使用中";
    GatewaysSubtitle => "Remote HTTPS proxies this device can relay through", "這部裝置可透過其轉送的遠端 HTTPS 代理";
    NoGatewaysHint => "No gateways. Open a gateinto:// link or add one to the config file.", "沒有閘道。請開啟 gateinto:// 連結，或在設定檔中新增。";
    ConfigReadOnly => "From the config file, read-only here.", "來自設定檔，此處為唯讀。";
    AddGateway => "Add gateway", "新增閘道";
    RoutePerStart => "Set per browser start; Start browser uses Gateway", "每次啟動瀏覽器時設定；「啟動瀏覽器」使用閘道";
    NotSet => "Not set", "未設定";
    Name => "Name", "名稱";
    NoValue => "None", "無";
    Host => "Host", "主機";
    Port => "Port", "連接埠";
    ServerName => "Server name", "伺服器名稱";
    Source => "Source", "來源";
    ConfigFile => "Config file", "設定檔";
    AddedHere => "Added on this device", "在這部裝置上新增";
    Route => "Route", "路由";
    PortalPage => "Portal page", "入口網頁";
    TlsMode => "TLS mode", "TLS 模式";
    HybridPreferred => "Hybrid preferred", "優先使用混合";
    HybridRequired => "Hybrid required", "必須使用混合";
    ClassicalOnly => "Classical only", "僅限傳統";
    ClientCertificate => "Client certificate", "用戶端憑證";
    ActiveSessions => "Active sessions", "使用中的工作階段";
    NoSessions => "No sessions", "沒有工作階段";
    SessionCount => "{0} session", "{0} 個工作階段";
    SessionsCount => "{0} sessions", "{0} 個工作階段";
    GatewayAndMixed => "Gateway and Mixed", "閘道與混合";
    Off => "Off", "關閉";
    Optional => "Optional", "選用";
    Required => "Required", "必要";
    SelfSigned => "{0}, self-signed", "{0}，自我簽署";
    DeviceSubtitle => "What gateways see when this PC signs in", "這部電腦登入時閘道看到的資訊";
    Storage => "Storage", "儲存位置";
    DeviceId => "Device ID", "裝置識別碼";
    UsedWith => "Used with", "用於";
    CopyDeviceIdFailed => "Could not copy the device ID", "無法複製裝置識別碼";
    NoDeviceKey => "No device key yet. Run `gateinto setup` to create one.", "尚無裝置金鑰。請執行 `gateinto setup` 建立。";
    ReadingDeviceKey => "Reading the device key…", "正在讀取裝置金鑰…";
    HardwareKey => "Hardware key", "硬體金鑰";
    DeviceKey => "Device key", "裝置金鑰";
    KeyName => "Key name", "金鑰名稱";
    CopyDeviceId => "Copy device ID", "複製裝置識別碼";
    Copied => "Copied", "已複製";
    ThisPc => "This PC", "這部電腦";
    LoopbackOnly => "Loopback only", "僅限本機回送";
    UnknownReason => "Unknown: {0}", "未知：{0}";
    OpenToNetwork => "Open to the network on {0}", "在 {0} 對網路開放";
    Software => "Software", "軟體";
    Algorithm => "Algorithm", "演算法";
    Agent => "Agent", "代理程式";
    SignedInAs => "Signed in as {0}", "登入身分：{0}";
}

impl Text {
    pub fn english(self) -> &'static str {
        Self::ENGLISH[self as usize]
    }

    pub fn chinese(self) -> &'static str {
        Self::CHINESE[self as usize]
    }

    pub fn get(self) -> &'static str {
        match current() {
            Language::English => self.english(),
            Language::Chinese => self.chinese(),
        }
    }
}

pub fn tr(text: Text) -> &'static str {
    text.get()
}

pub fn fill(text: Text, args: &[&dyn fmt::Display]) -> String {
    fill_with(text.get(), args)
}

fn fill_with(template: &str, args: &[&dyn fmt::Display]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let tail = &rest[open..];
        let arg = tail
            .find('}')
            .and_then(|close| Some((tail[1..close].parse::<usize>().ok()?, close)))
            .and_then(|(i, close)| Some((args.get(i)?, close)));
        match arg {
            Some((arg, close)) => {
                out.push_str(&arg.to_string());
                rest = &tail[close + 1..];
            }
            None => {
                out.push('{');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

pub fn localize(english: &str) -> Cow<'_, str> {
    match Text::ENGLISH.iter().position(|&known| known == english) {
        Some(i) if current() == Language::Chinese => Cow::Borrowed(Text::CHINESE[i]),
        _ => Cow::Borrowed(english),
    }
}

impl From<Text> for Cow<'static, str> {
    fn from(text: Text) -> Self {
        Cow::Borrowed(text.get())
    }
}

impl fmt::Display for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn placeholders(s: &str) -> Vec<usize> {
        let mut found: Vec<usize> = (0..10)
            .filter(|i| s.contains(&format!("{{{i}}}")))
            .collect();
        found.sort_unstable();
        found
    }

    #[test]
    fn every_key_has_both_languages_and_no_entry_is_empty() {
        assert_eq!(Text::ALL.len(), Text::ENGLISH.len());
        assert_eq!(Text::ALL.len(), Text::CHINESE.len());
        for &text in Text::ALL {
            assert!(!text.english().trim().is_empty(), "{text:?}");
            assert!(!text.chinese().trim().is_empty(), "{text:?}");
            assert_eq!(
                placeholders(text.english()),
                placeholders(text.chinese()),
                "{text:?}"
            );
        }
    }

    #[test]
    fn english_entries_are_unique_so_messages_map_back_to_one_key() {
        for (i, a) in Text::ENGLISH.iter().enumerate() {
            assert!(!Text::ENGLISH[i + 1..].contains(a), "{a}");
        }
    }

    #[test]
    fn the_current_language_picks_the_entry() {
        assert_eq!(current(), Language::English);
        assert_eq!(tr(Text::Demo), "Demo");
        set(Language::Chinese);
        assert_eq!(tr(Text::Demo), "示範");
        assert_eq!(Cow::from(Text::DemoNote), "僅為範例資料");
        assert_eq!(Text::Demo.to_string(), "示範");
        set(Language::English);
        assert_eq!(Cow::from(Text::DemoNote), "Sample data only");
    }

    #[test]
    fn placeholders_are_filled_by_position() {
        assert_eq!(fill_with("{1} of {0}, {1}", &[&3, &"x"]), "x of 3, x");
        assert_eq!(fill_with("none", &[&3]), "none");
        assert_eq!(fill_with("{0} {1}", &[&"{1}", &"b"]), "{1} b");
        assert_eq!(fill_with("{x} {9} {", &[&1]), "{x} {9} {");
    }

    #[test]
    fn known_messages_are_translated_and_others_kept() {
        set(Language::Chinese);
        assert_eq!(localize("Sample data only"), "僅為範例資料");
        assert_eq!(
            localize("tunnel refused by gateway"),
            "tunnel refused by gateway"
        );
        set(Language::English);
        assert_eq!(localize("Sample data only"), "Sample data only");
    }

    #[test]
    fn choices_round_trip_through_their_stored_names() {
        for choice in Choice::ALL {
            assert_eq!(Choice::parse(Some(choice.name())), choice);
        }
        assert_eq!(Choice::parse(None), Choice::System);
        assert_eq!(Choice::parse(Some("")), Choice::System);
        assert_eq!(Choice::parse(Some("Klingon")), Choice::System);
        assert_eq!(Choice::parse(Some("english")), Choice::System);
    }

    #[test]
    fn choices_resolve_against_the_system_language() {
        for system in [Language::English, Language::Chinese] {
            assert_eq!(Choice::System.language(system), system);
            assert_eq!(Choice::English.language(system), Language::English);
            assert_eq!(Choice::Chinese.language(system), Language::Chinese);
        }
    }

    #[test]
    fn language_names_read_the_same_in_every_language() {
        for language in [Language::English, Language::Chinese] {
            set(language);
            assert_eq!(Choice::English.label(), "English");
            assert_eq!(Choice::Chinese.label(), "繁體中文");
        }
        assert_eq!(Choice::System.label(), "系統");
        set(Language::English);
        assert_eq!(Choice::System.label(), "System");
    }

    #[test]
    fn traditional_chinese_ui_tags_pick_chinese() {
        for tag in [
            "zh-TW",
            "zh-tw",
            "zh-Hant",
            "zh-Hant-TW",
            "zh-HK",
            "zh-MO",
            "zh-Hant-HK",
        ] {
            assert_eq!(from_tags(&[tag]), Some(Language::Chinese), "{tag}");
        }
        for tag in [
            "en-US", "zh-CN", "zh-Hans", "zh-SG", "zh", "ja-JP", "zh-TWX",
        ] {
            assert_eq!(from_tags(&[tag]), Some(Language::English), "{tag}");
        }
        assert_eq!(from_tags(&["en-US", "zh-TW"]), Some(Language::English));
        assert_eq!(from_tags::<&str>(&[]), None);
    }

    #[test]
    fn traditional_chinese_language_ids_pick_chinese() {
        for id in [0x0404, 0x0C04, 0x1404, 0x7C04] {
            assert_eq!(from_langid(id), Language::Chinese, "{id:#x}");
        }
        for id in [0x0409, 0x0804, 0x1004, 0x0411, 0] {
            assert_eq!(from_langid(id), Language::English, "{id:#x}");
        }
    }
}
