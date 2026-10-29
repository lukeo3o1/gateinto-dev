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

pub fn names(list: &[u16]) -> Vec<String> {
    list.split(|&unit| unit == 0)
        .take_while(|name| !name.is_empty())
        .map(String::from_utf16_lossy)
        .collect()
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
    Software => "Software", "軟體";
    Algorithm => "Algorithm", "演算法";
    Agent => "Agent", "代理程式";
    SignedInAs => "Signed in as {0}", "登入身分：{0}";
    AgentOlder => "The running agent is older than this version of Gateinto and cannot show its log. Restart it to see its messages here.", "執行中的代理程式比這個版本的 Gateinto 舊，無法顯示記錄。請重新啟動代理程式以在此查看訊息。";
    NoMessages => "No messages yet", "尚無訊息";
    NoWarnings => "No warnings", "沒有警告";
    LogSubtitle => "Messages from the running agent. Passwords and page contents are never logged.", "來自執行中代理程式的訊息。密碼與網頁內容一律不會記錄。";
    Copy => "Copy", "複製";
    CopyLogFailed => "Could not copy the log", "無法複製記錄";
    Warnings => "Warnings", "警告";
    NoGateways => "No gateways", "沒有閘道";
    PortalFailed => "Could not open the portal page", "無法開啟入口網頁";
    ShowCredentials => "Show credentials", "顯示憑證";
    OpenPortal => "Open portal page", "開啟入口網頁";
    GatewayDetails => "Gateway details", "閘道詳細資料";
    NotFound => "Not found", "找不到";
    NoConfigPath => "No config file location", "沒有設定檔位置";
    OpenConfig => "Open config file", "開啟設定檔";
    OpenConfigFailed => "Could not open the config file", "無法開啟設定檔";
    App => "App", "應用程式";
    Theme => "Theme", "主題";
    ThemeFailed => "Could not save the theme setting", "無法儲存主題設定";
    SignIn => "Start at sign-in", "登入時啟動";
    SignInNote => "Opens Gateinto when you sign in", "登入時開啟 Gateinto";
    SignInUnread => "Could not read the sign-in setting", "無法讀取登入時啟動設定";
    SignInFailed => "Could not change the sign-in setting", "無法變更登入時啟動設定";
    FromConfig => "From the config file", "來自設定檔";
    Detected => "{0} (detected)", "{0}（已偵測）";
    Kilobytes => "{0} KB", "{0} KB";
    Bytes => "{0} bytes", "{0} 位元組";
    Seconds => "{0} s", "{0} 秒";
    ConcurrentTunnels => "Concurrent tunnels", "同時通道數";
    ConnectTimeout => "Connect timeout", "連線逾時";
    IdleTimeout => "Idle timeout", "閒置逾時";
    HeaderLimit => "Request header limit", "請求標頭上限";
    Light => "Light", "淺色";
    Dark => "Dark", "深色";
    CredentialsTitle => "Session credentials", "工作階段憑證";
    Close => "Close", "關閉";
    Add => "Add", "新增";
    Cancel => "Cancel", "取消";
    Username => "Username", "使用者名稱";
    AskingCredentials => "Asking the agent for this session's credentials…", "正在向代理程式索取此工作階段的憑證…";
    CredentialsUnavailable => "The agent did not hand out this session's credentials. Close this and try again.", "代理程式未提供此工作階段的憑證。請關閉後再試一次。";
    CredentialsSubtitle => "Shown when this PC cannot check the OS user, so the browser asks for a proxy sign-in.", "這台電腦無法確認作業系統使用者、瀏覽器因此要求 Proxy 登入時顯示。";
    ClipboardFailed => "Could not copy to the clipboard", "無法複製到剪貼簿";
    HyphenHint => "Type it exactly, including the hyphens.", "請完整輸入，包括連字號。";
    DialogNames => "sign-in dialog names {0}", "登入對話框會顯示 {0}";
    CredentialsWarning => "Enter these only in the browser's proxy sign-in dialog that names {0}. Never enter them in a website's sign-in page or dialog.", "只能在顯示 {0} 的瀏覽器 Proxy 登入對話框中輸入。切勿在網站的登入頁面或對話框中輸入。";
    GatewayAddress => "Gateway address", "閘道位址";
    AddressHint => "Host name or IP address. Port 443 is the default.", "主機名稱或 IP 位址。預設連接埠為 443。";
    NameHint => "Shown in lists. Leave empty to use the host name.", "顯示在清單中。留空則使用主機名稱。";
    PortalHint => "Optional. An https:// page the browser opens first.", "選填。瀏覽器最先開啟的 https:// 網頁。";
    NoFolder => "This device has no folder for added gateways.", "這台裝置沒有存放新增閘道的資料夾。";
    Ambiguous => "Several gateways use this address. Enter the name of the one you mean.", "有多個閘道使用這個位址。請輸入您要的閘道名稱。";
    Damaged => "A damaged gateway entry on this device uses this name or address. Fix or remove it, then try again.", "這台裝置上有一筆損毀的閘道項目使用這個名稱或位址。請修正或移除後再試一次。";
    Unstorable => "This address is too long to store on this device.", "這個位址太長，無法存放在這台裝置上。";
    StoreUnavailable => "The gateways added on this device cannot be read, so no gateway can be added now.", "無法讀取這台裝置上新增的閘道，因此目前無法新增閘道。";
    Taken => "Another gateway with this name or address was just added. Nothing was changed.", "剛才已新增另一個使用這個名稱或位址的閘道。未做任何變更。";
    Full => "This device holds as many added gateways as it can. Remove one first.", "這台裝置可新增的閘道已達上限。請先移除一個。";
    NotSaved => "The gateway could not be saved on this device.", "無法在這台裝置上儲存閘道。";
    Unlisted => "The gateway list cannot be read.", "無法讀取閘道清單。";
    Unusable => "These values cannot be used for a gateway.", "這些值無法用於閘道。";
    EnterHost => "Enter a host name or IP address, with an optional :port.", "請輸入主機名稱或 IP 位址，可加上 :連接埠。";
    ReservedHost => "The host may not start with a Windows device name such as CON or NUL.", "主機名稱不可用 CON 或 NUL 等 Windows 裝置名稱開頭。";
    NameRule => "Use letters, digits, _ or -, not starting with -.", "請使用字母、數字、_ 或 -，且不可以 - 開頭。";
    EnterHttps => "Enter an https:// address.", "請輸入 https:// 位址。";
    AlreadySetUp => "Already set up as \"{0}\".", "已設定為「{0}」。";
    NameUsed => "\"{0}\" is already used by another gateway.", "「{0}」已被其他閘道使用。";
    TooClose => "Too close to \"{0}\": names may not differ only in letter case.", "與「{0}」太相近：名稱不可只有大小寫不同。";
    StartSession => "Start a browser session", "啟動瀏覽器工作階段";
    NoGatewaysYet => "No gateways yet.", "尚無閘道。";
    StartingSession => "Starting a browser session…", "正在啟動瀏覽器工作階段…";
    SessionStarted => "Browser session started", "已啟動瀏覽器工作階段";
    OpenApp => "Open Gateinto", "開啟 Gateinto";
    AddGatewayMenu => "Add gateway…", "新增閘道…";
    Exit => "Exit", "結束";
    FlyoutTitle => "Gateinto status", "Gateinto 狀態";
    OneSessionTraffic => "1 session · {0} with traffic", "1 個工作階段 · {0} 個有流量";
    SessionsTraffic => "{0} sessions · {1} with traffic", "{0} 個工作階段 · {1} 個有流量";
    Checking => "Checking", "檢查中";
    WaitingStatus => "Waiting for the agent status", "正在等候代理程式狀態";
    OpenCount => "{0} open", "{0} 個已開啟";
    MoreInApp => "{0} more in Gateinto", "Gateinto 中還有 {0} 個";
    TrayTip => "Gateinto: {0}\n{1}", "Gateinto：{0}\n{1}";
    DemoTitle => "Gateinto Demo", "Gateinto 示範";
    DemoFlyoutTitle => "Gateinto Demo status", "Gateinto 示範狀態";
    DemoTrayTip => "Gateinto Demo: {0}\n{1}", "Gateinto 示範：{0}\n{1}";
    DemoNotStarted => "Demo: nothing was started", "示範：未啟動任何項目";
    DemoNotRevoked => "Demo: nothing was revoked", "示範：未撤銷任何項目";
    DemoNotStopped => "Demo: the agent was not stopped", "示範：未停止代理程式";
    DemoNotSaved => "Demo: nothing was saved", "示範：未儲存任何項目";
    DemoNotOpened => "Demo: nothing was opened", "示範：未開啟任何項目";
    NoRendering => "Gateinto could not start Direct2D and DirectWrite rendering.", "Gateinto 無法啟動 Direct2D 與 DirectWrite 繪製。";
    NoWindowClass => "Gateinto could not register its window class.", "Gateinto 無法登錄視窗類別。";
    NoWindow => "Gateinto could not create its window.", "Gateinto 無法建立視窗。";
    LanguageRow => "Language", "語言";
    LanguageFailed => "Could not save the language setting", "無法儲存語言設定";
    AgentNotRunning => "no agent is running", "沒有正在執行的代理程式";
    AgentClosed => "the agent closed the connection without an answer", "代理程式未回應就關閉了連線";
    AgentTimedOut => "the agent did not answer in time", "代理程式未及時回應";
    Confirmation => "the agent asked to confirm this gateway; open its gateinto:// link to confirm it", "代理程式要求確認此閘道；請開啟其 gateinto:// 連結以確認";
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Note {
    Gui(Text),
    Agent(String),
}

impl Note {
    pub fn shown(&self) -> &str {
        match self {
            Note::Gui(text) => tr(*text),
            Note::Agent(message) => message,
        }
    }
}

impl From<Text> for Note {
    fn from(text: Text) -> Self {
        Note::Gui(text)
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
    fn gui_notes_follow_the_language_and_agent_notes_stay_as_worded() {
        let gui = Note::from(Text::DemoNote);
        let agent = Note::Agent("Sample data only".to_owned());
        set(Language::Chinese);
        assert_eq!(gui.shown(), "僅為範例資料");
        assert_eq!(agent.shown(), "Sample data only");
        set(Language::English);
        assert_eq!(gui.shown(), "Sample data only");
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

    #[test]
    fn a_preferred_language_list_reads_up_to_its_first_empty_name() {
        let list: Vec<u16> = "zh-TW\0en-US\0\0".encode_utf16().collect();
        assert_eq!(names(&list), ["zh-TW", "en-US"]);
        assert_eq!(from_tags(&names(&list)), Some(Language::Chinese));
        assert!(names(&[0, 0]).is_empty());
        assert_eq!(from_tags(&names(&[])), None);
    }
}
