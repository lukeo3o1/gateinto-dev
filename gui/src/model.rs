#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionKind {
    Device,
    Browser,
}

#[derive(Clone, Copy, Debug)]
pub struct Session {
    pub id: u32,
    pub title: &'static str,
    pub kind: SessionKind,
    pub gateway: &'static str,
    pub listen: &'static str,
    pub since: &'static str,
    pub auth: &'static str,
    pub route: &'static str,
    pub credentials: bool,
}

pub const SESSIONS: [Session; 3] = [
    Session {
        id: 1,
        title: "Device session",
        kind: SessionKind::Device,
        gateway: "office · proxy.example.com",
        listen: "127.0.0.1:8118",
        since: "since logon",
        auth: "Session credentials",
        route: "Gateway",
        credentials: true,
    },
    Session {
        id: 2,
        title: "Chrome",
        kind: SessionKind::Browser,
        gateway: "office · proxy.example.com",
        listen: "127.0.0.1:49152",
        since: "12 min",
        auth: "Windows user",
        route: "Gateway",
        credentials: false,
    },
    Session {
        id: 3,
        title: "Edge",
        kind: SessionKind::Browser,
        gateway: "lab · gw.lab.example.net",
        listen: "127.0.0.1:49188",
        since: "2 min",
        auth: "Windows user",
        route: "Mixed",
        credentials: false,
    },
];

pub const APP_NAME: &str = "Gateinto";
pub const NAV: [&str; 4] = ["Sessions", "Gateways", "Device identity", "Settings"];
pub const SELECTED_NAV: usize = 0;
pub const TITLE: &str = "Sessions";
pub const SUBTITLE: &str = "Agent running · 3 sessions · listening on loopback only";
pub const OPEN_LOG: &str = "Open log";
pub const NEW_SESSION: &str = "New browser session";
pub const CREDENTIALS: &str = "Credentials";
pub const REVOKE: &str = "Revoke";
pub const DOT: &str = "·";
pub const DEVICE_KEY: &str = "Device key in TPM · non-exportable";
pub const FINGERPRINT: &str = "spki-sha256 [FINGERPRINT]";
pub const DETAILS: &str = "Details";

impl Session {
    pub fn tag(&self) -> String {
        format!("#{}", self.id)
    }

    pub fn detail(&self) -> [(&'static str, bool); 5] {
        [
            (self.gateway, false),
            (DOT, false),
            (self.listen, true),
            (DOT, false),
            (self.since, false),
        ]
    }
}
