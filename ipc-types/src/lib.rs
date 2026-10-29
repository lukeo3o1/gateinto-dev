use std::fmt;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

macro_rules! named {
    ($name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        pub enum $name {
            $(#[serde(rename = $text)] $variant,)+
            #[serde(other, rename = "unknown")]
            Unknown,
        }

        impl $name {
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $text,)+
                    Self::Unknown => "unknown",
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

named!(SessionKind {
    Browser => "browser",
});

named!(SessionRoute {
    All => "all",
    Mixed => "mixed",
});

named!(SessionAuth {
    OsUser => "os_user",
    Password => "password",
    None => "none",
});

named!(BrowserKind {
    Chrome => "chrome",
    Edge => "edge",
    Chromium => "chromium",
});

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: u64,
    pub kind: SessionKind,
    pub gateway: String,
    pub upstream: String,
    pub listen: SocketAddr,
    pub route: SessionRoute,
    pub auth: SessionAuth,
    pub started: u64,
    pub tunnels: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser: Option<BrowserKind>,
}

impl SessionInfo {
    pub fn to_line(&self) -> String {
        serde_json::to_string(self).expect("a session has only string keys and serializable values")
    }

    pub fn parse_list(lines: &[String]) -> Result<Vec<Self>, ListError> {
        lines
            .iter()
            .filter(|line| !line.is_empty())
            .map(|line| {
                if line.starts_with('{') {
                    serde_json::from_str(line).map_err(ListError::Malformed)
                } else {
                    Err(ListError::OlderAgent(line.clone()))
                }
            })
            .collect()
    }
}

#[derive(Debug)]
pub enum ListError {
    OlderAgent(String),
    Malformed(serde_json::Error),
}

impl fmt::Display for ListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OlderAgent(_) => f.write_str(
                "the running agent is older than this version of gateinto and cannot list its sessions here; restart it with `gateinto stop` and start it again",
            ),
            Self::Malformed(error) => {
                write!(f, "the agent listed a session this version cannot read: {error}")
            }
        }
    }
}

impl std::error::Error for ListError {}

named!(LogLevel {
    Error => "error",
    Warn => "warn",
    Info => "info",
});

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEvent {
    pub seq: u64,
    pub time: u64,
    pub level: LogLevel,
    pub scope: String,
    pub message: String,
}

impl LogEvent {
    pub fn to_line(&self) -> String {
        serde_json::to_string(self)
            .expect("a log event has only string keys and serializable values")
    }
}

const LAST: &str = "last: ";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogPage {
    pub last: u64,
    pub events: Vec<LogEvent>,
}

impl LogPage {
    pub fn last_line(last: u64) -> String {
        format!("{LAST}{last}")
    }

    pub fn to_lines(&self) -> Vec<String> {
        std::iter::once(Self::last_line(self.last))
            .chain(self.events.iter().map(LogEvent::to_line))
            .collect()
    }

    pub fn parse(lines: &[String]) -> Result<Self, LogError> {
        let mut last = None;
        let mut events = Vec::new();
        for line in lines {
            if line.starts_with('{') {
                events.push(serde_json::from_str(line).map_err(LogError::Malformed)?);
            } else if let Some(value) = line.strip_prefix(LAST) {
                last = value.parse().ok();
            }
        }
        Ok(Self {
            last: last.ok_or(LogError::Missing)?,
            events,
        })
    }
}

#[derive(Debug)]
pub enum LogError {
    Missing,
    Malformed(serde_json::Error),
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the agent sent a log page this version cannot read: ")?;
        match self {
            Self::Missing => f.write_str("it has no last sequence number"),
            Self::Malformed(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for LogError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(browser: Option<BrowserKind>) -> SessionInfo {
        SessionInfo {
            id: 3,
            kind: SessionKind::Browser,
            gateway: "main".to_owned(),
            upstream: "[::1]:443".to_owned(),
            listen: "127.0.0.1:8080".parse().unwrap(),
            route: SessionRoute::Mixed,
            auth: SessionAuth::OsUser,
            started: 1_700_000_000,
            tunnels: 2,
            browser,
        }
    }

    #[test]
    fn a_session_is_one_json_object_with_snake_case_values() {
        let line = info(Some(BrowserKind::Chrome)).to_line();
        assert_eq!(
            line,
            r#"{"id":3,"kind":"browser","gateway":"main","upstream":"[::1]:443","listen":"127.0.0.1:8080","route":"mixed","auth":"os_user","started":1700000000,"tunnels":2,"browser":"chrome"}"#
        );
        assert_eq!(
            SessionInfo::parse_list(&[line]).unwrap(),
            [info(Some(BrowserKind::Chrome))]
        );
    }

    #[test]
    fn an_unknown_browser_is_omitted_and_read_back_as_none() {
        let line = info(None).to_line();
        assert!(!line.contains("browser\":"), "{line}");
        assert_eq!(SessionInfo::parse_list(&[line]).unwrap(), [info(None)]);
    }

    #[test]
    fn a_list_skips_empty_lines_and_ignores_unknown_fields() {
        let mut line = info(None).to_line();
        line.insert_str(1, r#""added_later":true,"#);
        let lines = [String::new(), line];
        assert_eq!(SessionInfo::parse_list(&lines).unwrap(), [info(None)]);
    }

    #[test]
    fn values_added_by_a_newer_agent_are_read_as_unknown() {
        let line = info(Some(BrowserKind::Chrome))
            .to_line()
            .replace(r#""browser":"chrome""#, r#""browser":"firefox""#)
            .replace(r#""auth":"os_user""#, r#""auth":"token""#)
            .replace(r#""kind":"browser""#, r#""kind":"tunnel""#)
            .replace(r#""route":"mixed""#, r#""route":"split""#);
        assert_eq!(
            SessionInfo::parse_list(&[line]).unwrap(),
            [SessionInfo {
                kind: SessionKind::Unknown,
                route: SessionRoute::Unknown,
                auth: SessionAuth::Unknown,
                browser: Some(BrowserKind::Unknown),
                ..info(None)
            }]
        );
        assert_eq!(BrowserKind::Unknown.to_string(), "unknown");
    }

    #[test]
    fn the_removed_device_kind_reads_as_unknown() {
        let line = info(None)
            .to_line()
            .replace(r#""kind":"browser""#, r#""kind":"device""#);
        assert_eq!(
            SessionInfo::parse_list(&[line]).unwrap()[0].kind,
            SessionKind::Unknown
        );
    }

    #[test]
    fn an_unknown_value_is_written_as_unknown() {
        let line = SessionInfo {
            kind: SessionKind::Unknown,
            route: SessionRoute::Unknown,
            auth: SessionAuth::Unknown,
            browser: Some(BrowserKind::Unknown),
            ..info(None)
        }
        .to_line();
        for field in ["kind", "route", "auth", "browser"] {
            assert!(line.contains(&format!(r#""{field}":"unknown""#)), "{line}");
        }
    }

    #[test]
    fn a_line_that_is_not_a_json_object_comes_from_an_older_agent() {
        let lines = [
            info(None).to_line(),
            "session: 1 device office 127.0.0.1:8080".to_owned(),
        ];
        let error = SessionInfo::parse_list(&lines).unwrap_err();
        assert!(matches!(&error, ListError::OlderAgent(line) if *line == lines[1]));
        assert_eq!(
            error.to_string(),
            "the running agent is older than this version of gateinto and cannot list its sessions here; restart it with `gateinto stop` and start it again"
        );
    }

    #[test]
    fn the_names_shown_to_people_match_the_json_values() {
        assert_eq!(SessionKind::Browser.to_string(), "browser");
        assert_eq!(SessionRoute::All.to_string(), "all");
        assert_eq!(SessionAuth::OsUser.to_string(), "os_user");
        assert_eq!(BrowserKind::Edge.to_string(), "edge");
    }

    fn event(seq: u64, level: LogLevel) -> LogEvent {
        LogEvent {
            seq,
            time: 1_700_000_000_123,
            level,
            scope: "session 2".to_owned(),
            message: "tunnel opened".to_owned(),
        }
    }

    #[test]
    fn a_log_event_is_one_json_object() {
        assert_eq!(
            event(4, LogLevel::Warn).to_line(),
            r#"{"seq":4,"time":1700000000123,"level":"warn","scope":"session 2","message":"tunnel opened"}"#
        );
    }

    #[test]
    fn a_log_page_round_trips_through_its_lines() {
        let page = LogPage {
            last: 9,
            events: vec![event(8, LogLevel::Info), event(9, LogLevel::Error)],
        };
        let lines = page.to_lines();
        assert_eq!(lines[0], "last: 9");
        assert_eq!(LogPage::parse(&lines).unwrap(), page);
    }

    #[test]
    fn a_log_page_ignores_header_lines_and_fields_added_later() {
        let mut line = event(3, LogLevel::Info).to_line();
        line.insert_str(1, r#""added_later":1,"#);
        let line = line.replace(r#""level":"info""#, r#""level":"notice""#);
        let lines = [
            "agent-pid: 42".to_owned(),
            String::new(),
            "last: 3".to_owned(),
            line,
        ];
        assert_eq!(
            LogPage::parse(&lines).unwrap(),
            LogPage {
                last: 3,
                events: vec![event(3, LogLevel::Unknown)],
            }
        );
    }

    #[test]
    fn a_log_page_needs_its_last_sequence_number() {
        let missing = LogPage::parse(&[event(1, LogLevel::Info).to_line()]).unwrap_err();
        assert!(matches!(missing, LogError::Missing), "{missing:?}");
        let bad = LogPage::parse(&["last: soon".to_owned()]).unwrap_err();
        assert!(matches!(bad, LogError::Missing), "{bad:?}");
        let malformed = LogPage::parse(&["last: 1".to_owned(), "{".to_owned()]).unwrap_err();
        assert!(matches!(malformed, LogError::Malformed(_)), "{malformed:?}");
        assert_eq!(
            missing.to_string(),
            "the agent sent a log page this version cannot read: it has no last sequence number"
        );
    }

    #[test]
    fn log_levels_are_named_like_their_json_values() {
        assert_eq!(LogLevel::Info.to_string(), "info");
        assert_eq!(LogLevel::Warn.to_string(), "warn");
        assert_eq!(LogLevel::Error.to_string(), "error");
    }
}
