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
}
