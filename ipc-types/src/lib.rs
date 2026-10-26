use std::fmt;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

macro_rules! named {
    ($name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        pub enum $name {
            $(#[serde(rename = $text)] $variant),+
        }

        impl $name {
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $text),+
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
    Device => "device",
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
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn parse_list(lines: &[String]) -> Result<Vec<Self>, serde_json::Error> {
        lines
            .iter()
            .filter(|line| line.starts_with('{'))
            .map(|line| serde_json::from_str(line))
            .collect()
    }
}

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
    fn a_list_skips_lines_that_are_not_json_objects_and_ignores_unknown_fields() {
        let mut line = info(None).to_line();
        line.insert_str(1, r#""added_later":true,"#);
        let lines = ["agent-pid: 42".to_owned(), line];
        assert_eq!(SessionInfo::parse_list(&lines).unwrap(), [info(None)]);
    }

    #[test]
    fn a_malformed_session_line_fails_the_list() {
        let lines = [r#"{"id":"x"}"#.to_owned()];
        assert!(SessionInfo::parse_list(&lines).is_err());
    }

    #[test]
    fn the_names_shown_to_people_match_the_json_values() {
        assert_eq!(SessionKind::Device.to_string(), "device");
        assert_eq!(SessionRoute::All.to_string(), "all");
        assert_eq!(SessionAuth::OsUser.to_string(), "os_user");
        assert_eq!(BrowserKind::Edge.to_string(), "edge");
    }
}
