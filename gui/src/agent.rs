use std::path::PathBuf;

use gateinto::ipc::{self, ConfigSource, RequestError, Response, SessionInfo};

use crate::i18n::{Note, Text};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentState {
    Running(Vec<SessionInfo>),
    Stopped,
    Unreachable(Note),
}

pub fn note(error: RequestError) -> Note {
    match error {
        RequestError::NotRunning => Text::AgentNotRunning.into(),
        RequestError::Closed => Text::AgentClosed.into(),
        RequestError::TimedOut => Text::AgentTimedOut.into(),
        error => Note::Agent(error.to_string()),
    }
}

impl AgentState {
    pub fn from_list(reply: Result<Response, RequestError>) -> Self {
        match reply {
            Ok(Response::Ok(lines)) => match SessionInfo::parse_list(&lines) {
                Ok(sessions) => Self::Running(sessions),
                Err(error) => Self::Unreachable(Note::Agent(error.to_string())),
            },
            Ok(Response::Error(message)) => Self::Unreachable(Note::Agent(message)),
            Err(RequestError::NotRunning) => Self::Stopped,
            Err(error) => Self::Unreachable(note(error)),
        }
    }

    pub fn ids(&self) -> Vec<u64> {
        match self {
            Self::Running(sessions) => sessions.iter().map(|s| s.id).collect(),
            Self::Stopped | Self::Unreachable(_) => Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Config {
    #[default]
    Unreported,
    Reported(ConfigSource),
}

impl Config {
    pub fn from_reply(reply: Result<Response, RequestError>) -> Self {
        match reply {
            Ok(Response::Ok(lines)) => {
                ipc::config_source(&lines).map_or(Self::Unreported, Self::Reported)
            }
            Ok(Response::Error(_)) | Err(_) => Self::Unreported,
        }
    }

    pub fn path(&self, default: impl FnOnce() -> Option<PathBuf>) -> Option<PathBuf> {
        match self {
            Self::Unreported => default(),
            Self::Reported(ConfigSource::File(path)) => Some(path.clone()),
            Self::Reported(ConfigSource::Defaults) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateinto::ipc::{ConfigSource, SessionAuth, SessionKind, SessionRoute};

    fn session(id: u64) -> SessionInfo {
        SessionInfo {
            id,
            kind: SessionKind::Browser,
            gateway: "office".to_owned(),
            upstream: "proxy.example:443".to_owned(),
            listen: "127.0.0.1:8080".parse().unwrap(),
            route: SessionRoute::All,
            auth: SessionAuth::Password,
            started: 1_000,
            tunnels: 0,
            browser: None,
        }
    }

    #[test]
    fn a_listed_agent_is_running_with_its_sessions() {
        let lines = vec![session(1).to_line(), String::new(), session(4).to_line()];
        assert_eq!(
            AgentState::from_list(Ok(Response::Ok(lines))),
            AgentState::Running(vec![session(1), session(4)])
        );
        assert_eq!(
            AgentState::from_list(Ok(Response::Ok(Vec::new()))),
            AgentState::Running(Vec::new())
        );
    }

    #[test]
    fn only_a_running_agent_has_session_ids() {
        assert_eq!(
            AgentState::Running(vec![session(1), session(4)]).ids(),
            [1, 4]
        );
        assert!(AgentState::Stopped.ids().is_empty());
        assert!(
            AgentState::Unreachable(Note::Agent("busy".to_owned()))
                .ids()
                .is_empty()
        );
    }

    #[test]
    fn client_side_failures_are_worded_by_the_gui() {
        let _zh = crate::i18n::speaking(crate::i18n::Language::Chinese);
        assert_eq!(
            note(RequestError::NotRunning).shown(),
            "沒有正在執行的代理程式"
        );
        assert_eq!(
            note(RequestError::Closed).shown(),
            "代理程式未回應就關閉了連線"
        );
        assert_eq!(note(RequestError::TimedOut).shown(), "代理程式未及時回應");
        assert_eq!(
            AgentState::from_list(Err(RequestError::TimedOut)),
            AgentState::Unreachable(Note::Gui(Text::AgentTimedOut))
        );
        let broken = || RequestError::Io(std::io::Error::other("pipe broke"));
        assert_eq!(note(broken()), Note::Agent(broken().to_string()));
    }

    #[test]
    fn no_agent_means_stopped() {
        assert_eq!(
            AgentState::from_list(Err(RequestError::NotRunning)),
            AgentState::Stopped
        );
    }

    fn reported(lines: &[&str]) -> Config {
        Config::from_reply(Ok(Response::Ok(
            lines.iter().map(|line| (*line).to_owned()).collect(),
        )))
    }

    fn absolute(name: &str) -> PathBuf {
        std::env::temp_dir().join(name)
    }

    #[test]
    fn the_running_agent_reports_its_config_file_or_none() {
        let file = absolute("agent.toml");
        assert_eq!(
            reported(&[&format!("config: {}", file.display())]),
            Config::Reported(ConfigSource::File(file))
        );
        assert_eq!(
            reported(&["config: none"]),
            Config::Reported(ConfigSource::Defaults)
        );
    }

    #[test]
    fn an_agent_that_does_not_report_its_config_is_unreported() {
        let older = Ok(Response::Error(gateinto::ipc::INVALID_REQUEST.to_owned()));
        assert_eq!(Config::from_reply(older), Config::Unreported);
        assert_eq!(
            Config::from_reply(Err(RequestError::NotRunning)),
            Config::Unreported
        );
        assert_eq!(
            Config::from_reply(Err(RequestError::TimedOut)),
            Config::Unreported
        );
        assert_eq!(reported(&[]), Config::Unreported);
        assert_eq!(reported(&["config: relative.toml"]), Config::Unreported);
    }

    #[test]
    fn only_a_reported_config_replaces_the_default_path() {
        let default = absolute("default.toml");
        let ours = || Some(default.clone());
        assert_eq!(Config::Unreported.path(ours), Some(default.clone()));
        let file = absolute("agent.toml");
        let agent = Config::Reported(ConfigSource::File(file.clone()));
        assert_eq!(agent.path(|| panic!("read the default")), Some(file));
        let none = Config::Reported(ConfigSource::Defaults);
        assert_eq!(none.path(|| panic!("read the default")), None);
    }

    #[test]
    fn other_failures_leave_the_agent_unreachable_with_the_reason() {
        assert_eq!(
            AgentState::from_list(Ok(Response::Error("busy".to_owned()))),
            AgentState::Unreachable(Note::Agent("busy".to_owned()))
        );
        let old = AgentState::from_list(Ok(Response::Ok(vec!["session: 1".to_owned()])));
        assert!(
            matches!(&old, AgentState::Unreachable(reason) if reason.shown().contains("older than this version")),
            "{old:?}"
        );
    }
}
