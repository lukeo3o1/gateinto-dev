use gateinto::ipc::{RequestError, Response, SessionInfo};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentState {
    Running(Vec<SessionInfo>),
    Stopped,
    Unreachable(String),
}

impl AgentState {
    pub fn from_list(reply: Result<Response, RequestError>) -> Self {
        match reply {
            Ok(Response::Ok(lines)) => match SessionInfo::parse_list(&lines) {
                Ok(sessions) => Self::Running(sessions),
                Err(error) => Self::Unreachable(error.to_string()),
            },
            Ok(Response::Error(message)) => Self::Unreachable(message),
            Err(RequestError::NotRunning) => Self::Stopped,
            Err(error) => Self::Unreachable(error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateinto::ipc::{SessionAuth, SessionKind, SessionRoute};

    fn session(id: u64) -> SessionInfo {
        SessionInfo {
            id,
            kind: SessionKind::Device,
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
    fn no_agent_means_stopped() {
        assert_eq!(
            AgentState::from_list(Err(RequestError::NotRunning)),
            AgentState::Stopped
        );
    }

    #[test]
    fn other_failures_leave_the_agent_unreachable_with_the_reason() {
        assert_eq!(
            AgentState::from_list(Err(RequestError::TimedOut)),
            AgentState::Unreachable("the agent did not answer within 60 seconds".to_owned())
        );
        assert_eq!(
            AgentState::from_list(Ok(Response::Error("busy".to_owned()))),
            AgentState::Unreachable("busy".to_owned())
        );
        let old = AgentState::from_list(Ok(Response::Ok(vec!["session: 1".to_owned()])));
        assert!(
            matches!(&old, AgentState::Unreachable(reason) if reason.contains("older than this version")),
            "{old:?}"
        );
    }
}
