use gateinto::ipc::{SessionInfo, SessionKind};

use crate::agent::AgentState;
use crate::i18n::{Text, fill, tr};
use crate::sessions::{self, Names};
use crate::worker::Command;

pub const CLOSE: Text = Text::CloseTerminal;
pub const STOP: Text = Text::StopAgent;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ending {
    Close(u64),
    Stop,
}

impl Ending {
    pub fn command(self) -> Command {
        match self {
            Self::Close(id) => Command::Close(id),
            Self::Stop => Command::Stop,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prompt {
    pub title: &'static str,
    pub question: String,
    pub confirm: &'static str,
}

pub fn asks(command: &Command, state: &AgentState, unlisted: u64) -> Option<Ending> {
    let ending = match command {
        Command::Close(id) => Ending::Close(*id),
        Command::Stop => Ending::Stop,
        _ => return None,
    };
    ended(state, ending, unlisted).map(|_| ending)
}

pub fn prompt(ending: Ending, state: &AgentState, names: &Names, unlisted: u64) -> Option<Prompt> {
    let (terminals, count) = ended(state, ending, unlisted)?;
    Some(match ending {
        Ending::Close(_) => {
            let row = sessions::row(terminals[0], 0, names);
            Prompt {
                title: tr(CLOSE),
                question: fill(
                    Text::CloseTerminalAsk,
                    &[&row.title, &row.number, &row.gateway],
                ),
                confirm: tr(CLOSE),
            }
        }
        Ending::Stop => Prompt {
            title: tr(STOP),
            question: match count {
                1 => tr(Text::StopTerminalAsk).to_owned(),
                count => fill(Text::StopTerminalsAsk, &[&count]),
            },
            confirm: tr(STOP),
        },
    })
}

fn ended(state: &AgentState, ending: Ending, unlisted: u64) -> Option<(Vec<&SessionInfo>, u64)> {
    let AgentState::Running(sessions) = state else {
        return None;
    };
    let terminals: Vec<&SessionInfo> = sessions
        .iter()
        .filter(|s| s.kind == SessionKind::Terminal)
        .filter(|s| match ending {
            Ending::Close(id) => s.id == id,
            Ending::Stop => true,
        })
        .collect();
    let count = match ending {
        Ending::Close(_) => terminals.len() as u64,
        Ending::Stop => terminals.len() as u64 + unlisted,
    };
    (count > 0).then_some((terminals, count))
}

#[cfg(test)]
mod tests {
    use gateinto::ipc::{SessionAuth, SessionRoute};

    use super::*;
    use crate::i18n::{Language, Note, speaking};

    fn session(id: u64, kind: SessionKind, shell: Option<&str>) -> SessionInfo {
        SessionInfo {
            id,
            kind,
            gateway: "office".to_owned(),
            upstream: "proxy.example.com:8443".to_owned(),
            listen: "127.0.0.1:8080".parse().unwrap(),
            route: SessionRoute::All,
            auth: SessionAuth::OsUser,
            started: 1_000,
            tunnels: 0,
            browser: None,
            shell: shell.map(str::to_owned),
            verification: false,
        }
    }

    fn running(terminals: u64) -> AgentState {
        let mut sessions = vec![session(1, SessionKind::Browser, None)];
        for id in 0..terminals {
            sessions.push(session(10 + id, SessionKind::Terminal, Some("pwsh.exe")));
        }
        AgentState::Running(sessions)
    }

    fn launch() -> Command {
        Command::Launch("office".parse().unwrap())
    }

    #[test]
    fn closing_a_terminal_asks_and_closing_a_browser_does_not() {
        let state = running(1);
        assert_eq!(
            asks(&Command::Close(10), &state, 0),
            Some(Ending::Close(10))
        );
        assert_eq!(asks(&Command::Close(1), &state, 0), None);
        assert_eq!(asks(&Command::Close(99), &state, 0), None);
        assert_eq!(asks(&Command::Close(10), &AgentState::Stopped, 0), None);
    }

    #[test]
    fn stop_asks_only_while_the_last_list_has_a_terminal() {
        assert_eq!(asks(&Command::Stop, &running(1), 0), Some(Ending::Stop));
        assert_eq!(asks(&Command::Stop, &running(3), 0), Some(Ending::Stop));
        assert_eq!(asks(&Command::Stop, &running(0), 0), None);
        assert_eq!(asks(&Command::Stop, &AgentState::Stopped, 0), None);
        let unreachable = AgentState::Unreachable(Note::Agent("x".to_owned()));
        assert_eq!(asks(&Command::Stop, &unreachable, 0), None);
    }

    #[test]
    fn stop_also_counts_terminals_the_last_list_does_not_show_yet() {
        let names = Names::default();
        assert_eq!(asks(&Command::Stop, &running(0), 1), Some(Ending::Stop));
        assert_eq!(asks(&Command::Stop, &AgentState::Stopped, 1), None);
        assert_eq!(asks(&Command::Close(10), &running(0), 1), None);
        let one = prompt(Ending::Stop, &running(0), &names, 1).unwrap();
        assert!(
            one.question.contains("1 terminal session is open"),
            "{one:?}"
        );
        let three = prompt(Ending::Stop, &running(2), &names, 1).unwrap();
        assert!(
            three.question.contains("3 terminal sessions are open"),
            "{three:?}"
        );
        assert_eq!(prompt(Ending::Stop, &AgentState::Stopped, &names, 1), None);
    }

    #[test]
    fn other_commands_never_ask() {
        let state = running(2);
        for command in [
            launch(),
            Command::Terminal("office".parse().unwrap()),
            Command::Start,
            Command::Probe,
        ] {
            assert_eq!(asks(&command, &state, 0), None, "{command:?}");
        }
    }

    #[test]
    fn a_confirmed_ending_sends_its_own_command() {
        assert_eq!(Ending::Close(10).command(), Command::Close(10));
        assert_eq!(Ending::Stop.command(), Command::Stop);
    }

    #[test]
    fn the_close_prompt_names_the_shell_and_the_gateway() {
        let prompt = prompt(Ending::Close(10), &running(1), &Names::default(), 0).unwrap();
        assert_eq!(prompt.title, "Close terminal");
        assert_eq!(prompt.confirm, "Close terminal");
        assert_eq!(
            prompt.question,
            "Close pwsh.exe #10 on office? Its shell and everything \
             started from it end, and unsaved work there is lost."
        );
    }

    #[test]
    fn the_stop_prompt_counts_the_terminals() {
        let one = prompt(Ending::Stop, &running(1), &Names::default(), 0).unwrap();
        assert_eq!(one.title, "Stop agent");
        assert_eq!(one.confirm, "Stop agent");
        assert!(
            one.question.contains("1 terminal session is open"),
            "{one:?}"
        );
        let three = prompt(Ending::Stop, &running(3), &Names::default(), 0).unwrap();
        assert!(
            three.question.contains("3 terminal sessions are open"),
            "{three:?}"
        );
    }

    #[test]
    fn a_prompt_whose_target_is_gone_is_dropped() {
        let names = Names::default();
        assert_eq!(prompt(Ending::Close(10), &running(0), &names, 0), None);
        assert_eq!(prompt(Ending::Close(1), &running(1), &names, 0), None);
        assert_eq!(prompt(Ending::Stop, &running(0), &names, 0), None);
        assert_eq!(prompt(Ending::Stop, &AgentState::Stopped, &names, 0), None);
        assert_eq!(
            prompt(Ending::Close(10), &AgentState::Stopped, &names, 0),
            None
        );
    }

    #[test]
    fn both_prompts_speak_chinese() {
        let _zh = speaking(Language::Chinese);
        let close = prompt(Ending::Close(10), &running(1), &Names::default(), 0).unwrap();
        assert_eq!(close.title, "關閉終端機");
        assert!(
            close
                .question
                .starts_with("要關閉「office」上的 pwsh.exe #10 嗎？"),
            "{close:?}"
        );
        let stop = prompt(Ending::Stop, &running(2), &Names::default(), 0).unwrap();
        assert_eq!(stop.confirm, tr(STOP));
        assert!(
            stop.question.contains("目前有 2 個終端機工作階段"),
            "{stop:?}"
        );
    }
}
