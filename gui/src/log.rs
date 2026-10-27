use std::collections::VecDeque;

use gateinto::ipc::{self, LogEvent, LogLevel, LogPage, Request, RequestError, Response};

use crate::agent::AgentState;

pub const KEPT: usize = 500;
pub const STOPPED: &str = "The agent is not running";
pub const OLDER: &str = "The running agent is older than this version of Gateinto and cannot show its log. Restart it to see its messages here.";
pub const NOTHING: &str = "No messages yet";
pub const NO_WARNINGS: &str = "No warnings";
pub const SUBTITLE: &str =
    "Messages from the running agent. Passwords and page contents are never logged.";
pub const COPY: &str = "Copy";
pub const COPIED: &str = "Copied";
pub const COPY_FAILED: &str = "Could not copy the log";

const DAY: u64 = 86_400;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Journal {
    pid: Option<u32>,
    after: u64,
    events: VecDeque<LogEvent>,
    problem: Option<String>,
    older: bool,
}

impl Journal {
    pub fn events(&self) -> &VecDeque<LogEvent> {
        &self.events
    }

    pub fn problem(&self) -> Option<&str> {
        self.problem.as_deref()
    }

    pub fn request(&self) -> Option<Request> {
        (!self.older).then_some(Request::Log { after: self.after })
    }

    pub fn reopen(&mut self) {
        if self.older {
            *self = Self::default();
        }
    }

    pub fn stopped(&mut self) {
        *self = Self::default();
    }

    pub fn absorb(&mut self, reply: Result<Response, RequestError>) -> bool {
        let lines = match reply {
            Ok(Response::Ok(lines)) => lines,
            Ok(Response::Error(message)) if message == ipc::INVALID_REQUEST => {
                *self = Self {
                    problem: Some(OLDER.to_owned()),
                    older: true,
                    ..Self::default()
                };
                return false;
            }
            Ok(Response::Error(message)) => return self.failed(message),
            Err(RequestError::NotRunning) => {
                self.stopped();
                return false;
            }
            Err(error) => return self.failed(error.to_string()),
        };
        let page = match LogPage::parse(&lines) {
            Ok(page) => page,
            Err(error) => return self.failed(error.to_string()),
        };
        let pid = ipc::agent_pid(&lines);
        if (self.pid.is_some() && pid != self.pid) || page.last < self.after {
            *self = Self {
                pid,
                ..Self::default()
            };
            return true;
        }
        self.pid = pid;
        self.problem = None;
        let before = self.after;
        for event in page.events {
            if event.seq > self.after {
                self.after = event.seq;
                self.events.push_back(event);
            }
        }
        while self.events.len() > KEPT {
            self.events.pop_front();
        }
        before < self.after && self.after < page.last
    }

    fn failed(&mut self, problem: String) -> bool {
        self.problem = Some(problem);
        false
    }
}

pub fn clock(time_ms: u64, offset: u64) -> String {
    let seconds = (time_ms / 1000 + offset) % DAY;
    format!(
        "{:02}:{:02}:{:02}",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    )
}

pub fn local_offset(local: u64, utc: u64) -> u64 {
    let difference = (local % DAY + DAY - utc % DAY) % DAY;
    (difference + 30) / 60 * 60 % DAY
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Filter {
    #[default]
    All,
    Warnings,
}

impl Filter {
    fn shows(self, level: LogLevel) -> bool {
        match self {
            Self::All => true,
            Self::Warnings => matches!(level, LogLevel::Warn | LogLevel::Error),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub time: String,
    pub level: LogLevel,
    pub scope: String,
    pub message: String,
}

impl Row {
    pub fn label(&self) -> String {
        self.level.as_str().to_ascii_uppercase()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    Rows(Vec<Row>),
    Empty(String),
}

pub fn body(state: &AgentState, journal: &Journal, filter: Filter, offset: u64) -> Body {
    match state {
        AgentState::Stopped => return Body::Empty(STOPPED.to_owned()),
        AgentState::Unreachable(error) => return Body::Empty(error.clone()),
        AgentState::Running(_) => {}
    }
    let rows: Vec<Row> = journal
        .events
        .iter()
        .filter(|event| filter.shows(event.level))
        .map(|event| Row {
            time: clock(event.time, offset),
            level: event.level,
            scope: event.scope.clone(),
            message: event.message.clone(),
        })
        .collect();
    if !rows.is_empty() {
        return Body::Rows(rows);
    }
    Body::Empty(match (journal.problem(), filter) {
        (Some(problem), _) => problem.to_owned(),
        (None, Filter::All) => NOTHING.to_owned(),
        (None, Filter::Warnings) => NO_WARNINGS.to_owned(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page {
    pub subtitle: String,
    pub alert: bool,
    pub filter: Filter,
    pub copy: Option<&'static str>,
    pub body: Body,
}

pub fn page(
    state: &AgentState,
    journal: &Journal,
    filter: Filter,
    offset: u64,
    failure: Option<&str>,
    copied: bool,
) -> Page {
    let body = body(state, journal, filter, offset);
    let rows = matches!(body, Body::Rows(_));
    let alert = failure.or(journal.problem().filter(|_| rows));
    Page {
        subtitle: alert.unwrap_or(SUBTITLE).to_owned(),
        alert: alert.is_some(),
        filter,
        copy: rows.then_some(if copied { COPIED } else { COPY }),
        body,
    }
}

pub fn text(rows: &[Row]) -> String {
    rows.iter()
        .map(|row| {
            format!(
                "{} {} {} {}\r\n",
                row.time,
                row.label(),
                row.scope,
                row.message
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use gateinto::ipc::{LogEvent, LogLevel, LogPage, RequestError, Response};

    use super::*;

    fn event(seq: u64, level: LogLevel) -> LogEvent {
        LogEvent {
            seq,
            time: 1_700_000_000_000 + seq * 1000,
            level,
            scope: "agent".to_owned(),
            message: format!("event {seq}"),
        }
    }

    fn answer(
        pid: u32,
        last: u64,
        seqs: impl IntoIterator<Item = u64>,
    ) -> Result<Response, RequestError> {
        let page = LogPage {
            last,
            events: seqs
                .into_iter()
                .map(|seq| event(seq, LogLevel::Info))
                .collect(),
        };
        let mut lines = vec![format!("agent-pid: {pid}")];
        lines.extend(page.to_lines());
        Ok(Response::Ok(lines))
    }

    fn seqs(journal: &Journal) -> Vec<u64> {
        journal.events().iter().map(|event| event.seq).collect()
    }

    #[test]
    fn a_new_journal_asks_for_everything() {
        assert_eq!(
            Journal::default().request(),
            Some(Request::Log { after: 0 })
        );
    }

    #[test]
    fn pages_are_appended_and_the_next_request_continues_after_them() {
        let mut journal = Journal::default();
        assert!(journal.absorb(answer(7, 5, [1, 2, 3])));
        assert_eq!(journal.request(), Some(Request::Log { after: 3 }));
        assert!(!journal.absorb(answer(7, 5, [4, 5])));
        assert_eq!(seqs(&journal), [1, 2, 3, 4, 5]);
        assert!(!journal.absorb(answer(7, 5, [])));
        assert_eq!(journal.request(), Some(Request::Log { after: 5 }));
        assert_eq!(journal.problem(), None);
    }

    #[test]
    fn events_already_held_are_not_added_twice() {
        let mut journal = Journal::default();
        journal.absorb(answer(7, 3, [1, 2, 3]));
        journal.absorb(answer(7, 4, [3, 4]));
        assert_eq!(seqs(&journal), [1, 2, 3, 4]);
    }

    #[test]
    fn only_the_newest_events_are_kept() {
        let mut journal = Journal::default();
        let last = KEPT as u64 + 20;
        journal.absorb(answer(7, last, 1..=last));
        assert_eq!(journal.events().len(), KEPT);
        assert_eq!(journal.events()[0].seq, 21);
    }

    #[test]
    fn a_restarted_agent_starts_the_journal_over() {
        let mut journal = Journal::default();
        journal.absorb(answer(7, 9, [8, 9]));
        assert!(journal.absorb(answer(8, 12, [10, 11, 12])));
        assert!(journal.events().is_empty());
        assert_eq!(journal.request(), Some(Request::Log { after: 0 }));
        journal.absorb(answer(8, 12, [1, 2]));
        assert_eq!(seqs(&journal), [1, 2]);

        let mut journal = Journal::default();
        journal.absorb(answer(7, 9, [8, 9]));
        assert!(journal.absorb(answer(7, 2, [])));
        assert!(journal.events().is_empty());
        assert_eq!(journal.request(), Some(Request::Log { after: 0 }));
    }

    #[test]
    fn an_older_agent_is_asked_once_until_the_page_is_opened_again() {
        let mut journal = Journal::default();
        journal.absorb(answer(7, 1, [1]));
        assert!(!journal.absorb(Ok(Response::Error("invalid request".to_owned()))));
        assert_eq!(journal.request(), None);
        assert!(journal.events().is_empty());
        assert_eq!(journal.problem(), Some(OLDER));
        journal.reopen();
        assert_eq!(journal.request(), Some(Request::Log { after: 0 }));
        assert_eq!(journal.problem(), None);
    }

    #[test]
    fn other_failures_are_shown_and_asked_again_on_the_next_poll() {
        let mut journal = Journal::default();
        journal.absorb(answer(7, 1, [1]));
        assert!(!journal.absorb(Err(RequestError::TimedOut)));
        assert_eq!(
            journal.problem(),
            Some(RequestError::TimedOut.to_string().as_str())
        );
        assert_eq!(seqs(&journal), [1]);
        assert!(!journal.absorb(Ok(Response::Ok(vec!["agent-pid: 7".to_owned()]))));
        assert!(
            journal
                .problem()
                .unwrap()
                .contains("no last sequence number")
        );
        assert_eq!(journal.request(), Some(Request::Log { after: 1 }));
        journal.absorb(answer(7, 1, []));
        assert_eq!(journal.problem(), None);
    }

    #[test]
    fn a_stopped_agent_empties_the_journal() {
        let mut journal = Journal::default();
        journal.absorb(answer(7, 1, [1]));
        assert!(!journal.absorb(Err(RequestError::NotRunning)));
        assert_eq!(journal, Journal::default());
        journal.absorb(answer(7, 1, [1]));
        journal.stopped();
        assert_eq!(journal, Journal::default());
    }

    #[test]
    fn times_are_shown_as_local_hours_minutes_and_seconds() {
        let noon = 1_700_000_000_000 - 1_700_000_000_000 % 86_400_000 + 12 * 3_600_000;
        assert_eq!(clock(noon + 61_999, 0), "12:01:01");
        assert_eq!(clock(noon, 13 * 3600 + 1800), "01:30:00");
        assert_eq!(clock(0, 0), "00:00:00");
    }

    #[test]
    fn the_local_offset_is_the_difference_of_the_clocks_to_the_minute() {
        assert_eq!(local_offset(3600 * 14 + 30, 3600 * 12 + 31), 7200);
        assert_eq!(local_offset(3600, 3600 * 23), 7200);
        assert_eq!(local_offset(3600 * 20 + 1, 3600 * 22), 22 * 3600);
        assert_eq!(local_offset(5, 5), 0);
    }

    fn running() -> AgentState {
        AgentState::Running(Vec::new())
    }

    fn mixed() -> Journal {
        let mut journal = Journal::default();
        let page = LogPage {
            last: 3,
            events: vec![
                event(1, LogLevel::Info),
                event(2, LogLevel::Warn),
                LogEvent {
                    scope: "session 4".to_owned(),
                    ..event(3, LogLevel::Error)
                },
            ],
        };
        journal.absorb(Ok(Response::Ok(page.to_lines())));
        journal
    }

    #[test]
    fn rows_show_time_level_scope_and_message_oldest_first() {
        let Body::Rows(rows) = body(&running(), &mixed(), Filter::All, 0) else {
            panic!("rows expected");
        };
        let shown: Vec<(&str, &str, &str)> = rows
            .iter()
            .map(|row| (row.level.as_str(), row.scope.as_str(), row.message.as_str()))
            .collect();
        assert_eq!(
            shown,
            [
                ("info", "agent", "event 1"),
                ("warn", "agent", "event 2"),
                ("error", "session 4", "event 3"),
            ]
        );
        assert_eq!(rows[0].time, clock(1_700_000_001_000, 0));
        assert_eq!(rows[0].label(), "INFO");
        assert_eq!(rows[2].label(), "ERROR");
    }

    #[test]
    fn the_warnings_filter_keeps_warnings_and_errors() {
        let Body::Rows(rows) = body(&running(), &mixed(), Filter::Warnings, 0) else {
            panic!("rows expected");
        };
        let levels: Vec<LogLevel> = rows.iter().map(|row| row.level).collect();
        assert_eq!(levels, [LogLevel::Warn, LogLevel::Error]);
    }

    #[test]
    fn copied_text_is_one_line_per_shown_row() {
        let Body::Rows(rows) = body(&running(), &mixed(), Filter::Warnings, 0) else {
            panic!("rows expected");
        };
        let time = clock(1_700_000_002_000, 0);
        let later = clock(1_700_000_003_000, 0);
        assert_eq!(
            text(&rows),
            format!("{time} WARN agent event 2\r\n{later} ERROR session 4 event 3\r\n")
        );
    }

    #[test]
    fn without_rows_the_page_says_why() {
        let empty =
            |state: &AgentState, journal: &Journal, filter| match body(state, journal, filter, 0) {
                Body::Empty(text) => text,
                Body::Rows(rows) => panic!("unexpected rows {rows:?}"),
            };
        assert_eq!(empty(&AgentState::Stopped, &mixed(), Filter::All), STOPPED);
        assert_eq!(
            empty(
                &AgentState::Unreachable("no pipe".to_owned()),
                &mixed(),
                Filter::All
            ),
            "no pipe"
        );
        let mut older = mixed();
        older.absorb(Ok(Response::Error("invalid request".to_owned())));
        assert_eq!(empty(&running(), &older, Filter::All), OLDER);
        assert_eq!(empty(&running(), &Journal::default(), Filter::All), NOTHING);
        let mut quiet = Journal::default();
        quiet.absorb(answer(7, 1, [1]));
        assert_eq!(empty(&running(), &quiet, Filter::Warnings), NO_WARNINGS);
    }

    #[test]
    fn a_failure_is_shown_above_the_rows_it_kept() {
        let mut journal = mixed();
        journal.absorb(Err(RequestError::TimedOut));
        assert!(
            matches!(body(&running(), &journal, Filter::All, 0), Body::Rows(rows) if rows.len() == 3)
        );
        assert!(journal.problem().is_some());
    }

    #[test]
    fn the_page_explains_what_is_logged_and_offers_to_copy_rows() {
        let shown = page(&running(), &mixed(), Filter::All, 0, None, false);
        assert_eq!(shown.subtitle, SUBTITLE);
        assert!(!shown.alert);
        assert_eq!(shown.filter, Filter::All);
        assert_eq!(shown.copy, Some(COPY));
        assert!(matches!(shown.body, Body::Rows(ref rows) if rows.len() == 3));
        let copied = page(&running(), &mixed(), Filter::Warnings, 0, None, true);
        assert_eq!(copied.copy, Some(COPIED));
        assert_eq!(copied.filter, Filter::Warnings);
    }

    #[test]
    fn nothing_to_copy_without_rows() {
        let shown = page(&AgentState::Stopped, &mixed(), Filter::All, 0, None, true);
        assert_eq!(shown.copy, None);
        assert_eq!(shown.body, Body::Empty(STOPPED.to_owned()));
        assert_eq!(shown.subtitle, SUBTITLE);
    }

    #[test]
    fn problems_with_kept_rows_and_failures_replace_the_subtitle() {
        let mut journal = mixed();
        journal.absorb(Err(RequestError::TimedOut));
        let shown = page(&running(), &journal, Filter::All, 0, None, false);
        assert_eq!(shown.subtitle, RequestError::TimedOut.to_string());
        assert!(shown.alert);
        let failed = page(
            &running(),
            &journal,
            Filter::All,
            0,
            Some("Could not copy"),
            false,
        );
        assert_eq!(failed.subtitle, "Could not copy");
        assert!(failed.alert);
        let older = {
            let mut older = mixed();
            older.absorb(Ok(Response::Error("invalid request".to_owned())));
            older
        };
        let shown = page(&running(), &older, Filter::All, 0, None, false);
        assert_eq!(shown.subtitle, SUBTITLE);
        assert_eq!(shown.body, Body::Empty(OLDER.to_owned()));
    }
}
