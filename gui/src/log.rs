use std::collections::VecDeque;

use gateinto::ipc::{self, LogEvent, LogLevel, LogPage, Request, RequestError, Response};

use crate::agent::AgentState;
use crate::i18n::{Note, Text, tr};

pub const KEPT: usize = 500;
pub const STOPPED: Text = Text::AgentStopped;
pub const OLDER: Text = Text::AgentOlder;
pub const NOTHING: Text = Text::NoMessages;
pub const NO_WARNINGS: Text = Text::NoWarnings;
pub const SUBTITLE: Text = Text::LogSubtitle;
pub const COPY: Text = Text::Copy;
pub const COPIED: Text = Text::Copied;
pub const COPY_FAILED: Text = Text::CopyLogFailed;

const DAY: u64 = 86_400;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Journal {
    pid: Option<u32>,
    after: u64,
    events: VecDeque<LogEvent>,
    problem: Option<Note>,
    older: bool,
}

impl Journal {
    #[cfg(test)]
    pub fn events(&self) -> &VecDeque<LogEvent> {
        &self.events
    }

    fn shown(&self, filter: Filter) -> impl Iterator<Item = &LogEvent> {
        self.events
            .iter()
            .filter(move |event| filter.shows(event.level))
    }

    pub fn problem(&self) -> Option<&str> {
        self.problem.as_ref().map(Note::shown)
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
                    problem: Some(OLDER.into()),
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
        self.problem = Some(Note::Agent(problem));
        false
    }
}

pub fn evicted(before: &Journal, after: &Journal, filter: Filter) -> usize {
    let Some(first) = after.events.front() else {
        return 0;
    };
    if before.pid != after.pid {
        return 0;
    }
    before
        .shown(filter)
        .take_while(|event| event.seq < first.seq)
        .count()
}

pub fn kept_offset(offset: i32, evicted: usize, row_h: i32) -> i32 {
    let rows = i32::try_from(evicted).unwrap_or(i32::MAX);
    offset.saturating_sub(rows.saturating_mul(row_h)).max(0)
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
        label(self.level)
    }
}

fn label(level: LogLevel) -> String {
    level.as_str().to_ascii_uppercase()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    Rows(Vec<Row>),
    Empty(String),
}

pub fn body(state: &AgentState, journal: &Journal, filter: Filter, offset: u64) -> Body {
    match state {
        AgentState::Stopped => return Body::Empty(tr(STOPPED).to_owned()),
        AgentState::Unreachable(error) => return Body::Empty(error.clone()),
        AgentState::Running(_) => {}
    }
    let rows: Vec<Row> = journal
        .shown(filter)
        .map(|event| Row {
            time: clock(event.time, offset),
            level: event.level,
            scope: event.scope.clone(),
            message: event
                .message
                .chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .collect(),
        })
        .collect();
    if !rows.is_empty() {
        return Body::Rows(rows);
    }
    Body::Empty(match (journal.problem(), filter) {
        (Some(problem), _) => problem.to_owned(),
        (None, Filter::All) => tr(NOTHING).to_owned(),
        (None, Filter::Warnings) => tr(NO_WARNINGS).to_owned(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page<'a> {
    pub subtitle: String,
    pub alert: bool,
    pub filter: Filter,
    pub copy: Option<&'static str>,
    pub body: &'a Body,
}

pub fn page<'a>(
    journal: &Journal,
    body: &'a Body,
    filter: Filter,
    failure: Option<&str>,
    copied: bool,
) -> Page<'a> {
    let rows = matches!(body, Body::Rows(_));
    let alert = failure.or(journal.problem().filter(|_| rows));
    Page {
        subtitle: alert.unwrap_or(tr(SUBTITLE)).to_owned(),
        alert: alert.is_some(),
        filter,
        copy: rows.then(|| tr(if copied { COPIED } else { COPY })),
        body,
    }
}

pub fn text(journal: &Journal, filter: Filter, offset: u64) -> String {
    journal
        .shown(filter)
        .map(|event| {
            format!(
                "{} {} {} {}\r\n",
                clock(event.time, offset),
                label(event.level),
                event.scope,
                event.message
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
    fn rows_dropped_from_the_front_are_counted_for_the_shown_filter() {
        let full = |pid: u32, seqs: std::ops::RangeInclusive<u64>| {
            let last = *seqs.end();
            let events = seqs
                .map(|seq| match seq % 4 {
                    0 => event(seq, LogLevel::Warn),
                    _ => event(seq, LogLevel::Info),
                })
                .collect();
            let mut lines = vec![format!("agent-pid: {pid}")];
            lines.extend(LogPage { last, events }.to_lines());
            Ok(Response::Ok(lines))
        };
        let kept = KEPT as u64;
        let mut before = Journal::default();
        before.absorb(full(7, 1..=kept));
        let mut after = before.clone();
        after.absorb(full(7, kept + 1..=kept + 9));
        assert_eq!(evicted(&before, &after, Filter::All), 9);
        assert_eq!(evicted(&before, &after, Filter::Warnings), 2);
        assert_eq!(evicted(&before, &before, Filter::All), 0);
        assert_eq!(evicted(&before, &Journal::default(), Filter::All), 0);
        let mut restarted = before.clone();
        restarted.absorb(full(8, 1..=3));
        restarted.absorb(full(8, 1..=3));
        assert_eq!(seqs(&restarted), [1, 2, 3]);
        assert_eq!(evicted(&before, &restarted, Filter::All), 0);
    }

    #[test]
    fn a_view_above_the_bottom_moves_up_by_the_dropped_rows() {
        assert_eq!(kept_offset(400, 3, 24), 328);
        assert_eq!(kept_offset(400, 0, 24), 400);
        assert_eq!(kept_offset(40, 3, 24), 0);
        assert_eq!(kept_offset(i32::MAX, usize::MAX, 24), 0);
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
        assert_eq!(journal.problem(), Some(OLDER.english()));
        journal.reopen();
        assert_eq!(journal.request(), Some(Request::Log { after: 0 }));
        assert_eq!(journal.problem(), None);
    }

    #[test]
    fn only_the_gui_wording_of_a_problem_is_translated() {
        let _zh = crate::i18n::speaking(crate::i18n::Language::Chinese);
        let mut older = Journal::default();
        older.absorb(Ok(Response::Error("invalid request".to_owned())));
        assert_eq!(older.problem(), Some(tr(OLDER)));
        let mut echoed = Journal::default();
        echoed.absorb(Ok(Response::Error(OLDER.english().to_owned())));
        assert_eq!(echoed.problem(), Some(OLDER.english()));
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
    fn control_characters_are_shown_as_spaces_and_copied_as_they_were() {
        let raw = "first\nsecond\r\tthird\u{1b}[0m\u{85}end";
        let mut journal = Journal::default();
        let page = LogPage {
            last: 1,
            events: vec![LogEvent {
                message: raw.to_owned(),
                ..event(1, LogLevel::Info)
            }],
        };
        journal.absorb(Ok(Response::Ok(page.to_lines())));
        let Body::Rows(rows) = body(&running(), &journal, Filter::All, 0) else {
            panic!("rows expected");
        };
        assert_eq!(rows[0].message, "first second  third [0m end");
        let time = clock(1_700_000_001_000, 0);
        assert_eq!(
            text(&journal, Filter::All, 0),
            format!("{time} INFO agent {raw}\r\n")
        );
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
        let time = clock(1_700_000_002_000, 0);
        let later = clock(1_700_000_003_000, 0);
        assert_eq!(
            text(&mixed(), Filter::Warnings, 0),
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
        assert_eq!(
            empty(&AgentState::Stopped, &mixed(), Filter::All),
            tr(STOPPED)
        );
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
        assert_eq!(empty(&running(), &older, Filter::All), tr(OLDER));
        assert_eq!(
            empty(&running(), &Journal::default(), Filter::All),
            tr(NOTHING)
        );
        let mut quiet = Journal::default();
        quiet.absorb(answer(7, 1, [1]));
        assert_eq!(empty(&running(), &quiet, Filter::Warnings), tr(NO_WARNINGS));
    }

    #[test]
    fn the_log_page_speaks_chinese_but_agent_text_does_not() {
        let _zh = crate::i18n::speaking(crate::i18n::Language::Chinese);
        let empty =
            |state: &AgentState, journal: &Journal, filter| match body(state, journal, filter, 0) {
                Body::Empty(text) => text,
                Body::Rows(rows) => panic!("unexpected rows {rows:?}"),
            };
        assert_eq!(
            empty(&AgentState::Stopped, &mixed(), Filter::All),
            "代理程式未執行"
        );
        let mut older = mixed();
        older.absorb(Ok(Response::Error("invalid request".to_owned())));
        assert_eq!(
            empty(&running(), &older, Filter::All),
            "執行中的代理程式比這個版本的 Gateinto 舊，無法顯示記錄。請重新啟動代理程式以在此查看訊息。"
        );
        assert_eq!(
            empty(&running(), &Journal::default(), Filter::All),
            "尚無訊息"
        );
        let mut quiet = Journal::default();
        quiet.absorb(answer(7, 1, [1]));
        assert_eq!(empty(&running(), &quiet, Filter::Warnings), "沒有警告");
        let shown_body = body(&running(), &mixed(), Filter::All, 0);
        let shown = page(&mixed(), &shown_body, Filter::All, None, false);
        assert_eq!(
            shown.subtitle,
            "來自執行中代理程式的訊息。密碼與網頁內容一律不會記錄。"
        );
        assert_eq!(shown.copy, Some("複製"));
        assert_eq!(
            page(&mixed(), &shown_body, Filter::All, None, true).copy,
            Some("已複製")
        );
        let Body::Rows(rows) = shown_body else {
            panic!("no rows")
        };
        let journal = mixed();
        let original: Vec<&str> = journal
            .shown(Filter::All)
            .map(|e| e.message.as_str())
            .collect();
        let messages: Vec<&str> = rows.iter().map(|r| r.message.as_str()).collect();
        assert_eq!(messages, original);
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
        let shown_body = body(&running(), &mixed(), Filter::All, 0);
        let shown = page(&mixed(), &shown_body, Filter::All, None, false);
        assert_eq!(shown.subtitle, tr(SUBTITLE));
        assert!(!shown.alert);
        assert_eq!(shown.filter, Filter::All);
        assert_eq!(shown.copy, Some(tr(COPY)));
        assert!(matches!(shown.body, Body::Rows(rows) if rows.len() == 3));
        let copied_body = body(&running(), &mixed(), Filter::Warnings, 0);
        let copied = page(&mixed(), &copied_body, Filter::Warnings, None, true);
        assert_eq!(copied.copy, Some(tr(COPIED)));
        assert_eq!(copied.filter, Filter::Warnings);
    }

    #[test]
    fn nothing_to_copy_without_rows() {
        let shown_body = body(&AgentState::Stopped, &mixed(), Filter::All, 0);
        let shown = page(&mixed(), &shown_body, Filter::All, None, true);
        assert_eq!(shown.copy, None);
        assert_eq!(*shown.body, Body::Empty(tr(STOPPED).to_owned()));
        assert_eq!(shown.subtitle, tr(SUBTITLE));
    }

    #[test]
    fn problems_with_kept_rows_and_failures_replace_the_subtitle() {
        let mut journal = mixed();
        journal.absorb(Err(RequestError::TimedOut));
        let shown_body = body(&running(), &journal, Filter::All, 0);
        let shown = page(&journal, &shown_body, Filter::All, None, false);
        assert_eq!(shown.subtitle, RequestError::TimedOut.to_string());
        assert!(shown.alert);
        let failed_body = body(&running(), &journal, Filter::All, 0);
        let failed = page(
            &journal,
            &failed_body,
            Filter::All,
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
        let shown_body = body(&running(), &older, Filter::All, 0);
        let shown = page(&older, &shown_body, Filter::All, None, false);
        assert_eq!(shown.subtitle, tr(SUBTITLE));
        assert_eq!(*shown.body, Body::Empty(tr(OLDER).to_owned()));
    }
}
