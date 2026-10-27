use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::FormatFields;
use tracing_subscriber::fmt::format::{DefaultFields, Writer};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

use crate::ipc::{self, LogEvent, LogLevel, Response};

pub const CAPACITY: usize = 500;
pub const MAX_MESSAGE_CHARS: usize = 1000;
const ELLIPSIS: char = '\u{2026}';

#[derive(Default)]
struct Ring {
    last: u64,
    events: VecDeque<LogEvent>,
}

#[derive(Clone, Default)]
pub struct Logbook {
    ring: Arc<Mutex<Ring>>,
}

impl fmt::Debug for Logbook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Logbook").finish_non_exhaustive()
    }
}

impl Logbook {
    pub fn layer(&self) -> LogbookLayer {
        LogbookLayer { book: self.clone() }
    }

    pub fn response(&self, after: u64) -> Response {
        let ring = self
            .ring
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let events = ring
            .events
            .iter()
            .filter(|event| event.seq > after)
            .cloned();
        ipc::log_response(ring.last, events)
    }

    fn push(&self, level: LogLevel, scope: String, message: String) {
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| {
                u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
            });
        let mut ring = self
            .ring
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        ring.last += 1;
        let seq = ring.last;
        if ring.events.len() == CAPACITY {
            ring.events.pop_front();
        }
        ring.events.push_back(LogEvent {
            seq,
            time,
            level,
            scope,
            message,
        });
    }
}

pub struct LogbookLayer {
    book: Logbook,
}

struct SessionNumber(u64);

#[derive(Default)]
struct IdField(Option<u64>);

impl Visit for IdField {
    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "id" {
            self.0 = Some(value);
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        if field.name() == "id" {
            self.0 = u64::try_from(value).ok();
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "id" {
            let text = format!("{value:?}");
            self.0 = text
                .parse()
                .ok()
                .filter(|number: &u64| number.to_string() == text);
        }
    }
}

fn level(level: &Level) -> Option<LogLevel> {
    match *level {
        Level::ERROR => Some(LogLevel::Error),
        Level::WARN => Some(LogLevel::Warn),
        Level::INFO => Some(LogLevel::Info),
        _ => None,
    }
}

fn module(target: &str) -> &str {
    let module = target.strip_prefix("gateinto::").unwrap_or(target);
    match module.split("::").next() {
        Some("gateinto" | "") | None => "agent",
        Some(first) => first,
    }
}

fn capped(mut message: String) -> String {
    if let Some((cut, _)) = message.char_indices().nth(MAX_MESSAGE_CHARS) {
        message.truncate(cut);
        message.push(ELLIPSIS);
    }
    message
}

impl<S> Layer<S> for LogbookLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        if attrs.metadata().name() != "session" {
            return;
        }

        let mut field = IdField::default();
        attrs.record(&mut field);
        if let (Some(number), Some(span)) = (field.0, ctx.span(id)) {
            span.extensions_mut().insert(SessionNumber(number));
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let Some(level) = level(metadata.level()) else {
            return;
        };
        let session = ctx.event_scope(event).and_then(|scope| {
            scope
                .from_root()
                .filter_map(|span| span.extensions().get::<SessionNumber>().map(|n| n.0))
                .last()
        });
        let scope = match session {
            Some(number) => format!("session {number}"),
            None => module(metadata.target()).to_owned(),
        };
        let mut message = String::new();
        if DefaultFields::new()
            .format_fields(Writer::new(&mut message), event)
            .is_err()
        {
            return;
        }
        self.book.push(level, capped(scope), capped(message));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{LogLevel, LogPage, MAX_RESPONSE_BYTES, Response};
    use tracing::{debug, error, info, info_span, trace, warn};
    use tracing_subscriber::layer::SubscriberExt;

    fn recorded(book: &Logbook, emit: impl FnOnce()) {
        let _logs = crate::test_logs::capture();
        let subscriber = tracing_subscriber::registry().with(book.layer());
        tracing::subscriber::with_default(subscriber, emit);
    }

    fn page(book: &Logbook, after: u64) -> LogPage {
        let Response::Ok(lines) = book.response(after) else {
            panic!("a log response is ok");
        };
        LogPage::parse(&lines).unwrap()
    }

    #[test]
    fn only_info_and_more_severe_events_are_kept_in_order() {
        let book = Logbook::default();
        recorded(&book, || {
            trace!("kept out trace");
            debug!("kept out debug");
            info!("kept info");
            warn!("kept warn");
            error!("kept error");
        });
        let page = page(&book, 0);
        assert_eq!(page.last, 3);
        let kept: Vec<_> = page
            .events
            .iter()
            .map(|event| (event.seq, event.level, event.message.as_str()))
            .collect();
        assert_eq!(
            kept,
            [
                (1, LogLevel::Info, "kept info"),
                (2, LogLevel::Warn, "kept warn"),
                (3, LogLevel::Error, "kept error"),
            ]
        );
        assert!(
            page.events
                .iter()
                .all(|event| event.time > 1_600_000_000_000)
        );
    }

    #[test]
    fn a_reader_gets_only_the_events_after_its_sequence_number() {
        let book = Logbook::default();
        recorded(&book, || {
            for n in 0..4 {
                info!("numbered {n}");
            }
        });
        let page = page(&book, 2);
        assert_eq!(page.last, 4);
        let seqs: Vec<u64> = page.events.iter().map(|event| event.seq).collect();
        assert_eq!(seqs, [3, 4]);
        assert!(self::page(&book, 4).events.is_empty());
        assert!(self::page(&book, 9).events.is_empty());
    }

    #[test]
    fn the_oldest_events_are_dropped_beyond_the_capacity() {
        let book = Logbook::default();
        recorded(&book, || {
            for n in 0..CAPACITY + 10 {
                info!("bounded {n}");
            }
        });
        let mut seqs = Vec::new();
        let mut after = 0;
        loop {
            let page = page(&book, after);
            assert_eq!(page.last, CAPACITY as u64 + 10);
            let Some(event) = page.events.last() else {
                break;
            };
            after = event.seq;
            seqs.extend(page.events.iter().map(|event| event.seq));
        }
        assert_eq!(seqs, (11..=CAPACITY as u64 + 10).collect::<Vec<_>>());
    }

    #[test]
    fn long_messages_are_cut_and_still_fit_a_response() {
        let book = Logbook::default();
        let control = "\u{1}".repeat(MAX_MESSAGE_CHARS * 4);
        let wide = "\u{e9}".repeat(MAX_MESSAGE_CHARS * 4);
        recorded(&book, || {
            warn!("{control}");
            warn!("{wide}");
        });
        let page = page(&book, 0);
        assert_eq!(page.events.len(), 2);
        for event in &page.events {
            assert_eq!(event.message.chars().count(), MAX_MESSAGE_CHARS + 1);
            assert!(event.message.ends_with('\u{2026}'));
            assert!(event.to_line().len() * 8 < MAX_RESPONSE_BYTES);
        }
    }

    #[test]
    fn event_fields_follow_the_message_like_on_stderr() {
        let book = Logbook::default();
        recorded(&book, || {
            info!(gateway = "office", tunnels = 2, "session started");
        });
        assert_eq!(
            page(&book, 0).events[0].message,
            r#"session started gateway="office" tunnels=2"#
        );
    }

    #[test]
    fn a_session_span_gives_only_its_number_as_the_scope() {
        let book = Logbook::default();
        recorded(&book, || {
            let session = info_span!("session", id = 7, gateway = "span-secret-gateway");
            let _session = session.enter();
            let connection = info_span!("connection", peer = "127.0.0.1:5555");
            let _connection = connection.enter();
            info!("inside a session");
        });
        let event = &page(&book, 0).events[0];
        assert_eq!(event.scope, "session 7");
        assert_eq!(event.message, "inside a session");
        let line = event.to_line();
        assert!(!line.contains("span-secret-gateway"), "{line}");
        assert!(!line.contains("5555"), "{line}");
    }

    #[test]
    fn without_a_session_the_scope_is_the_module_that_logged() {
        let book = Logbook::default();
        recorded(&book, || {
            info!(target: "gateinto", "from the command");
            info!(target: "gateinto::agent", "from the agent");
            info!(target: "gateinto::proxy::tunnel", "from a tunnel");
            info!(target: "rustls::client", "from a library");
            let named = info_span!("session", id = "not-a-number");
            named.in_scope(|| info!(target: "gateinto::sessions", "odd session"));
        });
        let scopes: Vec<String> = page(&book, 0)
            .events
            .into_iter()
            .map(|event| event.scope)
            .collect();
        assert_eq!(scopes, ["agent", "agent", "proxy", "rustls", "sessions"]);
    }
}
