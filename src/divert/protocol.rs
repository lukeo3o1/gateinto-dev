use std::error::Error;
use std::fmt::{self, Write as _};
use std::io::{self, Write};
use std::mem;

use super::{Counters, decimal};

pub const MAX_LINE_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub engine: Counters,
    pub receive_errors: u64,
    pub send_errors: u64,
}

impl Snapshot {
    fn fields(&mut self) -> [(&'static str, &mut u64); 18] {
        let Self {
            engine:
                Counters {
                    captured,
                    new_flows,
                    reflected,
                    replies_restored,
                    syn_retransmits,
                    orphans_dropped,
                    key_collisions,
                    unknown_replies_dropped,
                    fragments_dropped,
                    malformed_dropped,
                    options_dropped,
                    table_full,
                    contained_udp,
                    contained_other,
                    contained_ipv6,
                    inbound_dropped,
                },
            receive_errors,
            send_errors,
        } = self;
        [
            ("captured", captured),
            ("new_flows", new_flows),
            ("reflected", reflected),
            ("replies_restored", replies_restored),
            ("syn_retransmits", syn_retransmits),
            ("orphans_dropped", orphans_dropped),
            ("key_collisions", key_collisions),
            ("unknown_replies_dropped", unknown_replies_dropped),
            ("fragments_dropped", fragments_dropped),
            ("malformed_dropped", malformed_dropped),
            ("options_dropped", options_dropped),
            ("table_full", table_full),
            ("contained_udp", contained_udp),
            ("contained_other", contained_other),
            ("contained_ipv6", contained_ipv6),
            ("inbound_dropped", inbound_dropped),
            ("receive_errors", receive_errors),
            ("send_errors", send_errors),
        ]
    }

    fn parse(text: &str) -> Option<Self> {
        let mut snapshot = Self::default();
        let mut tokens = text.split(' ');
        if tokens.next() != Some("") {
            return None;
        }
        for (name, value) in snapshot.fields() {
            let (key, number) = tokens.next()?.split_once('=')?;
            if key != name {
                return None;
            }
            *value = decimal(number)?;
        }
        tokens.next().is_none().then_some(snapshot)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidArguments,
    AnotherHelper,
    FirewallRule,
    FilesMissing,
    DigestMismatch,
    DriverLoad(u32),
    DriverVersion,
}

impl ErrorCode {
    const NAMED: [Self; 6] = [
        Self::InvalidArguments,
        Self::AnotherHelper,
        Self::FirewallRule,
        Self::FilesMissing,
        Self::DigestMismatch,
        Self::DriverVersion,
    ];

    fn parse(text: &str) -> Option<Self> {
        match text.strip_prefix("driver-load ") {
            Some(error) => decimal(error).map(Self::DriverLoad),
            None => Self::NAMED
                .into_iter()
                .find(|code| code.to_string() == text),
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidArguments => "invalid-arguments",
            Self::AnotherHelper => "another-helper",
            Self::FirewallRule => "firewall-rule",
            Self::FilesMissing => "files-missing",
            Self::DigestMismatch => "digest-mismatch",
            Self::DriverLoad(error) => return write!(f, "driver-load {error}"),
            Self::DriverVersion => "driver-version",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Ready,
    Failed(ErrorCode),
    Counters(Snapshot),
}

impl Event {
    pub fn line(&self) -> String {
        let mut line = match self {
            Self::Ready => "ready".to_owned(),
            Self::Failed(code) => format!("error {code}"),
            Self::Counters(snapshot) => {
                let mut line = "counters".to_owned();
                for (name, value) in { *snapshot }.fields() {
                    let _ = write!(line, " {name}={value}");
                }
                line
            }
        };
        line.push('\n');
        line
    }

    fn parse(line: &str) -> Result<Self, ProtocolError> {
        if line == "ready" {
            Ok(Self::Ready)
        } else if let Some(code) = line.strip_prefix("error ") {
            ErrorCode::parse(code)
                .map(Self::Failed)
                .ok_or(ProtocolError::UnknownLine)
        } else if let Some(fields) = line.strip_prefix("counters") {
            Snapshot::parse(fields)
                .map(Self::Counters)
                .ok_or(ProtocolError::InvalidCounters)
        } else {
            Err(ProtocolError::UnknownLine)
        }
    }
}

pub(super) fn send(report: &mut impl Write, event: &Event) -> io::Result<()> {
    report.write_all(event.line().as_bytes())?;
    report.flush()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    LineTooLong,
    UnfinishedLine,
    InvalidCharacter,
    EmptyLine,
    UnknownLine,
    InvalidCounters,
    CountersBeforeReady,
    SecondStatus,
    LineAfterError,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::LineTooLong => "the divert helper sent a line that is too long",
            Self::UnfinishedLine => "the divert helper ended inside a line",
            Self::InvalidCharacter => "the divert helper sent a byte outside printable ASCII",
            Self::EmptyLine => "the divert helper sent an empty line",
            Self::UnknownLine => "the divert helper sent an unknown line",
            Self::InvalidCounters => "the divert helper sent an invalid counter line",
            Self::CountersBeforeReady => "the divert helper sent counters before ready",
            Self::SecondStatus => "the divert helper sent a second status line",
            Self::LineAfterError => "the divert helper sent a line after its error",
        })
    }
}

impl Error for ProtocolError {}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Status {
    #[default]
    Waiting,
    Ready,
    Failed,
}

#[derive(Debug, Default)]
pub struct StatusReader {
    pending: Vec<u8>,
    status: Status,
    broken: Option<ProtocolError>,
}

impl StatusReader {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Event>, ProtocolError> {
        let read = self.read(bytes);
        if let Err(error) = read {
            self.broken = Some(error);
        }
        read
    }

    pub fn finish(&self) -> Result<(), ProtocolError> {
        match self.broken {
            Some(error) => Err(error),
            None if self.pending.is_empty() => Ok(()),
            None => Err(ProtocolError::UnfinishedLine),
        }
    }

    fn read(&mut self, bytes: &[u8]) -> Result<Vec<Event>, ProtocolError> {
        if let Some(error) = self.broken {
            return Err(error);
        }
        let mut events = Vec::new();
        for &byte in bytes {
            match byte {
                b'\n' => {
                    let line = mem::take(&mut self.pending);
                    events.push(self.line(&line)?);
                }
                b' '..=b'~' if self.pending.len() + 1 < MAX_LINE_BYTES => self.pending.push(byte),
                b' '..=b'~' => return Err(ProtocolError::LineTooLong),
                _ => return Err(ProtocolError::InvalidCharacter),
            }
        }
        Ok(events)
    }

    fn line(&mut self, line: &[u8]) -> Result<Event, ProtocolError> {
        if line.is_empty() {
            return Err(ProtocolError::EmptyLine);
        }
        let line = std::str::from_utf8(line).map_err(|_| ProtocolError::InvalidCharacter)?;
        let event = Event::parse(line)?;
        self.status = match (self.status, &event) {
            (Status::Failed, _) => return Err(ProtocolError::LineAfterError),
            (Status::Waiting, Event::Ready) => Status::Ready,
            (Status::Waiting, Event::Failed(_)) => Status::Failed,
            (Status::Waiting, Event::Counters(_)) => {
                return Err(ProtocolError::CountersBeforeReady);
            }
            (Status::Ready, Event::Counters(_)) => Status::Ready,
            (Status::Ready, _) => return Err(ProtocolError::SecondStatus),
        };
        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::divert::Counters;

    fn numbered() -> Snapshot {
        Snapshot {
            engine: Counters {
                captured: 1,
                new_flows: 2,
                reflected: 3,
                replies_restored: 4,
                syn_retransmits: 5,
                orphans_dropped: 6,
                key_collisions: 7,
                unknown_replies_dropped: 8,
                fragments_dropped: 9,
                malformed_dropped: 10,
                options_dropped: 11,
                table_full: 12,
                contained_udp: 13,
                contained_other: 14,
                contained_ipv6: 15,
                inbound_dropped: 16,
            },
            receive_errors: 17,
            send_errors: 18,
        }
    }

    const NUMBERED: &str = "counters captured=1 new_flows=2 reflected=3 replies_restored=4 \
        syn_retransmits=5 orphans_dropped=6 key_collisions=7 unknown_replies_dropped=8 \
        fragments_dropped=9 malformed_dropped=10 options_dropped=11 table_full=12 \
        contained_udp=13 contained_other=14 contained_ipv6=15 inbound_dropped=16 \
        receive_errors=17 send_errors=18\n";

    fn read(input: &[u8]) -> Result<Vec<Event>, ProtocolError> {
        let mut reader = StatusReader::new();
        let events = reader.push(input)?;
        reader.finish()?;
        Ok(events)
    }

    fn after_ready(line: &str) -> Result<Vec<Event>, ProtocolError> {
        read(format!("ready\n{line}").as_bytes())
    }

    const CODES: [(ErrorCode, &str); 8] = [
        (ErrorCode::InvalidArguments, "invalid-arguments"),
        (ErrorCode::AnotherHelper, "another-helper"),
        (ErrorCode::FirewallRule, "firewall-rule"),
        (ErrorCode::FilesMissing, "files-missing"),
        (ErrorCode::DigestMismatch, "digest-mismatch"),
        (ErrorCode::DriverLoad(0), "driver-load 0"),
        (ErrorCode::DriverLoad(u32::MAX), "driver-load 4294967295"),
        (ErrorCode::DriverVersion, "driver-version"),
    ];

    #[test]
    fn status_lines_are_ready_or_one_error_code_from_the_fixed_list() {
        assert_eq!(Event::Ready.line(), "ready\n");
        assert_eq!(read(b"ready\n"), Ok(vec![Event::Ready]));
        for (code, text) in CODES {
            let line = format!("error {text}\n");
            assert_eq!(Event::Failed(code).line(), line);
            assert_eq!(code.to_string(), text);
            assert_eq!(read(line.as_bytes()), Ok(vec![Event::Failed(code)]));
        }
    }

    #[test]
    fn a_counter_line_names_every_field_in_struct_order() {
        assert_eq!(Event::Counters(numbered()).line(), NUMBERED);
        assert_eq!(
            after_ready(NUMBERED),
            Ok(vec![Event::Ready, Event::Counters(numbered())])
        );
        assert_eq!(
            after_ready(&Event::Counters(Snapshot::default()).line()),
            Ok(vec![Event::Ready, Event::Counters(Snapshot::default())])
        );
    }

    #[test]
    fn unknown_lines_and_error_codes_are_refused() {
        for line in [
            "Ready",
            "ready ",
            " ready",
            "ok",
            "error",
            "error ",
            "error unknown",
            "error invalid-arguments ",
            "error  invalid-arguments",
            "error driver-load",
            "error driver-load ",
            "error driver-load +5",
            "error driver-load 05",
            "error driver-load 4294967296",
            "error driver-version 2",
        ] {
            assert_eq!(
                read(format!("{line}\n").as_bytes()),
                Err(ProtocolError::UnknownLine),
                "{line:?}"
            );
        }
    }

    #[test]
    fn exactly_one_status_line_comes_first() {
        for input in ["ready\nready\n", "ready\nerror firewall-rule\n"] {
            assert_eq!(
                read(input.as_bytes()),
                Err(ProtocolError::SecondStatus),
                "{input:?}"
            );
        }
        for second in ["ready\n", "error firewall-rule\n", NUMBERED] {
            let input = format!("error another-helper\n{second}");
            assert_eq!(
                read(input.as_bytes()),
                Err(ProtocolError::LineAfterError),
                "{input:?}"
            );
        }
        assert_eq!(
            read(NUMBERED.as_bytes()),
            Err(ProtocolError::CountersBeforeReady)
        );
    }

    #[test]
    fn a_counter_line_with_other_fields_is_refused() {
        let line = NUMBERED.trim_end();
        let swapped = line.replace("captured=1 new_flows=2", "new_flows=2 captured=1");
        for changed in [
            line.replace("table_full=12", "table_fill=12"),
            line.replace(" send_errors=18", ""),
            line.replace("counters captured=1 ", "counters "),
            swapped,
            line.replace("new_flows=2", "captured=1"),
            format!("{line} send_errors=18"),
            format!("{line} "),
            line.replace(" reflected", "  reflected"),
            line.replace("counters ", "counters  "),
            line.replace("=3 ", "= 3 "),
            line.replace("reflected=3", "reflected"),
            line.replace("reflected=3", "reflected==3"),
            "counters".to_owned(),
            "counters ".to_owned(),
        ] {
            assert_eq!(
                after_ready(&format!("{changed}\n")),
                Err(ProtocolError::InvalidCounters),
                "{changed:?}"
            );
        }
    }

    #[test]
    fn a_counter_value_is_a_canonical_u64() {
        let line = NUMBERED.trim_end();
        for value in [
            "",
            "+12",
            "-12",
            "012",
            "00",
            "1a",
            "0x1",
            "1.0",
            "18446744073709551616",
        ] {
            let changed = line.replace("table_full=12", &format!("table_full={value}"));
            assert_eq!(
                after_ready(&format!("{changed}\n")),
                Err(ProtocolError::InvalidCounters),
                "{value:?}"
            );
        }
    }

    #[test]
    fn every_byte_outside_printable_ascii_is_refused() {
        for input in [
            &b"ready\r\n"[..],
            b"\rready\n",
            b"ready\0\n",
            b"\tready\n",
            b"read\x7f\n",
            "r\u{e9}ady\n".as_bytes(),
            b"ready\xff\n",
        ] {
            assert_eq!(
                read(input),
                Err(ProtocolError::InvalidCharacter),
                "{input:?}"
            );
        }
    }

    #[test]
    fn an_empty_line_is_refused() {
        assert_eq!(read(b"\n"), Err(ProtocolError::EmptyLine));
        assert_eq!(read(b"ready\n\n"), Err(ProtocolError::EmptyLine));
    }

    #[test]
    fn the_end_of_the_stream_inside_a_line_is_refused() {
        assert_eq!(read(b"ready"), Err(ProtocolError::UnfinishedLine));
        assert_eq!(
            read(NUMBERED.trim_end().as_bytes()),
            Err(ProtocolError::UnfinishedLine)
        );
        assert_eq!(read(b""), Ok(Vec::new()));
        assert_eq!(read(b"ready\n"), Ok(vec![Event::Ready]));
    }

    #[test]
    fn the_longest_valid_line_fits_and_a_longer_one_is_refused_before_its_end() {
        let largest = Snapshot {
            engine: Counters {
                captured: u64::MAX,
                new_flows: u64::MAX,
                reflected: u64::MAX,
                replies_restored: u64::MAX,
                syn_retransmits: u64::MAX,
                orphans_dropped: u64::MAX,
                key_collisions: u64::MAX,
                unknown_replies_dropped: u64::MAX,
                fragments_dropped: u64::MAX,
                malformed_dropped: u64::MAX,
                options_dropped: u64::MAX,
                table_full: u64::MAX,
                contained_udp: u64::MAX,
                contained_other: u64::MAX,
                contained_ipv6: u64::MAX,
                inbound_dropped: u64::MAX,
            },
            receive_errors: u64::MAX,
            send_errors: u64::MAX,
        };
        let line = Event::Counters(largest).line();
        assert!(line.len() <= MAX_LINE_BYTES, "{}", line.len());
        assert_eq!(
            after_ready(&line),
            Ok(vec![Event::Ready, Event::Counters(largest)])
        );
        let longest = format!("{}\n", "a".repeat(MAX_LINE_BYTES - 1));
        assert_eq!(read(longest.as_bytes()), Err(ProtocolError::UnknownLine));
        let mut reader = StatusReader::new();
        assert_eq!(
            reader.push("a".repeat(MAX_LINE_BYTES).as_bytes()),
            Err(ProtocolError::LineTooLong)
        );
    }

    #[test]
    fn a_reader_stays_broken_after_an_error() {
        let mut reader = StatusReader::new();
        assert_eq!(reader.push(b"\n"), Err(ProtocolError::EmptyLine));
        assert_eq!(reader.push(b"ready\n"), Err(ProtocolError::EmptyLine));
        assert_eq!(reader.finish(), Err(ProtocolError::EmptyLine));
    }

    #[test]
    fn lines_split_across_pushes_are_joined() {
        let mut reader = StatusReader::new();
        assert_eq!(reader.push(b"rea"), Ok(Vec::new()));
        assert_eq!(reader.push(b"dy\ncounters"), Ok(vec![Event::Ready]));
        assert_eq!(
            reader.push(&NUMBERED.as_bytes()["counters".len()..]),
            Ok(vec![Event::Counters(numbered())])
        );
        assert_eq!(reader.finish(), Ok(()));
    }

    struct Random(u64);

    impl Random {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut value = self.0;
            value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            value ^ (value >> 31)
        }

        fn value(&mut self) -> u64 {
            let edges = [0, 1, 9, 10, 99, 100, u64::MAX - 1, u64::MAX];
            match self.next() % 4 {
                0 => edges[(self.next() % 8) as usize],
                1 => self.next() % 1000,
                2 => self.next() >> (self.next() % 64),
                _ => self.next(),
            }
        }

        fn snapshot(&mut self) -> Snapshot {
            let mut snapshot = Snapshot::default();
            for (_, value) in snapshot.fields() {
                *value = self.value();
            }
            snapshot
        }
    }

    #[test]
    fn encoded_events_read_back_unchanged_however_they_are_split() {
        let mut random = Random(43);
        for _ in 0..200 {
            let mut events = vec![Event::Ready];
            events.extend((0..20).map(|_| Event::Counters(random.snapshot())));
            let stream: String = events.iter().map(Event::line).collect();
            let mut reader = StatusReader::new();
            let mut read = Vec::new();
            let mut rest = stream.as_bytes();
            while !rest.is_empty() {
                let length = (random.next() % 700) as usize;
                let (chunk, tail) = rest.split_at(length.min(rest.len()));
                read.extend(reader.push(chunk).unwrap());
                rest = tail;
            }
            reader.finish().unwrap();
            assert_eq!(read, events);
        }
        for _ in 0..1000 {
            let code = ErrorCode::DriverLoad(random.next() as u32);
            assert_eq!(
                read(Event::Failed(code).line().as_bytes()),
                Ok(vec![Event::Failed(code)])
            );
        }
    }

    #[test]
    fn protocol_errors_have_fixed_messages() {
        assert_eq!(
            ProtocolError::SecondStatus.to_string(),
            "the divert helper sent a second status line"
        );
        assert_eq!(
            ProtocolError::LineTooLong.to_string(),
            "the divert helper sent a line that is too long"
        );
    }
}
