use std::error::Error;
use std::fmt::{self, Write as _};
use std::io::{self, Read, Write};
use std::num::{NonZeroU16, NonZeroU32};
use std::panic::{self, AssertUnwindSafe};

use aws_lc_rs::digest;

use super::firewall::{self, NetshCommand};
use super::protocol::{ErrorCode, Event, send};
use super::pump::{self, DivertPort, Liveness};
use super::{DEFAULT_CAPACITY, DEFAULT_IDLE_TIMEOUT, Dscp, Engine, decimal, filter};

pub const EXIT_NORMAL: u8 = 0;
pub const EXIT_NOT_REPORTED: u8 = 3;
pub const EXIT_REPORTED: u8 = 4;
pub const EXIT_ENGINE_FAILED: u8 = 5;

const PIPE_PREFIX: &str = r"\\.\pipe\gateinto-divert-";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipeName(String);

impl PipeName {
    pub fn parse(text: &str) -> Result<Self, InvalidArgument> {
        let digits = text.strip_prefix(PIPE_PREFIX).ok_or(InvalidArgument)?;
        let hex = digits.len() == 32
            && digits
                .bytes()
                .all(|digit| matches!(digit, b'0'..=b'9' | b'a'..=b'f'));
        hex.then(|| Self(text.to_owned())).ok_or(InvalidArgument)
    }

    pub fn from_random(bytes: [u8; 16]) -> Self {
        let mut name = PIPE_PREFIX.to_owned();
        for byte in bytes {
            let _ = write!(name, "{byte:02x}");
        }
        Self(name)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PipeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListenerPort(NonZeroU16);

impl ListenerPort {
    pub const MIN: u16 = 49152;

    pub fn new(port: u16) -> Result<Self, InvalidArgument> {
        NonZeroU16::new(port)
            .filter(|_| port >= Self::MIN)
            .map(Self)
            .ok_or(InvalidArgument)
    }

    pub fn parse(text: &str) -> Result<Self, InvalidArgument> {
        decimal(text).ok_or(InvalidArgument).and_then(Self::new)
    }

    pub fn get(self) -> NonZeroU16 {
        self.0
    }
}

impl fmt::Display for ListenerPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

fn agent_pid(text: &str) -> Result<NonZeroU32, InvalidArgument> {
    decimal(text).ok_or(InvalidArgument)
}

fn dscp(text: &str) -> Result<Dscp, InvalidArgument> {
    decimal(text)
        .and_then(|value| Dscp::new(value).ok())
        .ok_or(InvalidArgument)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidArgument;

impl fmt::Display for InvalidArgument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an argument of the divert helper is invalid")
    }
}

impl Error for InvalidArgument {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arguments<'a> {
    pub pipe: &'a str,
    pub agent_pid: &'a str,
    pub port: &'a str,
    pub dscp: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverVersion {
    pub major: u64,
    pub minor: u64,
}

pub const DRIVER_VERSION: DriverVersion = DriverVersion { major: 2, minor: 2 };

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesError {
    Missing,
    DigestMismatch,
}

impl From<FilesError> for ErrorCode {
    fn from(error: FilesError) -> Self {
        match error {
            FilesError::Missing => Self::FilesMissing,
            FilesError::DigestMismatch => Self::DigestMismatch,
        }
    }
}

pub trait Platform {
    type Pipe: Write + Send;
    type Watch: Liveness;
    type Lock;
    type Files;
    type Port: DivertPort;
    type Abandon: Abandon;

    fn connect(
        &mut self,
        pipe: &PipeName,
        agent: NonZeroU32,
    ) -> io::Result<(Self::Pipe, Self::Watch)>;
    fn lock(&mut self) -> Option<Self::Lock>;
    fn image_path(&mut self) -> Option<String>;
    fn netsh(&mut self, command: &NetshCommand) -> bool;
    fn open_files(&mut self) -> Result<Self::Files, FilesError>;
    fn open_port(&mut self, files: &Self::Files, filter: &str) -> Result<Self::Port, u32>;
    fn driver_version(&mut self, port: &Self::Port) -> Option<DriverVersion>;
    fn abandon(&mut self) -> Self::Abandon;
}

pub trait Abandon: Send {
    fn netsh(&mut self, command: &NetshCommand) -> bool;
    fn exit(self, code: u8);
}

pub fn run<P: Platform>(platform: &mut P, arguments: &Arguments<'_>) -> u8 {
    let (Ok(pipe), Ok(agent)) = (
        PipeName::parse(arguments.pipe),
        agent_pid(arguments.agent_pid),
    ) else {
        return EXIT_NOT_REPORTED;
    };
    let Ok((mut report, watch)) = platform.connect(&pipe, agent) else {
        return EXIT_NOT_REPORTED;
    };
    match serve(platform, arguments, &mut report, watch) {
        Ok(exit) => exit,
        Err(code) => match send(&mut report, &Event::Failed(code)) {
            Ok(()) => EXIT_REPORTED,
            Err(_) => EXIT_NOT_REPORTED,
        },
    }
}

fn serve<P: Platform>(
    platform: &mut P,
    arguments: &Arguments<'_>,
    report: &mut P::Pipe,
    watch: P::Watch,
) -> Result<u8, ErrorCode> {
    let (Ok(port), Ok(dscp)) = (ListenerPort::parse(arguments.port), dscp(arguments.dscp)) else {
        return Err(ErrorCode::InvalidArguments);
    };
    // Held until the rule is deleted: the next helper adds a rule of the same name.
    let _lock = platform.lock().ok_or(ErrorCode::AnotherHelper)?;
    platform.netsh(&firewall::delete_rule());
    let add = platform
        .image_path()
        .and_then(|program| firewall::add_rule(port, &program).ok())
        .ok_or(ErrorCode::FirewallRule)?;
    if !platform.netsh(&add) {
        platform.netsh(&firewall::delete_rule());
        return Err(ErrorCode::FirewallRule);
    }
    let diverted = panic::catch_unwind(AssertUnwindSafe(|| {
        divert(platform, port, dscp, report, watch)
    }))
    .unwrap_or(Ok(EXIT_ENGINE_FAILED));
    platform.netsh(&firewall::delete_rule());
    diverted
}

fn divert<P: Platform>(
    platform: &mut P,
    port: ListenerPort,
    dscp: Dscp,
    report: &mut P::Pipe,
    watch: P::Watch,
) -> Result<u8, ErrorCode> {
    let files = platform.open_files()?;
    let handle = platform
        .open_port(&files, &filter(port.get(), dscp))
        .map_err(ErrorCode::DriverLoad)?;
    if platform.driver_version(&handle) != Some(DRIVER_VERSION) {
        return Err(ErrorCode::DriverVersion);
    }
    // Held until the DLL and the driver are loaded, so neither can be swapped after its check.
    drop(files);
    if send(report, &Event::Ready).is_err() {
        return Ok(EXIT_NOT_REPORTED);
    }
    let engine = Engine::new(port.get(), DEFAULT_CAPACITY, DEFAULT_IDLE_TIMEOUT);
    let abandon = platform.abandon();
    match pump::run(&handle, engine, report, watch, move || give_up(abandon)) {
        Ok(()) => Ok(EXIT_NORMAL),
        Err(_) => Ok(EXIT_ENGINE_FAILED),
    }
}

fn give_up<A: Abandon>(mut abandon: A) {
    abandon.netsh(&firewall::delete_rule());
    abandon.exit(EXIT_ENGINE_FAILED);
}

pub fn sha256_matches(mut source: impl Read, expected: &[u8; 32]) -> bool {
    let mut context = digest::Context::new(&digest::SHA256);
    let mut buffer = [0; 8192];
    loop {
        match source.read(&mut buffer) {
            Ok(0) => return context.finish().as_ref() == expected,
            Ok(read) => context.update(&buffer[..read]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex, mpsc};
    use std::time::Instant;

    use super::*;
    use crate::divert::packet::SYN;
    use crate::divert::protocol::Snapshot;
    use crate::divert::pump::{GRACE_PERIOD, Received, RecvError};
    use crate::divert::testing::TestPacket;
    use crate::divert::{Counters, Direction};

    const PREFIX: &str = r"\\.\pipe\gateinto-divert-";

    #[test]
    fn a_pipe_name_is_the_fixed_prefix_and_32_lowercase_hex_digits() {
        let bytes = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let name = PipeName::from_random(bytes);
        assert_eq!(
            name.as_str(),
            format!("{PREFIX}0123456789abcdeffedcba9876543210")
        );
        assert_eq!(PipeName::parse(name.as_str()), Ok(name.clone()));
        assert_eq!(name.to_string(), name.as_str());
        let zero = PipeName::from_random([0; 16]);
        assert_eq!(zero.as_str(), format!("{PREFIX}{}", "0".repeat(32)));
        assert_eq!(PipeName::parse(zero.as_str()), Ok(zero));
    }

    #[test]
    fn a_pipe_name_outside_the_pattern_is_refused() {
        let digits = "0123456789abcdeffedcba9876543210";
        for refused in [
            String::new(),
            PREFIX.to_owned(),
            format!("{PREFIX}{}", digits.to_uppercase()),
            format!("{PREFIX}0123456789ABCDEFfedcba9876543210"),
            format!("{PREFIX}{}", &digits[1..]),
            format!("{PREFIX}{digits}0"),
            format!("{PREFIX}{}g", &digits[1..]),
            format!("{PREFIX}{} ", &digits[1..]),
            format!("{PREFIX}{digits}\0"),
            format!(r"\\.\pipe\gateinto-agent-{digits}"),
            format!(r"\\server\pipe\gateinto-divert-{digits}"),
            format!(r"//./pipe/gateinto-divert-{digits}"),
            format!(r"\\.\PIPE\gateinto-divert-{digits}"),
            format!(r"\\.\pipe\Gateinto-divert-{digits}"),
            format!(" {PREFIX}{digits}"),
            digits.to_owned(),
        ] {
            assert_eq!(
                PipeName::parse(&refused),
                Err(InvalidArgument),
                "{refused:?}"
            );
        }
    }

    #[test]
    fn an_agent_pid_is_a_canonical_nonzero_u32() {
        assert_eq!(agent_pid("1").map(NonZeroU32::get), Ok(1));
        assert_eq!(agent_pid("4294967295").map(NonZeroU32::get), Ok(u32::MAX));
        for refused in ["", "0", "00", "01", "+1", "-1", " 1", "1a", "4294967296"] {
            assert_eq!(agent_pid(refused), Err(InvalidArgument), "{refused:?}");
        }
    }

    #[test]
    fn a_listener_port_is_a_canonical_dynamic_port() {
        for port in [49152, 50000, 65535] {
            let parsed = ListenerPort::parse(&port.to_string()).unwrap();
            assert_eq!(parsed.get().get(), port);
            assert_eq!(parsed, ListenerPort::new(port).unwrap());
            assert_eq!(parsed.to_string(), port.to_string());
        }
        for refused in [
            "", "0", "1", "443", "49151", "65536", "+49152", "049152", "-49152", " 49152",
            "49152 ", "4915a", "port",
        ] {
            assert_eq!(
                ListenerPort::parse(refused),
                Err(InvalidArgument),
                "{refused:?}"
            );
        }
        for refused in [0, 443, 49151] {
            assert_eq!(
                ListenerPort::new(refused),
                Err(InvalidArgument),
                "{refused}"
            );
        }
    }

    #[test]
    fn a_dscp_argument_is_a_canonical_value_from_one_to_sixty_three() {
        for value in [1, 43, 63] {
            assert_eq!(dscp(&value.to_string()), Ok(Dscp::new(value).unwrap()));
        }
        for refused in ["", "0", "64", "255", "256", "+43", "043", "-1", "4 3", "x"] {
            assert_eq!(dscp(refused), Err(InvalidArgument), "{refused:?}");
        }
    }

    #[test]
    fn an_invalid_argument_has_a_fixed_message() {
        assert_eq!(
            InvalidArgument.to_string(),
            "an argument of the divert helper is invalid"
        );
    }

    #[test]
    fn a_sha256_digest_is_checked_over_the_whole_source() {
        let abc: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert!(sha256_matches(&b"abc"[..], &abc));
        assert!(!sha256_matches(&b"abd"[..], &abc));
        assert!(!sha256_matches(&b"abc\n"[..], &abc));
        let million_a: [u8; 32] = [
            0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92, 0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7,
            0x3e, 0x67, 0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e, 0x04, 0x6d, 0x39, 0xcc,
            0xc7, 0x11, 0x2c, 0xd0,
        ];
        assert!(sha256_matches(&vec![b'a'; 1_000_000][..], &million_a));
    }

    #[test]
    fn a_source_that_fails_to_read_does_not_match() {
        struct Failing(bool);

        impl Read for Failing {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if std::mem::replace(&mut self.0, true) {
                    return Err(io::Error::other("read failed"));
                }
                buffer[..3].copy_from_slice(b"abc");
                Ok(3)
            }
        }

        let abc = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b"abc");
        let abc: [u8; 32] = abc.as_ref().try_into().unwrap();
        assert!(!sha256_matches(Failing(false), &abc));
    }

    #[test]
    fn the_exit_codes_are_fixed_and_distinct() {
        assert_eq!(
            [
                EXIT_NORMAL,
                EXIT_NOT_REPORTED,
                EXIT_REPORTED,
                EXIT_ENGINE_FAILED
            ],
            [0, 3, 4, 5]
        );
    }

    type Log = Arc<Mutex<Vec<Call>>>;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        Connect(String, u32),
        Lock,
        Unlock,
        Netsh(String),
        ImagePath,
        OpenFiles,
        CloseFiles,
        OpenPort(String),
        DriverVersion,
        ClosePort,
        Write(String),
        Recv,
        Inject(u16),
        Shutdown,
        Exit(u8),
    }

    fn record(log: &Log, call: Call) {
        log.lock().unwrap().push(call);
    }

    struct FakePipe {
        log: Log,
        writes: bool,
    }

    impl Write for FakePipe {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            record(
                &self.log,
                Call::Write(String::from_utf8(bytes.to_vec()).unwrap()),
            );
            match self.writes {
                true => Ok(bytes.len()),
                false => Err(io::ErrorKind::BrokenPipe.into()),
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FakeWatch(Option<mpsc::Receiver<()>>);

    impl Liveness for FakeWatch {
        fn wait_until_gone(self) {
            if let Some(agent) = self.0 {
                let _ = agent.recv();
            }
        }
    }

    struct Closes(Log, Call);

    impl Drop for Closes {
        fn drop(&mut self) {
            record(&self.0, self.1.clone());
        }
    }

    struct FakePort {
        log: Log,
        packets: Mutex<Vec<Vec<u8>>>,
        fails: bool,
        panics: bool,
        _closes: Closes,
    }

    impl DivertPort for FakePort {
        type Address = ();

        fn recv(&self, buffer: &mut [u8]) -> Result<Received<()>, RecvError> {
            record(&self.log, Call::Recv);
            match self.packets.lock().unwrap().pop() {
                Some(packet) => {
                    buffer[..packet.len()].copy_from_slice(&packet);
                    Ok(Received {
                        length: packet.len(),
                        direction: Direction::Outbound,
                        address: (),
                    })
                }
                None if self.panics => panic!("the port failed"),
                None if self.fails => Err(RecvError::Failed(io::Error::other("failed"))),
                None => Err(RecvError::Shutdown),
            }
        }

        fn inject_inbound(&self, packet: &[u8], _: &()) -> io::Result<()> {
            record(
                &self.log,
                Call::Inject(u16::from_be_bytes([packet[22], packet[23]])),
            );
            Ok(())
        }

        fn shutdown(&self) {
            record(&self.log, Call::Shutdown);
        }
    }

    struct Fake {
        log: Log,
        connects: bool,
        free: bool,
        image_path: Option<String>,
        deletes: bool,
        adds: bool,
        files: Result<(), FilesError>,
        driver: Result<(), u32>,
        version: Option<DriverVersion>,
        writes: bool,
        agent_gone: bool,
        packets: Vec<Vec<u8>>,
        receive_fails: bool,
        receive_panics: bool,
        version_panics: bool,
        agents: Vec<mpsc::Sender<()>>,
    }

    const IMAGE: &str = r"C:\Users\Jane Doe\AppData\Local\Programs\Gateinto\gateinto.exe";
    const PINNED: DriverVersion = DRIVER_VERSION;

    impl Default for Fake {
        fn default() -> Self {
            Self {
                log: Log::default(),
                connects: true,
                free: true,
                image_path: Some(IMAGE.to_owned()),
                deletes: true,
                adds: true,
                files: Ok(()),
                driver: Ok(()),
                version: Some(PINNED),
                writes: true,
                agent_gone: false,
                packets: Vec::new(),
                receive_fails: false,
                receive_panics: false,
                version_panics: false,
                agents: Vec::new(),
            }
        }
    }

    impl Fake {
        fn calls(&self) -> Vec<Call> {
            self.log.lock().unwrap().clone()
        }

        fn written(&self) -> Vec<String> {
            self.calls()
                .into_iter()
                .filter_map(|call| match call {
                    Call::Write(line) => Some(line),
                    _ => None,
                })
                .collect()
        }
    }

    impl Platform for Fake {
        type Pipe = FakePipe;
        type Watch = FakeWatch;
        type Lock = Closes;
        type Files = Closes;
        type Port = FakePort;
        type Abandon = FakeAbandon;

        fn connect(
            &mut self,
            pipe: &PipeName,
            agent: NonZeroU32,
        ) -> io::Result<(FakePipe, FakeWatch)> {
            record(&self.log, Call::Connect(pipe.to_string(), agent.get()));
            if !self.connects {
                return Err(io::Error::other("refused"));
            }
            let watch = if self.agent_gone {
                FakeWatch(None)
            } else {
                let (agent, gone) = mpsc::channel();
                self.agents.push(agent);
                FakeWatch(Some(gone))
            };
            let pipe = FakePipe {
                log: Arc::clone(&self.log),
                writes: self.writes,
            };
            Ok((pipe, watch))
        }

        fn lock(&mut self) -> Option<Closes> {
            record(&self.log, Call::Lock);
            self.free
                .then(|| Closes(Arc::clone(&self.log), Call::Unlock))
        }

        fn image_path(&mut self) -> Option<String> {
            record(&self.log, Call::ImagePath);
            self.image_path.clone()
        }

        fn netsh(&mut self, command: &NetshCommand) -> bool {
            record(&self.log, Call::Netsh(command.as_str().to_owned()));
            match *command == firewall::delete_rule() {
                true => self.deletes,
                false => self.adds,
            }
        }

        fn open_files(&mut self) -> Result<Closes, FilesError> {
            record(&self.log, Call::OpenFiles);
            self.files
                .map(|()| Closes(Arc::clone(&self.log), Call::CloseFiles))
        }

        fn open_port(&mut self, _: &Closes, filter: &str) -> Result<FakePort, u32> {
            record(&self.log, Call::OpenPort(filter.to_owned()));
            self.driver.map(|()| FakePort {
                log: Arc::clone(&self.log),
                packets: Mutex::new(std::mem::take(&mut self.packets)),
                fails: self.receive_fails,
                panics: self.receive_panics,
                _closes: Closes(Arc::clone(&self.log), Call::ClosePort),
            })
        }

        fn driver_version(&mut self, _: &FakePort) -> Option<DriverVersion> {
            record(&self.log, Call::DriverVersion);
            assert!(!self.version_panics, "the version query failed");
            self.version
        }

        fn abandon(&mut self) -> FakeAbandon {
            FakeAbandon(Arc::clone(&self.log))
        }
    }

    struct FakeAbandon(Log);

    impl Abandon for FakeAbandon {
        fn netsh(&mut self, command: &NetshCommand) -> bool {
            record(&self.0, Call::Netsh(command.as_str().to_owned()));
            true
        }

        fn exit(self, code: u8) {
            record(&self.0, Call::Exit(code));
        }
    }

    fn pipe_name() -> String {
        PipeName::from_random([7; 16]).to_string()
    }

    const PORT: u16 = 51000;

    fn arguments<'a>(pipe: &'a str, port: &'a str, dscp: &'a str) -> Arguments<'a> {
        Arguments {
            pipe,
            agent_pid: "4242",
            port,
            dscp,
        }
    }

    fn run_fake(fake: &mut Fake) -> u8 {
        let pipe = pipe_name();
        run(fake, &arguments(&pipe, &PORT.to_string(), "43"))
    }

    fn connect() -> Call {
        Call::Connect(pipe_name(), 4242)
    }

    fn delete() -> Call {
        Call::Netsh(firewall::delete_rule().as_str().to_owned())
    }

    fn add() -> Call {
        let port = ListenerPort::new(PORT).unwrap();
        Call::Netsh(firewall::add_rule(port, IMAGE).unwrap().as_str().to_owned())
    }

    fn open_port() -> Call {
        Call::OpenPort(filter(NonZeroU16::new(PORT).unwrap(), Dscp::DEFAULT))
    }

    fn error(code: ErrorCode) -> Call {
        Call::Write(Event::Failed(code).line())
    }

    fn ready() -> Call {
        Call::Write(Event::Ready.line())
    }

    fn until_added() -> Vec<Call> {
        vec![connect(), Call::Lock, delete(), Call::ImagePath, add()]
    }

    fn joined(parts: &[&[Call]]) -> Vec<Call> {
        parts.concat()
    }

    #[test]
    fn a_run_follows_the_fixed_order_and_cleans_up_in_reverse() {
        let mut fake = Fake {
            packets: vec![TestPacket::client(SYN).build()],
            ..Fake::default()
        };
        assert_eq!(run_fake(&mut fake), EXIT_NORMAL);
        let counters = Snapshot {
            engine: Counters {
                captured: 1,
                new_flows: 1,
                reflected: 1,
                ..Counters::default()
            },
            ..Snapshot::default()
        };
        assert_eq!(
            fake.calls(),
            joined(&[
                &until_added(),
                &[
                    Call::OpenFiles,
                    open_port(),
                    Call::DriverVersion,
                    Call::CloseFiles,
                    ready(),
                    Call::Recv,
                    Call::Inject(PORT),
                    Call::Recv,
                    Call::Write(Event::Counters(counters).line()),
                    Call::ClosePort,
                    delete(),
                    Call::Unlock,
                ],
            ])
        );
    }

    #[test]
    fn a_failed_cleanup_of_a_stale_rule_is_ignored() {
        let mut fake = Fake {
            deletes: false,
            ..Fake::default()
        };
        assert_eq!(run_fake(&mut fake), EXIT_NORMAL);
        assert_eq!(fake.written(), [Event::Ready.line()]);
        assert_eq!(
            fake.calls()[fake.calls().len() - 3..],
            [Call::ClosePort, delete(), Call::Unlock]
        );
    }

    #[test]
    fn an_invalid_pipe_name_or_agent_pid_ends_the_helper_before_connecting() {
        let pipe = pipe_name();
        let mut refused = vec![
            (String::new(), "4242"),
            (pipe.to_uppercase(), "4242"),
            (pipe[..pipe.len() - 1].to_owned(), "4242"),
        ];
        for pid in ["", "0", "-1", "+4242", "04242", "4294967296", "pid"] {
            refused.push((pipe.clone(), pid));
        }
        for (pipe, agent_pid) in refused {
            let mut fake = Fake::default();
            let arguments = Arguments {
                agent_pid,
                ..arguments(&pipe, "51000", "43")
            };
            assert_eq!(run(&mut fake, &arguments), EXIT_NOT_REPORTED);
            assert_eq!(fake.calls(), [], "{pipe:?} {agent_pid:?}");
        }
    }

    #[test]
    fn a_failed_connection_ends_the_helper_without_writing() {
        let mut fake = Fake {
            connects: false,
            ..Fake::default()
        };
        assert_eq!(run_fake(&mut fake), EXIT_NOT_REPORTED);
        assert_eq!(fake.calls(), [connect()]);
    }

    #[test]
    fn an_invalid_port_or_dscp_is_reported_after_connecting() {
        let mut refused = Vec::new();
        for port in [
            "49151", "0", "65536", "", "port", "+51000", "051000", " 51000",
        ] {
            refused.push((port, "43"));
        }
        for dscp in ["0", "64", "", "x", "+43", "043", "4.3"] {
            refused.push(("51000", dscp));
        }
        for (port, dscp) in refused {
            let mut fake = Fake::default();
            let pipe = pipe_name();
            let exit = run(&mut fake, &arguments(&pipe, port, dscp));
            assert_eq!(exit, EXIT_REPORTED, "{port:?} {dscp:?}");
            assert_eq!(
                fake.calls(),
                [connect(), error(ErrorCode::InvalidArguments)],
                "{port:?} {dscp:?}"
            );
        }
    }

    #[test]
    fn another_helper_holding_the_mutex_is_reported() {
        let mut fake = Fake {
            free: false,
            ..Fake::default()
        };
        assert_eq!(run_fake(&mut fake), EXIT_REPORTED);
        assert_eq!(
            fake.calls(),
            [connect(), Call::Lock, error(ErrorCode::AnotherHelper)]
        );
    }

    #[test]
    fn a_failed_add_is_reported_after_deleting_what_it_may_have_added() {
        let mut fake = Fake {
            adds: false,
            ..Fake::default()
        };
        assert_eq!(run_fake(&mut fake), EXIT_REPORTED);
        assert_eq!(
            fake.calls(),
            joined(&[
                &until_added(),
                &[delete(), Call::Unlock, error(ErrorCode::FirewallRule)],
            ])
        );
    }

    #[test]
    fn giving_up_on_a_stuck_engine_deletes_the_rule_and_ends_the_process_as_failed() {
        let fake = Fake::default();
        give_up(FakeAbandon(Arc::clone(&fake.log)));
        assert_eq!(fake.calls(), [delete(), Call::Exit(EXIT_ENGINE_FAILED)]);
    }

    #[test]
    fn an_image_path_unfit_for_the_rule_is_a_firewall_error_before_the_add() {
        for image_path in [None, Some("gateinto.exe"), Some(r#"C:\a"b\gateinto.exe"#)] {
            let mut fake = Fake {
                image_path: image_path.map(str::to_owned),
                ..Fake::default()
            };
            assert_eq!(run_fake(&mut fake), EXIT_REPORTED);
            assert_eq!(
                fake.calls(),
                [
                    connect(),
                    Call::Lock,
                    delete(),
                    Call::ImagePath,
                    Call::Unlock,
                    error(ErrorCode::FirewallRule),
                ],
                "{image_path:?}"
            );
        }
    }

    #[test]
    fn missing_or_changed_files_are_reported_once_the_rule_is_deleted() {
        for (files, code) in [
            (FilesError::Missing, ErrorCode::FilesMissing),
            (FilesError::DigestMismatch, ErrorCode::DigestMismatch),
        ] {
            let mut fake = Fake {
                files: Err(files),
                ..Fake::default()
            };
            assert_eq!(run_fake(&mut fake), EXIT_REPORTED);
            assert_eq!(
                fake.calls(),
                joined(&[
                    &until_added(),
                    &[Call::OpenFiles, delete(), Call::Unlock, error(code)],
                ])
            );
        }
    }

    #[test]
    fn a_driver_that_does_not_load_is_reported_with_its_error() {
        let mut fake = Fake {
            driver: Err(1275),
            ..Fake::default()
        };
        assert_eq!(run_fake(&mut fake), EXIT_REPORTED);
        assert_eq!(
            fake.calls(),
            joined(&[
                &until_added(),
                &[
                    Call::OpenFiles,
                    open_port(),
                    Call::CloseFiles,
                    delete(),
                    Call::Unlock,
                    error(ErrorCode::DriverLoad(1275)),
                ],
            ])
        );
    }

    #[test]
    fn a_driver_of_another_version_is_closed_and_refused() {
        let others = [
            Some(DriverVersion { major: 2, minor: 1 }),
            Some(DriverVersion { major: 3, minor: 2 }),
            None,
        ];
        for version in others {
            let mut fake = Fake {
                version,
                ..Fake::default()
            };
            assert_eq!(run_fake(&mut fake), EXIT_REPORTED);
            assert_eq!(
                fake.calls(),
                joined(&[
                    &until_added(),
                    &[
                        Call::OpenFiles,
                        open_port(),
                        Call::DriverVersion,
                        Call::ClosePort,
                        Call::CloseFiles,
                        delete(),
                        Call::Unlock,
                        error(ErrorCode::DriverVersion),
                    ],
                ]),
                "{version:?}"
            );
        }
    }

    #[test]
    fn a_status_line_that_cannot_be_written_ends_as_unreported() {
        let mut fake = Fake {
            writes: false,
            ..Fake::default()
        };
        assert_eq!(run_fake(&mut fake), EXIT_NOT_REPORTED);
        assert_eq!(
            fake.calls(),
            joined(&[
                &until_added(),
                &[
                    Call::OpenFiles,
                    open_port(),
                    Call::DriverVersion,
                    Call::CloseFiles,
                    ready(),
                    Call::ClosePort,
                    delete(),
                    Call::Unlock,
                ],
            ])
        );
        let mut fake = Fake {
            writes: false,
            ..Fake::default()
        };
        let pipe = pipe_name();
        assert_eq!(
            run(&mut fake, &arguments(&pipe, "1", "43")),
            EXIT_NOT_REPORTED
        );
        assert_eq!(
            fake.calls(),
            [connect(), error(ErrorCode::InvalidArguments)]
        );
    }

    #[test]
    fn a_fatal_engine_error_skips_the_grace_period_and_still_deletes_the_rule() {
        let mut fake = Fake {
            receive_fails: true,
            agent_gone: true,
            ..Fake::default()
        };
        let start = Instant::now();
        assert_eq!(run_fake(&mut fake), EXIT_ENGINE_FAILED);
        assert!(start.elapsed() < GRACE_PERIOD, "{:?}", start.elapsed());
        let calls = fake.calls();
        assert!(!calls.contains(&Call::Shutdown), "{calls:?}");
        assert_eq!(
            calls[calls.len() - 3..],
            [Call::ClosePort, delete(), Call::Unlock]
        );
        assert_eq!(fake.written()[0], Event::Ready.line());
    }

    #[test]
    fn the_pinned_driver_version_is_2_2() {
        assert_eq!(DRIVER_VERSION, DriverVersion { major: 2, minor: 2 });
    }

    #[test]
    fn a_panic_in_the_engine_closes_the_handle_deletes_the_rule_and_fails() {
        let mut fake = Fake {
            receive_panics: true,
            ..Fake::default()
        };
        assert_eq!(run_fake(&mut fake), EXIT_ENGINE_FAILED);
        let calls = fake.calls();
        assert_eq!(
            calls[calls.len() - 3..],
            [Call::ClosePort, delete(), Call::Unlock]
        );
        assert_eq!(fake.written()[0], Event::Ready.line());
    }

    #[test]
    fn a_panic_after_the_rule_was_added_still_deletes_it() {
        let mut fake = Fake {
            version_panics: true,
            ..Fake::default()
        };
        assert_eq!(run_fake(&mut fake), EXIT_ENGINE_FAILED);
        assert_eq!(
            fake.calls(),
            joined(&[
                &until_added(),
                &[
                    Call::OpenFiles,
                    open_port(),
                    Call::DriverVersion,
                    Call::ClosePort,
                    Call::CloseFiles,
                    delete(),
                    Call::Unlock,
                ],
            ])
        );
    }
}
