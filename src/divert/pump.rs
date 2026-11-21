use std::cell::Cell;
use std::io::{self, Write};
use std::panic::{self, AssertUnwindSafe};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use super::protocol::{Event, Snapshot, send};
use super::{Direction, Engine, Verdict};

pub const PACKET_BUFFER_BYTES: usize = 40 + 0xFFFF;
pub const REPORT_INTERVAL: Duration = Duration::from_secs(10);
pub const GRACE_PERIOD: Duration = Duration::from_secs(5);
pub const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);
const STOP_ACK_TIMEOUT: Duration = Duration::from_secs(25);

pub struct Received<A> {
    pub length: usize,
    pub direction: Direction,
    pub address: A,
}

#[derive(Debug)]
pub enum RecvError {
    Shutdown,
    Failed(io::Error),
}

pub trait DivertPort: Sync {
    type Address;

    fn recv(&self, buffer: &mut [u8]) -> Result<Received<Self::Address>, RecvError>;
    fn inject_inbound(&self, packet: &[u8], address: &Self::Address) -> io::Result<()>;
    // Sticky: once called, every later `recv` returns `RecvError::Shutdown` after the queued packets.
    fn shutdown(&self);
}

pub trait Liveness: Send + 'static {
    fn wait_until_gone(self);
}

pub fn run<P, W, L, S>(
    port: &P,
    engine: Engine,
    report: &mut W,
    liveness: L,
    stuck: S,
) -> io::Result<()>
where
    P: DivertPort,
    W: Write + Send,
    L: Liveness,
    S: FnOnce() + Send,
{
    run_with(port, engine, report, liveness, stuck, &SystemClock)
}

#[derive(Default)]
struct State {
    snapshot: Snapshot,
    gone: bool,
    ended: bool,
}

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    changed: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn signal(&self, change: impl FnOnce(&mut State)) {
        change(&mut self.lock());
        self.changed.notify_all();
    }

    fn ends_within<C: Clock>(&self, clock: &C, limit: Duration) -> bool {
        let deadline = clock.now() + limit;
        let mut state = self.lock();
        loop {
            if state.ended {
                return true;
            }
            if clock.now() >= deadline {
                return false;
            }
            state = clock.wait_until(&self.changed, state, deadline);
        }
    }

    fn wait_for_agent_to_close<C: Clock>(&self, clock: &C) {
        let deadline = clock.now() + STOP_ACK_TIMEOUT;
        let mut state = self.lock();
        while !state.gone && clock.now() < deadline {
            state = clock.wait_until(&self.changed, state, deadline);
        }
    }
}

trait Clock: Sync {
    fn now(&self) -> Instant;
    fn wait_until<'a>(
        &self,
        changed: &Condvar,
        state: MutexGuard<'a, State>,
        deadline: Instant,
    ) -> MutexGuard<'a, State>;
}

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn wait_until<'a>(
        &self,
        changed: &Condvar,
        state: MutexGuard<'a, State>,
        deadline: Instant,
    ) -> MutexGuard<'a, State> {
        let timeout = deadline.saturating_duration_since(Instant::now());
        changed
            .wait_timeout(state, timeout)
            .unwrap_or_else(PoisonError::into_inner)
            .0
    }
}

fn run_with<P, W, L, S, C>(
    port: &P,
    engine: Engine,
    report: &mut W,
    liveness: L,
    stuck: S,
    clock: &C,
) -> io::Result<()>
where
    P: DivertPort,
    W: Write + Send,
    L: Liveness,
    S: FnOnce() + Send,
    C: Clock,
{
    let shared = Arc::new(Shared::default());
    let watcher = Arc::clone(&shared);
    // Not joined: the wait cannot be interrupted, and the helper exits once the pump returns.
    let watching = thread::Builder::new().spawn(move || {
        let _gone = OnDrop(|| watcher.signal(|state| state.gone = true));
        liveness.wait_until_gone();
    });
    let shared = &*shared;
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        watching?;
        thread::scope(|scope| {
            let report = &mut *report;
            thread::Builder::new()
                .spawn_scoped(scope, move || supervise(shared, port, report, stuck, clock))?;
            let _ended = OnDrop(|| shared.signal(|state| state.ended = true));
            forward(port, engine, shared, clock)
        })
    }));
    if !matches!(outcome, Ok(Ok(())))
        && !shared.lock().gone
        && panic::catch_unwind(AssertUnwindSafe(|| send(report, &Event::Stopping))).is_ok()
    {
        shared.wait_for_agent_to_close(clock);
    }
    outcome.unwrap_or_else(|panic| panic::resume_unwind(panic))
}

struct OnDrop<F: FnMut()>(F);

impl<F: FnMut()> Drop for OnDrop<F> {
    fn drop(&mut self) {
        (self.0)();
    }
}

fn forward<P: DivertPort, C: Clock>(
    port: &P,
    mut engine: Engine,
    shared: &Shared,
    clock: &C,
) -> io::Result<()> {
    let mut buffer = vec![0; PACKET_BUFFER_BYTES];
    let mut snapshot = Snapshot::default();
    let failure = loop {
        let received = match port.recv(&mut buffer) {
            Ok(received) => received,
            Err(RecvError::Shutdown) => return Ok(()),
            Err(RecvError::Failed(error)) => break error,
        };
        let Some(packet) = buffer.get_mut(..received.length) else {
            break io::Error::new(
                io::ErrorKind::InvalidData,
                "the received length exceeds the buffer",
            );
        };
        let verdict = engine.process(packet, received.direction, clock.now());
        if verdict == Verdict::InjectInbound
            && port.inject_inbound(packet, &received.address).is_err()
        {
            snapshot.send_errors += 1;
        }
        snapshot.engine = engine.counters();
        shared.lock().snapshot = snapshot;
    };
    snapshot.receive_errors += 1;
    shared.lock().snapshot = snapshot;
    Err(failure)
}

fn supervise<P: DivertPort, W: Write, S: FnOnce(), C: Clock>(
    shared: &Shared,
    port: &P,
    report: &mut W,
    stuck: S,
    clock: &C,
) {
    let stuck = Cell::new(Some(stuck));
    let shut_down = || {
        port.shutdown();
        if !shared.ends_within(clock, SHUTDOWN_DEADLINE)
            && let Some(stuck) = stuck.take()
        {
            stuck();
        }
    };
    let _shutdown = OnDrop(|| {
        if thread::panicking() {
            shut_down();
        }
    });
    let mut reported = Snapshot::default();
    let mut next_report = clock.now() + REPORT_INTERVAL;
    let mut shutdown_at = None;
    let mut state = shared.lock();
    loop {
        let now = clock.now();
        if state.gone {
            if state.ended {
                return;
            }
            let deadline = *shutdown_at.get_or_insert(now + GRACE_PERIOD);
            if now >= deadline {
                drop(state);
                shut_down();
                return;
            }
            state = clock.wait_until(&shared.changed, state, deadline);
        } else if state.ended || now >= next_report {
            let (snapshot, ended) = (state.snapshot, state.ended);
            drop(state);
            let written = if snapshot != reported {
                send(report, &Event::Counters(snapshot))
            } else {
                Ok(())
            };
            if ended {
                return;
            }
            if written.is_ok() {
                reported = snapshot;
            }
            next_report = now + REPORT_INTERVAL;
            state = shared.lock();
            state.gone |= written.is_err_and(|error| error.kind() != io::ErrorKind::TimedOut);
        } else {
            state = clock.wait_until(&shared.changed, state, next_report);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, mpsc};
    use std::thread;

    use super::*;
    use crate::divert::packet::{ACK, SYN, UDP};
    use crate::divert::protocol::{Event, StatusReader};
    use crate::divert::testing::{LISTENER, TestPacket};
    use crate::divert::{Counters, DEFAULT_IDLE_TIMEOUT};

    const PATIENCE: Duration = Duration::from_secs(10);

    fn eventually(condition: impl Fn() -> bool, what: &str) {
        let start = Instant::now();
        while !condition() {
            assert!(start.elapsed() < PATIENCE, "{what}");
            thread::sleep(Duration::from_millis(1));
        }
    }

    struct ClockState {
        now: Instant,
        deadline: Option<Instant>,
        waits: usize,
    }

    struct ManualClock {
        start: Instant,
        state: Mutex<ClockState>,
    }

    impl ManualClock {
        fn new() -> Arc<Self> {
            let start = Instant::now();
            Arc::new(Self {
                start,
                state: Mutex::new(ClockState {
                    now: start,
                    deadline: None,
                    waits: 0,
                }),
            })
        }

        fn at(&self, elapsed: Duration) -> Instant {
            self.start + elapsed
        }

        fn advance_to(&self, elapsed: Duration) {
            self.state.lock().unwrap().now = self.at(elapsed);
        }

        fn wait_for_deadline(&self, elapsed: Duration) {
            let deadline = Some(self.at(elapsed));
            eventually(
                || self.state.lock().unwrap().deadline == deadline,
                "the supervisor never waited for the expected deadline",
            );
        }

        fn settle(&self) {
            let waits = self.state.lock().unwrap().waits;
            eventually(
                || self.state.lock().unwrap().waits >= waits + 2,
                "the supervisor stopped waiting",
            );
        }
    }

    impl Clock for ManualClock {
        fn now(&self) -> Instant {
            self.state.lock().unwrap().now
        }

        fn wait_until<'a>(
            &self,
            changed: &Condvar,
            state: MutexGuard<'a, State>,
            deadline: Instant,
        ) -> MutexGuard<'a, State> {
            let mut clock = self.state.lock().unwrap();
            clock.deadline = Some(deadline);
            clock.waits += 1;
            drop(clock);
            changed
                .wait_timeout(state, Duration::from_millis(1))
                .unwrap()
                .0
        }
    }

    enum Step {
        Packet(Vec<u8>, Direction),
        Oversized,
        Fail,
        Panic,
        Shutdown,
    }

    fn outbound(packet: TestPacket) -> Step {
        Step::Packet(packet.build(), Direction::Outbound)
    }

    struct FakePort {
        clock: Arc<ManualClock>,
        steps: Mutex<mpsc::Receiver<Step>>,
        shutdowns: mpsc::Sender<Step>,
        receives: Mutex<Vec<usize>>,
        injected: Mutex<Vec<(Vec<u8>, usize)>>,
        failing: AtomicBool,
        ignores_shutdown: AtomicBool,
        shut_down: Mutex<Option<Instant>>,
    }

    impl FakePort {
        fn shut_down(&self) -> Option<Instant> {
            *self.shut_down.lock().unwrap()
        }

        fn injected(&self) -> Vec<(Vec<u8>, usize)> {
            self.injected.lock().unwrap().clone()
        }
    }

    impl DivertPort for FakePort {
        type Address = usize;

        fn recv(&self, buffer: &mut [u8]) -> Result<Received<usize>, RecvError> {
            let address = {
                let mut receives = self.receives.lock().unwrap();
                receives.push(buffer.len());
                receives.len()
            };
            match self.steps.lock().unwrap().recv() {
                Ok(Step::Packet(bytes, direction)) => {
                    buffer[..bytes.len()].copy_from_slice(&bytes);
                    Ok(Received {
                        length: bytes.len(),
                        direction,
                        address,
                    })
                }
                Ok(Step::Oversized) => Ok(Received {
                    length: buffer.len() + 1,
                    direction: Direction::Outbound,
                    address,
                }),
                Ok(Step::Fail) => Err(RecvError::Failed(io::Error::other("receive failed"))),
                Ok(Step::Panic) => panic!("the port failed"),
                Ok(Step::Shutdown) | Err(_) => Err(RecvError::Shutdown),
            }
        }

        fn inject_inbound(&self, packet: &[u8], address: &usize) -> io::Result<()> {
            self.injected
                .lock()
                .unwrap()
                .push((packet.to_vec(), *address));
            if self.failing.load(Ordering::SeqCst) {
                return Err(io::Error::other("send failed"));
            }
            Ok(())
        }

        fn shutdown(&self) {
            *self.shut_down.lock().unwrap() = Some(self.clock.now());
            if !self.ignores_shutdown.load(Ordering::SeqCst) {
                let _ = self.shutdowns.send(Step::Shutdown);
            }
        }
    }

    #[derive(Clone, Default)]
    struct Lines(Arc<Mutex<Vec<u8>>>);

    impl Write for Lines {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct Panicking;

    impl Write for Panicking {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            panic!("the report failed")
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct Broken;

    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
    }

    struct Blocking {
        lines: Lines,
        entered: Arc<AtomicBool>,
        release: Option<mpsc::Receiver<()>>,
    }

    impl Write for Blocking {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if let Some(release) = self.release.take() {
                self.entered.store(true, Ordering::SeqCst);
                let _ = release.recv();
            }
            self.lines.write(bytes)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct Gone(mpsc::Receiver<bool>);

    impl Liveness for Gone {
        fn wait_until_gone(self) {
            if self.0.recv() == Ok(true) {
                panic!("the watch failed");
            }
        }
    }

    struct Harness {
        clock: Arc<ManualClock>,
        port: Arc<FakePort>,
        feed: mpsc::Sender<Step>,
        gone: mpsc::Sender<bool>,
        lines: Lines,
        stuck: Arc<Mutex<Option<Instant>>>,
        result: mpsc::Receiver<io::Result<()>>,
    }

    impl Harness {
        fn start() -> Self {
            let lines = Lines::default();
            Self::writing_to(lines.clone(), lines)
        }

        fn writing_to(mut report: impl Write + Send + 'static, lines: Lines) -> Self {
            let clock = ManualClock::new();
            let (feed, steps) = mpsc::channel();
            let port = Arc::new(FakePort {
                clock: Arc::clone(&clock),
                steps: Mutex::new(steps),
                shutdowns: feed.clone(),
                receives: Mutex::default(),
                injected: Mutex::default(),
                failing: AtomicBool::new(false),
                ignores_shutdown: AtomicBool::new(false),
                shut_down: Mutex::default(),
            });
            let (gone, agent) = mpsc::channel();
            let (done, result) = mpsc::channel();
            let engine = Engine::new(LISTENER, 8, DEFAULT_IDLE_TIMEOUT);
            let stuck = Arc::new(Mutex::new(None));
            let (stuck_at, stuck_clock) = (Arc::clone(&stuck), Arc::clone(&clock));
            let give_up = move || *stuck_at.lock().unwrap() = Some(stuck_clock.now());
            let (pump_port, pump_clock) = (Arc::clone(&port), Arc::clone(&clock));
            thread::spawn(move || {
                let result = run_with(
                    &*pump_port,
                    engine,
                    &mut report,
                    Gone(agent),
                    give_up,
                    &*pump_clock,
                );
                let _ = done.send(result);
            });
            clock.wait_for_deadline(REPORT_INTERVAL);
            Self {
                clock,
                port,
                feed,
                gone,
                lines,
                stuck,
                result,
            }
        }

        fn send(&self, step: Step) {
            self.feed.send(step).unwrap();
        }

        fn processed(&self, packets: usize) {
            eventually(
                || self.port.receives.lock().unwrap().len() > packets,
                "the packet loop did not ask for the next packet",
            );
        }

        fn agent_gone(&self) {
            self.gone.send(false).unwrap();
        }

        fn stopping(&self) {
            eventually(
                || self.lines.0.lock().unwrap().ends_with(b"stopping\n"),
                "the agent was not told to stop before releasing capture",
            );
        }

        fn watch_panics(&self) {
            self.gone.send(true).unwrap();
        }

        fn stuck(&self) -> Option<Instant> {
            *self.stuck.lock().unwrap()
        }

        fn ignore_shutdown(&self) {
            self.port.ignores_shutdown.store(true, Ordering::SeqCst);
        }

        fn panicked(&self) -> bool {
            matches!(
                self.result.recv_timeout(PATIENCE),
                Err(mpsc::RecvTimeoutError::Disconnected)
            )
        }

        fn finished(&self) -> io::Result<()> {
            self.result
                .recv_timeout(PATIENCE)
                .expect("the pump did not end")
        }

        fn reports(&self) -> Vec<Snapshot> {
            let mut reader = StatusReader::new();
            reader.push(b"ready\n").unwrap();
            let events = reader.push(&self.lines.0.lock().unwrap()).unwrap();
            reader.finish().unwrap();
            events
                .into_iter()
                .filter_map(|event| match event {
                    Event::Counters(snapshot) => Some(snapshot),
                    Event::Stopping => None,
                    other => panic!("not a counter line: {other:?}"),
                })
                .collect()
        }

        fn captured(&self) -> Vec<u64> {
            self.reports()
                .iter()
                .map(|report| report.engine.captured)
                .collect()
        }
    }

    const SECOND: Duration = Duration::from_secs(1);

    #[test]
    fn the_buffer_holds_the_largest_windivert_packet_and_the_intervals_are_fixed() {
        assert_eq!(PACKET_BUFFER_BYTES, 40 + 0xFFFF);
        assert_eq!(REPORT_INTERVAL, Duration::from_secs(10));
        assert_eq!(GRACE_PERIOD, Duration::from_secs(5));
        assert_eq!(SHUTDOWN_DEADLINE, Duration::from_secs(5));
        let harness = Harness::start();
        harness.send(outbound(TestPacket::client(SYN)));
        harness.send(Step::Shutdown);
        assert!(harness.finished().is_ok());
        assert_eq!(
            *harness.port.receives.lock().unwrap(),
            [PACKET_BUFFER_BYTES, PACKET_BUFFER_BYTES]
        );
    }

    #[test]
    fn reflected_packets_are_injected_with_the_received_length_and_drops_are_not() {
        let harness = Harness::start();
        let mut syn = TestPacket::client(SYN).build();
        syn.extend_from_slice(&[7, 7]);
        let mut reflected = syn.clone();
        let verdict = Engine::new(LISTENER, 8, DEFAULT_IDLE_TIMEOUT).process(
            &mut reflected,
            Direction::Outbound,
            harness.clock.at(Duration::ZERO),
        );
        assert_eq!(verdict, Verdict::InjectInbound);
        harness.send(Step::Packet(syn.clone(), Direction::Outbound));
        harness.send(Step::Packet(
            TestPacket::reply(ACK).build(),
            Direction::Inbound,
        ));
        harness.send(outbound(TestPacket {
            protocol: UDP,
            ..TestPacket::client(0)
        }));
        harness.send(Step::Shutdown);
        assert!(harness.finished().is_ok());
        assert_eq!(harness.port.injected(), [(reflected, 1)]);
        assert_eq!(harness.port.injected()[0].0.len(), syn.len());
        assert_eq!(
            harness.reports(),
            [Snapshot {
                engine: Counters {
                    captured: 3,
                    new_flows: 1,
                    reflected: 1,
                    inbound_dropped: 1,
                    contained_udp: 1,
                    ..Counters::default()
                },
                ..Snapshot::default()
            }]
        );
    }

    #[test]
    fn a_failed_injection_is_counted_and_the_loop_continues() {
        let harness = Harness::start();
        harness.port.failing.store(true, Ordering::SeqCst);
        harness.send(outbound(TestPacket::client(SYN)));
        harness.send(outbound(TestPacket::client(ACK)));
        harness.send(Step::Shutdown);
        assert!(harness.finished().is_ok());
        assert_eq!(harness.port.injected().len(), 2);
        let report = harness.reports()[0];
        assert_eq!(
            (
                report.engine.reflected,
                report.send_errors,
                report.receive_errors
            ),
            (2, 2, 0)
        );
    }

    #[test]
    fn shutdown_ends_the_loop_normally_without_reporting_unchanged_counters() {
        let harness = Harness::start();
        harness.send(Step::Shutdown);
        assert!(harness.finished().is_ok());
        assert_eq!(harness.reports(), []);
        assert_eq!(harness.port.shut_down(), None);
    }

    #[test]
    fn a_receive_error_other_than_shutdown_ends_the_loop_with_an_error() {
        let harness = Harness::start();
        harness.send(outbound(TestPacket::client(SYN)));
        harness.send(Step::Fail);
        harness.send(outbound(TestPacket::client(ACK)));
        harness.stopping();
        harness.agent_gone();
        let error = harness.finished().unwrap_err();
        assert_eq!(error.to_string(), "receive failed");
        assert_eq!(harness.port.receives.lock().unwrap().len(), 2);
        assert_eq!(harness.port.shut_down(), None);
        let reports = harness.reports();
        assert_eq!(
            reports
                .iter()
                .map(|report| (report.engine.captured, report.receive_errors))
                .collect::<Vec<_>>(),
            [(1, 1)]
        );
    }

    #[test]
    fn a_received_length_beyond_the_buffer_is_a_fatal_receive_error() {
        let harness = Harness::start();
        harness.send(Step::Oversized);
        harness.stopping();
        harness.agent_gone();
        let error = harness.finished().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(harness.port.injected(), []);
        assert_eq!(harness.reports()[0].receive_errors, 1);
        assert_eq!(harness.reports()[0].engine.captured, 0);
    }

    #[test]
    fn the_reporter_writes_a_line_each_interval_only_when_the_counters_changed() {
        let harness = Harness::start();
        harness.clock.advance_to(REPORT_INTERVAL);
        harness.clock.wait_for_deadline(2 * REPORT_INTERVAL);
        assert_eq!(harness.captured(), Vec::<u64>::new());
        harness.send(outbound(TestPacket::client(SYN)));
        harness.processed(1);
        harness.clock.advance_to(2 * REPORT_INTERVAL - SECOND);
        harness.clock.settle();
        assert_eq!(harness.captured(), Vec::<u64>::new());
        harness.clock.advance_to(2 * REPORT_INTERVAL);
        harness.clock.wait_for_deadline(3 * REPORT_INTERVAL);
        assert_eq!(harness.captured(), [1]);
        harness.clock.advance_to(3 * REPORT_INTERVAL);
        harness.clock.wait_for_deadline(4 * REPORT_INTERVAL);
        assert_eq!(harness.captured(), [1]);
        harness.send(outbound(TestPacket::client(ACK)));
        harness.processed(2);
        harness.clock.advance_to(4 * REPORT_INTERVAL);
        harness.clock.wait_for_deadline(5 * REPORT_INTERVAL);
        assert_eq!(harness.captured(), [1, 2]);
        harness.send(Step::Shutdown);
        assert!(harness.finished().is_ok());
        assert_eq!(harness.captured(), [1, 2]);
    }

    #[test]
    fn the_port_is_shut_down_only_after_the_grace_period_once_the_agent_is_gone() {
        let harness = Harness::start();
        let gone = 3 * SECOND;
        harness.clock.advance_to(gone);
        harness.agent_gone();
        harness.clock.wait_for_deadline(gone + GRACE_PERIOD);
        harness.send(outbound(TestPacket::client(SYN)));
        harness.processed(1);
        harness
            .clock
            .advance_to(gone + GRACE_PERIOD - Duration::from_millis(1));
        harness.clock.settle();
        assert_eq!(harness.port.shut_down(), None);
        harness.clock.advance_to(gone + GRACE_PERIOD);
        assert!(harness.finished().is_ok());
        assert_eq!(
            harness.port.shut_down(),
            Some(harness.clock.at(gone + GRACE_PERIOD))
        );
        assert_eq!(harness.port.injected().len(), 1);
        assert_eq!(harness.reports(), []);
        assert_eq!(harness.stuck(), None);
    }

    #[test]
    fn a_failed_write_means_the_agent_is_gone() {
        let harness = Harness::writing_to(Broken, Lines::default());
        harness.send(outbound(TestPacket::client(SYN)));
        harness.processed(1);
        harness.clock.advance_to(REPORT_INTERVAL);
        harness
            .clock
            .wait_for_deadline(REPORT_INTERVAL + GRACE_PERIOD);
        assert_eq!(harness.port.shut_down(), None);
        harness.clock.advance_to(REPORT_INTERVAL + GRACE_PERIOD);
        assert!(harness.finished().is_ok());
        assert_eq!(
            harness.port.shut_down(),
            Some(harness.clock.at(REPORT_INTERVAL + GRACE_PERIOD))
        );
    }

    #[test]
    fn a_failed_receive_holds_capture_until_the_agent_closes_its_pipe() {
        let harness = Harness::start();
        harness.send(Step::Fail);
        harness.stopping();
        assert!(matches!(
            harness.result.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        assert_eq!(harness.port.shut_down(), None);
        harness.agent_gone();
        assert!(harness.finished().is_err());
    }

    #[test]
    fn a_failed_receive_releases_capture_after_the_stop_deadline() {
        let harness = Harness::start();
        harness.send(Step::Fail);
        harness.stopping();
        harness.clock.wait_for_deadline(STOP_ACK_TIMEOUT);
        harness.clock.advance_to(STOP_ACK_TIMEOUT);
        assert!(harness.finished().is_err());
    }

    #[test]
    fn a_fatal_error_skips_the_grace_period() {
        let harness = Harness::start();
        harness.send(outbound(TestPacket::client(SYN)));
        harness.processed(1);
        harness.agent_gone();
        harness.clock.wait_for_deadline(GRACE_PERIOD);
        harness.send(Step::Fail);
        assert!(harness.finished().is_err());
        assert_eq!(harness.port.shut_down(), None);
        assert_eq!(harness.reports(), []);
    }

    #[test]
    fn the_packet_loop_does_not_wait_for_a_blocked_report() {
        let lines = Lines::default();
        let entered = Arc::new(AtomicBool::new(false));
        let (release, blocked) = mpsc::channel();
        let report = Blocking {
            lines: lines.clone(),
            entered: Arc::clone(&entered),
            release: Some(blocked),
        };
        let harness = Harness::writing_to(report, lines);
        harness.send(outbound(TestPacket::client(SYN)));
        harness.processed(1);
        harness.clock.advance_to(REPORT_INTERVAL);
        eventually(
            || entered.load(Ordering::SeqCst),
            "the reporter did not write",
        );
        harness.send(outbound(TestPacket::client(ACK)));
        harness.send(outbound(TestPacket::client(ACK)));
        harness.processed(3);
        assert_eq!(harness.port.injected().len(), 3);
        release.send(()).unwrap();
        harness.send(Step::Shutdown);
        assert!(harness.finished().is_ok());
        assert_eq!(harness.captured(), [1, 3]);
    }

    #[test]
    fn a_panic_in_the_packet_loop_ends_the_pump_instead_of_hanging() {
        let harness = Harness::start();
        harness.send(outbound(TestPacket::client(SYN)));
        harness.processed(1);
        harness.send(Step::Panic);
        harness.stopping();
        harness.agent_gone();
        assert!(harness.panicked());
        assert_eq!(harness.port.shut_down(), None);
        assert_eq!(harness.captured(), [1]);
    }

    #[test]
    fn a_panic_in_the_reporter_shuts_the_port_down_and_ends_the_pump() {
        let harness = Harness::writing_to(Panicking, Lines::default());
        harness.send(outbound(TestPacket::client(SYN)));
        harness.processed(1);
        harness.clock.advance_to(REPORT_INTERVAL);
        assert!(harness.panicked());
        assert_eq!(
            harness.port.shut_down(),
            Some(harness.clock.at(REPORT_INTERVAL))
        );
        assert_eq!(harness.stuck(), None);
    }

    #[test]
    fn a_panic_while_watching_the_agent_counts_as_the_agent_gone() {
        let harness = Harness::start();
        harness.watch_panics();
        harness.clock.wait_for_deadline(GRACE_PERIOD);
        assert_eq!(harness.port.shut_down(), None);
        harness.clock.advance_to(GRACE_PERIOD);
        assert!(harness.finished().is_ok());
        assert_eq!(
            harness.port.shut_down(),
            Some(harness.clock.at(GRACE_PERIOD))
        );
    }

    #[test]
    fn a_port_still_receiving_after_its_shutdown_is_given_up_after_the_deadline() {
        let harness = Harness::start();
        harness.ignore_shutdown();
        harness.agent_gone();
        harness.clock.wait_for_deadline(GRACE_PERIOD);
        harness.clock.advance_to(GRACE_PERIOD);
        harness
            .clock
            .wait_for_deadline(GRACE_PERIOD + SHUTDOWN_DEADLINE);
        assert_eq!(
            harness.port.shut_down(),
            Some(harness.clock.at(GRACE_PERIOD))
        );
        harness
            .clock
            .advance_to(GRACE_PERIOD + SHUTDOWN_DEADLINE - Duration::from_millis(1));
        harness.clock.settle();
        assert_eq!(harness.stuck(), None);
        harness.clock.advance_to(GRACE_PERIOD + SHUTDOWN_DEADLINE);
        eventually(|| harness.stuck().is_some(), "the pump was not given up");
        assert_eq!(
            harness.stuck(),
            Some(harness.clock.at(GRACE_PERIOD + SHUTDOWN_DEADLINE))
        );
        harness.send(Step::Shutdown);
        assert!(harness.finished().is_ok());
    }

    #[test]
    fn a_port_still_receiving_after_a_reporter_panic_is_given_up_after_the_deadline() {
        let harness = Harness::writing_to(Panicking, Lines::default());
        harness.ignore_shutdown();
        harness.send(outbound(TestPacket::client(SYN)));
        harness.processed(1);
        harness.clock.advance_to(REPORT_INTERVAL);
        harness
            .clock
            .wait_for_deadline(REPORT_INTERVAL + SHUTDOWN_DEADLINE);
        assert_eq!(harness.stuck(), None);
        harness
            .clock
            .advance_to(REPORT_INTERVAL + SHUTDOWN_DEADLINE);
        eventually(|| harness.stuck().is_some(), "the pump was not given up");
        assert_eq!(
            harness.stuck(),
            Some(harness.clock.at(REPORT_INTERVAL + SHUTDOWN_DEADLINE))
        );
        harness.send(Step::Shutdown);
        assert!(harness.panicked());
    }
}
