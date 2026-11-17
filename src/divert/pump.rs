use std::io::{self, Write};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use super::protocol::{Event, Snapshot, send};
use super::{Direction, Engine, Verdict};

pub const PACKET_BUFFER_BYTES: usize = 40 + 0xFFFF;
pub const REPORT_INTERVAL: Duration = Duration::from_secs(10);
pub const GRACE_PERIOD: Duration = Duration::from_secs(5);

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
    fn shutdown(&self);
}

pub trait Liveness: Send + 'static {
    fn wait_until_gone(self);
}

pub fn run<P, W, L>(port: &P, engine: Engine, report: &mut W, liveness: L) -> io::Result<()>
where
    P: DivertPort,
    W: Write + Send,
    L: Liveness,
{
    run_with(port, engine, report, liveness, &SystemClock)
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

fn run_with<P, W, L, C>(
    port: &P,
    engine: Engine,
    report: &mut W,
    liveness: L,
    clock: &C,
) -> io::Result<()>
where
    P: DivertPort,
    W: Write + Send,
    L: Liveness,
    C: Clock,
{
    let shared = Arc::new(Shared::default());
    let watcher = Arc::clone(&shared);
    // Not joined: the wait cannot be interrupted, and the helper exits once the pump returns.
    thread::Builder::new().spawn(move || {
        liveness.wait_until_gone();
        watcher.signal(|state| state.gone = true);
    })?;
    let shared = &*shared;
    thread::scope(|scope| {
        thread::Builder::new()
            .spawn_scoped(scope, move || supervise(shared, port, report, clock))?;
        let forwarded = forward(port, engine, shared, clock);
        shared.signal(|state| state.ended = true);
        forwarded
    })
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

fn supervise<P: DivertPort, W: Write, C: Clock>(
    shared: &Shared,
    port: &P,
    report: &mut W,
    clock: &C,
) {
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
                port.shutdown();
                return;
            }
            state = clock.wait_until(&shared.changed, state, deadline);
        } else if state.ended || now >= next_report {
            let (snapshot, ended) = (state.snapshot, state.ended);
            drop(state);
            let failed = snapshot != reported && send(report, &Event::Counters(snapshot)).is_err();
            if ended {
                return;
            }
            reported = snapshot;
            next_report = now + REPORT_INTERVAL;
            state = shared.lock();
            state.gone |= failed;
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
            let _ = self.shutdowns.send(Step::Shutdown);
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

    struct Gone(mpsc::Receiver<()>);

    impl Liveness for Gone {
        fn wait_until_gone(self) {
            let _ = self.0.recv();
        }
    }

    struct Harness {
        clock: Arc<ManualClock>,
        port: Arc<FakePort>,
        feed: mpsc::Sender<Step>,
        gone: mpsc::Sender<()>,
        lines: Lines,
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
                shut_down: Mutex::default(),
            });
            let (gone, agent) = mpsc::channel();
            let (done, result) = mpsc::channel();
            let engine = Engine::new(LISTENER, 8, DEFAULT_IDLE_TIMEOUT);
            let (pump_port, pump_clock) = (Arc::clone(&port), Arc::clone(&clock));
            thread::spawn(move || {
                let result = run_with(&*pump_port, engine, &mut report, Gone(agent), &*pump_clock);
                let _ = done.send(result);
            });
            clock.wait_for_deadline(REPORT_INTERVAL);
            Self {
                clock,
                port,
                feed,
                gone,
                lines,
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
            self.gone.send(()).unwrap();
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
                .map(|event| match event {
                    Event::Counters(snapshot) => snapshot,
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
}
