use std::any::Any;
use std::collections::BTreeMap;
use std::collections::btree_map;
use std::fmt;
use std::io;
use std::panic::{self, AssertUnwindSafe};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::net::TcpStream;
use tokio::sync::watch;
use tracing::warn;

use crate::http::Authority;
use crate::job::Job;
use crate::proxy::Adopter;

const STOPPED: &str = "the transparent engine stopped while it was starting";
const ABANDONED: &str = "the start of the transparent engine was abandoned";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Generation(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Stopped,
    Starting(Generation),
    Running(Generation),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    NotRunning,
    Registered,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRunning => f.write_str("the transparent engine is not running"),
            Self::Registered => {
                f.write_str("the session is already registered for transparent routing")
            }
        }
    }
}

impl std::error::Error for Refusal {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Closing;

impl fmt::Display for Closing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the transparent session is closing")
    }
}

impl std::error::Error for Closing {}

pub trait Terminate {
    fn terminate(&self) -> io::Result<()>;
}

impl Terminate for Job {
    fn terminate(&self) -> io::Result<()> {
        Job::terminate(self)
    }
}

type Outcome = Option<Result<(), String>>;

enum Current {
    Stopped,
    Starting(Generation, watch::Sender<Outcome>),
    Running(Generation),
}

struct Inner<K, J> {
    current: Current,
    generations: u64,
    sessions: BTreeMap<K, Entry<J>>,
}

struct Entry<J> {
    generation: Generation,
    job: Arc<J>,
    adopter: Adopter,
    mark: Arc<Mark>,
}

impl<J: Terminate> Entry<J> {
    fn close(&self) {
        let _closing = self.mark.close();
        match panic::catch_unwind(AssertUnwindSafe(|| self.job.terminate())) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                warn!("terminating the job of a transparent session failed: {error}");
            }
            Err(panic) => warn!(
                "terminating the job of a transparent session panicked: {}",
                panic_message(panic.as_ref())
            ),
        }
    }
}

fn panic_message(panic: &(dyn Any + Send)) -> &str {
    panic
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("no message")
}

pub struct State<K, J> {
    inner: Mutex<Inner<K, J>>,
}

pub enum Begin<K, J> {
    Start(Starter<K, J>),
    Join(Joiner),
    Running(Generation),
}

impl<K, J> Default for State<K, J> {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Inner {
                current: Current::Stopped,
                generations: 0,
                sessions: BTreeMap::new(),
            }),
        }
    }
}

impl<K, J> State<K, J> {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, Inner<K, J>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn phase(&self) -> Phase {
        match self.lock().current {
            Current::Stopped => Phase::Stopped,
            Current::Starting(generation, _) => Phase::Starting(generation),
            Current::Running(generation) => Phase::Running(generation),
        }
    }

    pub fn begin(self: &Arc<Self>) -> Begin<K, J> {
        let mut inner = self.lock();
        match &inner.current {
            Current::Running(generation) => Begin::Running(*generation),
            Current::Starting(generation, outcome) => Begin::Join(Joiner {
                generation: *generation,
                outcome: outcome.subscribe(),
            }),
            Current::Stopped => {
                inner.generations += 1;
                let generation = Generation(inner.generations);
                let (sender, _) = watch::channel(None);
                inner.current = Current::Starting(generation, sender.clone());
                Begin::Start(Starter {
                    state: self.clone(),
                    generation,
                    sender: Some(sender),
                })
            }
        }
    }

    #[cfg(test)]
    pub fn joiners(&self) -> usize {
        match &self.lock().current {
            Current::Starting(_, outcome) => outcome.receiver_count(),
            Current::Stopped | Current::Running(_) => 0,
        }
    }

    fn finish(&self, generation: Generation, result: Result<(), String>) -> Result<(), String> {
        let mut inner = self.lock();
        if !matches!(inner.current, Current::Starting(current, _) if current == generation) {
            return result.and(Err(STOPPED.to_owned()));
        }
        inner.current = match result {
            Ok(()) => Current::Running(generation),
            Err(_) => Current::Stopped,
        };
        result
    }
}

impl<K: Ord + Clone, J> State<K, J> {
    pub fn register(&self, key: K, job: Arc<J>, adopter: Adopter) -> Result<Arc<Mark>, Refusal> {
        let mut inner = self.lock();
        let Current::Running(generation) = inner.current else {
            return Err(Refusal::NotRunning);
        };
        let btree_map::Entry::Vacant(vacant) = inner.sessions.entry(key) else {
            return Err(Refusal::Registered);
        };
        let mark = Arc::new(Mark::default());
        vacant.insert(Entry {
            generation,
            job,
            adopter,
            mark: mark.clone(),
        });
        Ok(mark)
    }

    pub fn unregister(&self, key: &K) -> bool {
        let removed = self.lock().sessions.remove(key);
        removed.is_some()
    }

    pub fn jobs(&self, generation: Generation) -> Vec<(K, Arc<J>)> {
        self.lock()
            .sessions
            .iter()
            .filter(|(_, entry)| entry.generation == generation)
            .map(|(key, entry)| (key.clone(), entry.job.clone()))
            .collect()
    }

    pub fn adopt(
        &self,
        generation: Generation,
        key: &K,
        stream: TcpStream,
        target: Authority,
    ) -> Result<(), TcpStream> {
        match self.lock().sessions.get(key) {
            Some(entry) if entry.generation == generation => entry.adopter.adopt(stream, target),
            _ => Err(stream),
        }
    }

    pub fn stop(&self, generation: Generation) -> Vec<K>
    where
        J: Terminate,
    {
        let taken: BTreeMap<K, Entry<J>> = {
            let mut inner = self.lock();
            match inner.current {
                Current::Starting(current, _) | Current::Running(current)
                    if current == generation => {}
                _ => return Vec::new(),
            }
            inner.current = Current::Stopped;
            let (taken, kept) = std::mem::take(&mut inner.sessions)
                .into_iter()
                .partition(|(_, entry)| entry.generation == generation);
            inner.sessions = kept;
            taken
        };
        taken
            .into_iter()
            .map(|(key, entry)| {
                entry.close();
                key
            })
            .collect()
    }
}

pub struct Starter<K, J> {
    state: Arc<State<K, J>>,
    generation: Generation,
    sender: Option<watch::Sender<Outcome>>,
}

impl<K, J> Starter<K, J> {
    pub fn generation(&self) -> Generation {
        self.generation
    }

    pub fn finish(mut self, result: Result<(), String>) -> Result<(), String> {
        self.conclude(result)
    }

    fn conclude(&mut self, result: Result<(), String>) -> Result<(), String> {
        let finished = self.state.finish(self.generation, result);
        if let Some(sender) = self.sender.take() {
            sender.send_replace(Some(finished.clone()));
        }
        finished
    }
}

impl<K, J> Drop for Starter<K, J> {
    fn drop(&mut self) {
        if self.sender.is_some() {
            let _ = self.conclude(Err(ABANDONED.to_owned()));
        }
    }
}

pub struct Joiner {
    generation: Generation,
    outcome: watch::Receiver<Outcome>,
}

impl Joiner {
    pub fn generation(&self) -> Generation {
        self.generation
    }

    pub async fn outcome(mut self) -> Result<(), String> {
        let outcome = self
            .outcome
            .wait_for(Option::is_some)
            .await
            .map(|outcome| outcome.clone());
        outcome
            .ok()
            .flatten()
            .unwrap_or_else(|| Err(ABANDONED.to_owned()))
    }
}

#[derive(Debug, Default)]
pub struct Mark {
    closing: Mutex<bool>,
}

pub struct Launch<'a> {
    _closing: MutexGuard<'a, bool>,
}

impl Mark {
    pub fn launch(&self) -> Result<Launch<'_>, Closing> {
        let closing = self.lock();
        if *closing {
            return Err(Closing);
        }
        Ok(Launch { _closing: closing })
    }

    fn close(&self) -> MutexGuard<'_, bool> {
        let mut closing = self.lock();
        *closing = true;
        closing
    }

    fn lock(&self) -> MutexGuard<'_, bool> {
        self.closing.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Event {
        Spawned,
        Terminated,
    }

    type During = Box<dyn FnOnce() + Send>;

    #[derive(Default)]
    struct FakeJob {
        events: Mutex<Vec<Event>>,
        fails: bool,
        during: Mutex<Option<During>>,
    }

    impl FakeJob {
        fn events(&self) -> Vec<Event> {
            self.events.lock().unwrap().clone()
        }

        fn record(&self, event: Event) {
            self.events.lock().unwrap().push(event);
        }
    }

    impl Terminate for FakeJob {
        fn terminate(&self) -> io::Result<()> {
            let during = self.during.lock().unwrap().take();
            if let Some(during) = during {
                during();
            }
            self.record(Event::Terminated);
            if self.fails {
                return Err(io::Error::other("access denied"));
            }
            Ok(())
        }
    }

    type Fake = State<u32, FakeJob>;

    fn adopter() -> Adopter {
        Adopter::channel(1).0
    }

    fn start(state: &Arc<Fake>) -> Starter<u32, FakeJob> {
        match state.begin() {
            Begin::Start(starter) => starter,
            _ => panic!("expected to start the engine, found {:?}", state.phase()),
        }
    }

    fn join(state: &Arc<Fake>) -> Joiner {
        match state.begin() {
            Begin::Join(joiner) => joiner,
            _ => panic!("expected to join a start, found {:?}", state.phase()),
        }
    }

    fn running(state: &Arc<Fake>) -> Generation {
        let starter = start(state);
        let generation = starter.generation();
        starter.finish(Ok(())).unwrap();
        generation
    }

    fn register(state: &Fake, key: u32) -> (Arc<FakeJob>, Arc<Mark>) {
        let job = Arc::new(FakeJob::default());
        let mark = state.register(key, job.clone(), adopter()).unwrap();
        (job, mark)
    }

    fn keys(state: &Fake, generation: Generation) -> Vec<u32> {
        state
            .jobs(generation)
            .into_iter()
            .map(|(key, _)| key)
            .collect()
    }

    type Adopted = tokio::sync::mpsc::Receiver<(TcpStream, Authority)>;

    fn adopting(state: &Fake, key: u32, capacity: usize) -> (Arc<FakeJob>, Adopted) {
        let job = Arc::new(FakeJob::default());
        let (adopter, adopted) = Adopter::channel(capacity);
        state.register(key, job.clone(), adopter).unwrap();
        (job, adopted)
    }

    async fn stream() -> (TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        (client, listener.accept().await.unwrap().0)
    }

    fn target() -> Authority {
        "203.0.113.7:443".parse().unwrap()
    }

    #[tokio::test]
    async fn concurrent_requests_share_one_start_and_its_success() {
        let state = Arc::new(Fake::new());
        assert_eq!(state.phase(), Phase::Stopped);
        let starter = start(&state);
        let generation = starter.generation();
        assert_eq!(state.joiners(), 0);
        let joiners = [join(&state), join(&state)];
        assert_eq!(state.phase(), Phase::Starting(generation));
        assert_eq!(state.joiners(), 2);
        for joiner in &joiners {
            assert_eq!(joiner.generation(), generation);
        }
        assert_eq!(starter.finish(Ok(())), Ok(()));
        assert_eq!(state.joiners(), 0);
        for joiner in joiners {
            assert_eq!(joiner.outcome().await, Ok(()));
        }
        assert_eq!(state.phase(), Phase::Running(generation));
        assert!(matches!(state.begin(), Begin::Running(running) if running == generation));
    }

    #[tokio::test]
    async fn concurrent_requests_share_the_failure_of_one_start_and_the_next_start_is_new() {
        let state = Arc::new(Fake::new());
        let starter = start(&state);
        let first = starter.generation();
        let joiner = join(&state);
        let waiting = tokio::spawn(joiner.outcome());
        tokio::task::yield_now().await;
        assert_eq!(
            starter.finish(Err("error another-helper".to_owned())),
            Err("error another-helper".to_owned())
        );
        assert_eq!(
            waiting.await.unwrap(),
            Err("error another-helper".to_owned())
        );
        assert_eq!(state.phase(), Phase::Stopped);
        let next = start(&state);
        assert_ne!(next.generation(), first);
        assert_eq!(state.phase(), Phase::Starting(next.generation()));
    }

    #[tokio::test]
    async fn a_joiner_gets_the_outcome_of_the_generation_it_joined_never_a_later_one() {
        let state = Arc::new(Fake::new());
        let first = start(&state);
        let joiner = join(&state);
        first.finish(Err("first".to_owned())).unwrap_err();
        let second = start(&state);
        assert_eq!(second.finish(Ok(())), Ok(()));
        assert_eq!(joiner.outcome().await, Err("first".to_owned()));
    }

    #[tokio::test]
    async fn a_helper_that_stops_after_ready_before_the_hand_over_leaves_the_engine_stopped() {
        let state = Arc::new(Fake::new());
        let starter = start(&state);
        let joiner = join(&state);
        assert!(state.stop(starter.generation()).is_empty());
        assert_eq!(state.phase(), Phase::Stopped);
        let handed_over = starter.finish(Ok(()));
        assert!(
            handed_over
                .as_ref()
                .is_err_and(|error| error.contains("stopped")),
            "{handed_over:?}"
        );
        assert_eq!(state.phase(), Phase::Stopped);
        assert_eq!(joiner.outcome().await, handed_over);
        let job = Arc::new(FakeJob::default());
        assert_eq!(
            state.register(1, job, adopter()).err(),
            Some(Refusal::NotRunning)
        );
    }

    #[tokio::test]
    async fn a_stale_start_neither_completes_nor_clears_a_newer_one() {
        type Stale = fn(Starter<u32, FakeJob>);
        let stale: [Stale; 3] = [
            |a| assert!(a.finish(Ok(())).is_err()),
            |a| assert!(a.finish(Err("timed out".to_owned())).is_err()),
            drop,
        ];
        for end in stale {
            let state = Arc::new(Fake::new());
            let a = start(&state);
            let a_joiner = join(&state);
            assert!(state.stop(a.generation()).is_empty());
            let b = start(&state);
            let b_joiner = join(&state);
            end(a);
            assert!(a_joiner.outcome().await.is_err());
            assert_eq!(state.phase(), Phase::Starting(b.generation()));
            let generation = b.generation();
            assert_eq!(b.finish(Ok(())), Ok(()));
            assert_eq!(b_joiner.outcome().await, Ok(()));
            assert_eq!(state.phase(), Phase::Running(generation));
        }
    }

    #[tokio::test]
    async fn an_abandoned_start_stops_the_engine_and_fails_its_joiners() {
        let state = Arc::new(Fake::new());
        let starter = start(&state);
        let joiner = join(&state);
        drop(starter);
        assert_eq!(state.phase(), Phase::Stopped);
        let outcome = joiner.outcome().await;
        assert!(
            outcome
                .as_ref()
                .is_err_and(|error| error.contains("abandoned")),
            "{outcome:?}"
        );
        start(&state);
    }

    #[test]
    fn registration_succeeds_only_while_the_engine_runs() {
        let state = Arc::new(Fake::new());
        let refused = |state: &Fake| {
            state
                .register(9, Arc::new(FakeJob::default()), adopter())
                .err()
        };
        assert_eq!(refused(&state), Some(Refusal::NotRunning));
        let starter = start(&state);
        assert_eq!(refused(&state), Some(Refusal::NotRunning));
        let generation = starter.generation();
        starter.finish(Ok(())).unwrap();
        register(&state, 1);
        assert_eq!(state.stop(generation), [1]);
        assert_eq!(refused(&state), Some(Refusal::NotRunning));
        let next = start(&state);
        assert_eq!(refused(&state), Some(Refusal::NotRunning));
        assert!(keys(&state, generation).is_empty());
        assert!(keys(&state, next.generation()).is_empty());
    }

    #[test]
    fn a_session_registers_once() {
        let state = Arc::new(Fake::new());
        let generation = running(&state);
        let (job, _) = register(&state, 1);
        let again = state.register(1, Arc::new(FakeJob::default()), adopter());
        assert_eq!(again.err(), Some(Refusal::Registered));
        let jobs = state.jobs(generation);
        assert_eq!(jobs.len(), 1);
        assert!(Arc::ptr_eq(&jobs[0].1, &job));
    }

    #[test]
    fn a_break_terminates_every_session_of_its_generation_and_marks_it_closing() {
        let state = Arc::new(Fake::new());
        let generation = running(&state);
        let (first, first_mark) = register(&state, 1);
        let (second, second_mark) = register(&state, 2);
        assert_eq!(keys(&state, generation), [1, 2]);
        assert_eq!(state.stop(generation), [1, 2]);
        assert_eq!(state.phase(), Phase::Stopped);
        for (job, mark) in [(first, first_mark), (second, second_mark)] {
            assert_eq!(job.events(), [Event::Terminated]);
            assert_eq!(mark.launch().err(), Some(Closing));
        }
        assert!(keys(&state, generation).is_empty());
    }

    #[test]
    fn a_late_or_repeated_break_changes_nothing() {
        let state = Arc::new(Fake::new());
        let old = running(&state);
        let (old_job, _) = register(&state, 1);
        assert_eq!(state.stop(old), [1]);
        assert!(state.stop(old).is_empty());
        assert_eq!(old_job.events(), [Event::Terminated]);
        let new = running(&state);
        let (new_job, new_mark) = register(&state, 2);
        assert!(state.stop(old).is_empty());
        assert_eq!(state.phase(), Phase::Running(new));
        assert_eq!(keys(&state, new), [2]);
        assert!(keys(&state, old).is_empty());
        assert!(new_job.events().is_empty());
        assert!(new_mark.launch().is_ok());
        register(&state, 3);
        assert_eq!(keys(&state, new), [2, 3]);
        assert_eq!(state.stop(new), [2, 3]);
        assert!(state.stop(new).is_empty());
        assert_eq!(new_job.events(), [Event::Terminated]);
    }

    #[test]
    fn a_failed_terminate_is_logged_and_the_other_sessions_are_still_terminated() {
        let logs = crate::test_logs::capture();
        let state = Arc::new(Fake::new());
        let generation = running(&state);
        let failing = Arc::new(FakeJob {
            fails: true,
            ..FakeJob::default()
        });
        state.register(1, failing.clone(), adopter()).unwrap();
        let (other, _) = register(&state, 2);
        assert_eq!(state.stop(generation), [1, 2]);
        assert_eq!(failing.events(), [Event::Terminated]);
        assert_eq!(other.events(), [Event::Terminated]);
        let warnings = logs.lines(" WARN ");
        assert_eq!(warnings.len(), 1, "{:?}", logs.lines(""));
        assert!(warnings[0].contains("access denied"), "{warnings:?}");
    }

    #[test]
    fn a_panicking_terminate_is_logged_and_every_session_is_still_closed_and_returned() {
        let logs = crate::test_logs::capture();
        let state = Arc::new(Fake::new());
        let generation = running(&state);
        let (panicking, panicking_mark) = register(&state, 1);
        *panicking.during.lock().unwrap() = Some(Box::new(|| panic!("the job handle is gone")));
        let (other, other_mark) = register(&state, 2);
        assert_eq!(state.stop(generation), [1, 2]);
        assert_eq!(state.phase(), Phase::Stopped);
        assert!(panicking.events().is_empty());
        assert_eq!(other.events(), [Event::Terminated]);
        for mark in [panicking_mark, other_mark] {
            assert_eq!(mark.launch().err(), Some(Closing));
        }
        let warnings = logs.lines(" WARN ");
        assert_eq!(warnings.len(), 1, "{:?}", logs.lines(""));
        assert!(
            warnings[0].contains("panicked: the job handle is gone"),
            "{warnings:?}"
        );
    }

    #[test]
    fn unregistered_sessions_leave_the_snapshot_and_are_not_terminated() {
        let state = Arc::new(Fake::new());
        let generation = running(&state);
        let (first, _) = register(&state, 1);
        register(&state, 2);
        assert!(state.unregister(&1));
        assert!(!state.unregister(&1));
        assert_eq!(keys(&state, generation), [2]);
        assert_eq!(state.stop(generation), [2]);
        assert!(first.events().is_empty());
    }

    #[test]
    fn a_launch_before_the_break_is_terminated_by_it_and_one_after_it_is_refused() {
        let state = Arc::new(Fake::new());
        let generation = running(&state);
        let (job, mark) = register(&state, 1);
        let (holding, held) = mpsc::channel();
        let launch = std::thread::spawn({
            let (job, mark) = (job.clone(), mark.clone());
            move || {
                let _launch = mark.launch().unwrap();
                holding.send(()).unwrap();
                std::thread::sleep(Duration::from_millis(50));
                job.record(Event::Spawned);
            }
        });
        held.recv().unwrap();
        assert_eq!(state.stop(generation), [1]);
        launch.join().unwrap();
        assert_eq!(job.events(), [Event::Spawned, Event::Terminated]);
        assert_eq!(mark.launch().err(), Some(Closing));
    }

    #[test]
    fn a_break_releases_the_engine_lock_before_it_terminates_a_job() {
        let state = Arc::new(Fake::new());
        let generation = running(&state);
        let (job, _) = register(&state, 1);
        let (registered, registration) = mpsc::channel();
        *job.during.lock().unwrap() = Some(Box::new({
            let state = state.clone();
            move || {
                std::thread::spawn(move || {
                    let refused = state
                        .register(2, Arc::new(FakeJob::default()), adopter())
                        .err();
                    let _ = registered.send((refused, state.phase()));
                });
                let answered = registration.recv_timeout(Duration::from_secs(5));
                assert_eq!(
                    answered,
                    Ok((Some(Refusal::NotRunning), Phase::Stopped)),
                    "the engine lock was held while the job was terminated"
                );
            }
        }));
        assert_eq!(state.stop(generation), [1]);
        assert_eq!(job.events(), [Event::Terminated]);
    }

    #[tokio::test]
    async fn a_stream_is_adopted_only_by_a_session_registered_under_the_given_generation() {
        let state = Arc::new(Fake::new());
        let old = running(&state);
        let (_, mut old_adopted) = adopting(&state, 1, 4);
        assert_eq!(state.stop(old), [1]);
        let new = running(&state);
        let (_, mut adopted) = adopting(&state, 2, 4);
        let (_client, accepted) = stream().await;
        let accepted = state.adopt(old, &2, accepted, target()).unwrap_err();
        let accepted = state.adopt(new, &1, accepted, target()).unwrap_err();
        assert!(old_adopted.try_recv().is_err());
        assert!(adopted.try_recv().is_err());
        state.adopt(new, &2, accepted, target()).unwrap();
        assert_eq!(adopted.try_recv().unwrap().1, target());
    }

    #[tokio::test]
    async fn a_full_session_hands_the_stream_back() {
        let state = Arc::new(Fake::new());
        let generation = running(&state);
        let (_, mut adopted) = adopting(&state, 1, 1);
        let (_first_client, first) = stream().await;
        let (_second_client, second) = stream().await;
        state.adopt(generation, &1, first, target()).unwrap();
        state.adopt(generation, &1, second, target()).unwrap_err();
        adopted.try_recv().unwrap();
        assert!(adopted.try_recv().is_err());
    }

    #[tokio::test]
    async fn no_stream_is_adopted_once_unregister_or_a_break_has_taken_the_session() {
        let state = Arc::new(Fake::new());
        let generation = running(&state);
        let (_, mut unregistered) = adopting(&state, 1, 4);
        assert!(state.unregister(&1));
        let (_client, accepted) = stream().await;
        let accepted = state.adopt(generation, &1, accepted, target()).unwrap_err();
        assert!(unregistered.try_recv().is_err());

        let (before_client, before) = stream().await;
        let (job, mut adopted) = adopting(&state, 2, 4);
        state.adopt(generation, &2, before, target()).unwrap();
        let during = Arc::new(Mutex::new(None));
        *job.during.lock().unwrap() = Some(Box::new({
            let (state, during) = (state.clone(), during.clone());
            move || {
                let refused = state.adopt(generation, &2, accepted, target()).is_err();
                *during.lock().unwrap() = Some(refused);
            }
        }));
        assert_eq!(state.stop(generation), [2]);
        assert_eq!(*during.lock().unwrap(), Some(true));
        let (_after_client, after) = stream().await;
        state.adopt(generation, &2, after, target()).unwrap_err();
        let (queued, _) = adopted.try_recv().unwrap();
        assert_eq!(
            queued.peer_addr().unwrap(),
            before_client.local_addr().unwrap()
        );
        assert!(adopted.try_recv().is_err());
    }

    #[test]
    fn refusals_name_their_reason() {
        assert!(Refusal::NotRunning.to_string().contains("not running"));
        assert!(
            Refusal::Registered
                .to_string()
                .contains("already registered")
        );
        assert!(Closing.to_string().contains("closing"));
    }
}
