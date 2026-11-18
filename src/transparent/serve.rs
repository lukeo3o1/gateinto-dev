use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tracing::{debug, warn};

use super::state::State;
use crate::http::Authority;
#[cfg(windows)]
use crate::job::Job;
#[cfg(windows)]
use crate::proxy::Attribution;
use crate::proxy::{self, Adopter, Denial, Original};

pub(crate) const MAX_ATTRIBUTIONS: usize = 64;

const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

pub(crate) trait Attribute<K, J>: Send + Sync + 'static {
    fn attribute(
        &self,
        peer: SocketAddr,
        local: SocketAddr,
        jobs: &[(K, Arc<J>)],
        deadline: Instant,
    ) -> Result<Original<K>, Denial>;
}

#[cfg(windows)]
impl<K: Clone + Send + Sync + 'static> Attribute<K, Job> for Attribution {
    fn attribute(
        &self,
        peer: SocketAddr,
        local: SocketAddr,
        jobs: &[(K, Arc<Job>)],
        deadline: Instant,
    ) -> Result<Original<K>, Denial> {
        self.original(peer, local, jobs, deadline)
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) async fn serve<K, J, A>(
    listener: TcpListener,
    state: Arc<State<K, J>>,
    attribution: Arc<A>,
    handshake_timeout: Duration,
    shutdown: impl Future<Output = ()>,
) where
    K: Ord + Clone + Send + Sync + 'static,
    J: Send + Sync + 'static,
    A: Attribute<K, J>,
{
    let attributions = Arc::new(Semaphore::new(MAX_ATTRIBUTIONS));
    let mut dispatches = JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => break,
            Some(_) = dispatches.join_next(), if !dispatches.is_empty() => {}
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    let Ok(permit) = attributions.clone().try_acquire_owned() else {
                        debug!("refused a transparent connection: too many attributions in flight");
                        proxy::reset(stream);
                        continue;
                    };
                    let local = stream.local_addr();
                    dispatches.spawn(dispatch(
                        Unadopted(Some(stream)),
                        (peer, local),
                        state.clone(),
                        attribution.clone(),
                        handshake_timeout,
                        permit,
                    ));
                }
                Err(error) => {
                    warn!(%error, "accepting a transparent connection failed");
                    tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
                }
            },
        }
    }
    drop(listener);
    dispatches.shutdown().await;
}

struct Unadopted(Option<TcpStream>);

impl Unadopted {
    fn adopt(mut self, adopter: &Adopter, target: Authority) -> bool {
        let Some(stream) = self.0.take() else {
            return false;
        };
        adopter
            .adopt(stream, target)
            .map_err(|stream| self.0 = Some(stream))
            .is_ok()
    }
}

impl Drop for Unadopted {
    fn drop(&mut self) {
        if let Some(stream) = self.0.take() {
            proxy::reset(stream);
        }
    }
}

async fn dispatch<K, J, A>(
    stream: Unadopted,
    (peer, local): (SocketAddr, io::Result<SocketAddr>),
    state: Arc<State<K, J>>,
    attribution: Arc<A>,
    handshake_timeout: Duration,
    permit: OwnedSemaphorePermit,
) where
    K: Ord + Clone + Send + Sync + 'static,
    J: Send + Sync + 'static,
    A: Attribute<K, J>,
{
    let found = match local {
        Ok(local) => {
            let jobs = state.jobs();
            attribute(attribution, peer, local, jobs, handshake_timeout, permit).await
        }
        Err(error) => Err(Denial::Lookup(error.to_string())),
    };
    let Original {
        session,
        destination,
        ..
    } = match found {
        Ok(found) => found,
        Err(denial) => {
            debug!(denial = denial.kind(), "refused a transparent connection");
            return;
        }
    };
    match state.adopter(&session) {
        Some(adopter) => {
            if !stream.adopt(&adopter, Authority::from(destination)) {
                debug!("refused a transparent connection: its session cannot take it");
            }
        }
        None => debug!("refused a transparent connection: its session has closed"),
    }
}

async fn attribute<K, J, A>(
    attribution: Arc<A>,
    peer: SocketAddr,
    local: SocketAddr,
    jobs: Vec<(K, Arc<J>)>,
    handshake_timeout: Duration,
    permit: OwnedSemaphorePermit,
) -> Result<Original<K>, Denial>
where
    K: Send + 'static,
    J: Send + Sync + 'static,
    A: Attribute<K, J>,
{
    let deadline = tokio::time::Instant::now() + handshake_timeout;
    let until = deadline.into_std();
    let lookup = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        attribution.attribute(peer, local, &jobs, until)
    });
    match tokio::time::timeout_at(deadline, lookup).await {
        Ok(Ok(found)) => found,
        Ok(Err(_)) => Err(Denial::Lookup("the attribution task failed".to_owned())),
        Err(_) => Err(Denial::TimedOut),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::{Duration, Instant};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{mpsc, oneshot};
    use tokio::task::JoinHandle;
    use tokio::time::timeout;

    use super::*;
    use crate::http::Authority;
    use crate::proxy::{Adopter, Denial, Original};
    use crate::transparent::state::{Begin, State};

    type Sessions = State<u32, ()>;
    type Adopted = mpsc::Receiver<(TcpStream, Authority)>;

    const PID: u32 = 987_654_321;
    const DESTINATION: &str = "203.0.113.7:443";
    const LONG: Duration = Duration::from_secs(30);

    struct Fake<F>(F);

    impl<F> Attribute<u32, ()> for Fake<F>
    where
        F: Fn(SocketAddr, SocketAddr, &[(u32, Arc<()>)]) -> Result<Original<u32>, Denial>
            + Send
            + Sync
            + 'static,
    {
        fn attribute(
            &self,
            peer: SocketAddr,
            local: SocketAddr,
            jobs: &[(u32, Arc<()>)],
            _: Instant,
        ) -> Result<Original<u32>, Denial> {
            (self.0)(peer, local, jobs)
        }
    }

    fn to(session: u32) -> Result<Original<u32>, Denial> {
        Ok(Original {
            pid: PID,
            session,
            destination: DESTINATION.parse().unwrap(),
        })
    }

    fn running() -> Arc<Sessions> {
        let state = Arc::new(State::new());
        let Begin::Start(starter) = state.begin() else {
            panic!("a new engine state is stopped");
        };
        starter.finish(Ok(())).unwrap();
        state
    }

    fn session(state: &Sessions, key: u32, capacity: usize) -> Adopted {
        let (adopter, adopted) = Adopter::channel(capacity);
        state.register(key, Arc::new(()), adopter).unwrap();
        adopted
    }

    struct Served {
        addr: SocketAddr,
        stop: Option<oneshot::Sender<()>>,
        served: JoinHandle<()>,
    }

    impl Served {
        async fn connect(&self) -> TcpStream {
            TcpStream::connect(self.addr).await.unwrap()
        }

        async fn stop(mut self) {
            let _ = self.stop.take().unwrap().send(());
            timeout(Duration::from_secs(5), self.served)
                .await
                .expect("the loop did not end")
                .unwrap();
        }
    }

    async fn serve_with<F>(state: &Arc<Sessions>, attribution: F, handshake: Duration) -> Served
    where
        F: Fn(SocketAddr, SocketAddr, &[(u32, Arc<()>)]) -> Result<Original<u32>, Denial>
            + Send
            + Sync
            + 'static,
    {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel();
        let served = tokio::spawn(serve(
            listener,
            state.clone(),
            Arc::new(Fake(attribution)),
            handshake,
            async {
                let _ = stopped.await;
            },
        ));
        Served {
            addr,
            stop: Some(stop),
            served,
        }
    }

    async fn assert_reset(client: &mut TcpStream) {
        let mut received = [0; 64];
        match timeout(Duration::from_secs(5), client.read(&mut received)).await {
            Err(_) => panic!("the stream was not reset in time"),
            Ok(Err(error)) => assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset),
            Ok(Ok(n)) => panic!("expected a reset, got {:?}", &received[..n]),
        }
    }

    async fn adopted(adopted: &mut Adopted) -> (TcpStream, Authority) {
        timeout(Duration::from_secs(5), adopted.recv())
            .await
            .expect("nothing was adopted")
            .expect("the adopter is closed")
    }

    #[derive(Default)]
    struct Gate {
        open: Mutex<bool>,
        opened: Condvar,
        entered: AtomicUsize,
    }

    impl Gate {
        fn pass(&self) {
            self.entered.fetch_add(1, Ordering::SeqCst);
            let open = self.open.lock().unwrap();
            drop(self.opened.wait_while(open, |open| !*open).unwrap());
        }

        fn release(&self) {
            *self.open.lock().unwrap() = true;
            self.opened.notify_all();
        }

        fn opened_on_drop(self: &Arc<Self>) -> OpenedOnDrop {
            OpenedOnDrop(self.clone())
        }

        async fn entered(&self, count: usize) {
            timeout(Duration::from_secs(10), async {
                while self.entered.load(Ordering::SeqCst) < count {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("the attributions did not start");
        }
    }

    struct OpenedOnDrop(Arc<Gate>);

    impl Drop for OpenedOnDrop {
        fn drop(&mut self) {
            self.0.release();
        }
    }

    #[tokio::test]
    async fn an_attributed_stream_is_adopted_by_its_session_with_its_destination() {
        let state = running();
        let mut first = session(&state, 1, 4);
        let mut second = session(&state, 2, 4);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let served = serve_with(
            &state,
            {
                let seen = seen.clone();
                move |peer, local, jobs| {
                    let keys: Vec<u32> = jobs.iter().map(|(key, _)| *key).collect();
                    seen.lock().unwrap().push((peer, local, keys));
                    to(2)
                }
            },
            LONG,
        )
        .await;

        let mut client = served.connect().await;
        let (mut stream, target) = adopted(&mut second).await;
        assert_eq!(target, DESTINATION.parse::<Authority>().unwrap());
        assert_eq!(
            *seen.lock().unwrap(),
            [(
                client.local_addr().unwrap(),
                client.peer_addr().unwrap(),
                vec![1, 2]
            )]
        );
        assert!(first.try_recv().is_err());
        client.write_all(b"ping").await.unwrap();
        let mut received = [0; 4];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"ping");
        served.stop().await;
    }

    #[tokio::test]
    async fn a_denial_a_timeout_or_a_panic_resets_the_stream_and_reaches_no_session() {
        type Lookup = fn() -> Result<Original<u32>, Denial>;
        let lookups: [Lookup; 4] = [
            || Err(Denial::NotInJob),
            || Err(Denial::SelfTarget),
            || {
                std::thread::sleep(Duration::from_secs(1));
                to(1)
            },
            || panic!("the attribution failed"),
        ];
        for lookup in lookups {
            let state = running();
            let mut adopter = session(&state, 1, 4);
            let served =
                serve_with(&state, move |_, _, _| lookup(), Duration::from_millis(100)).await;
            let started = Instant::now();
            let mut client = served.connect().await;
            assert_reset(&mut client).await;
            assert!(started.elapsed() < Duration::from_millis(900));
            served.stop().await;
            assert!(adopter.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn a_session_that_unregistered_during_the_attribution_is_reset() {
        let state = running();
        let mut adopter = session(&state, 1, 4);
        let served = serve_with(
            &state,
            {
                let state = state.clone();
                move |_, _, jobs| {
                    assert_eq!(jobs.len(), 1);
                    assert!(state.unregister(&1));
                    to(1)
                }
            },
            LONG,
        )
        .await;
        let mut client = served.connect().await;
        assert_reset(&mut client).await;
        served.stop().await;
        assert!(adopter.try_recv().is_err());
    }

    #[tokio::test]
    async fn a_stream_handed_back_by_a_full_or_closed_session_is_reset() {
        let state = running();
        let mut full = session(&state, 1, 1);
        drop(session(&state, 2, 1));
        let next = Arc::new(Mutex::new(vec![2, 1, 1, 1]));
        let served = serve_with(
            &state,
            {
                let next = next.clone();
                move |_, _, _| to(next.lock().unwrap().pop().unwrap())
            },
            LONG,
        )
        .await;
        let _first = served.connect().await;
        let (_kept, _) = adopted(&mut full).await;
        let mut queued = served.connect().await;
        timeout(Duration::from_secs(5), async {
            while full.is_empty() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the second stream was not queued");
        let mut beyond = served.connect().await;
        assert_reset(&mut beyond).await;
        let mut closed = served.connect().await;
        assert_reset(&mut closed).await;
        assert!(
            timeout(Duration::from_millis(100), queued.read(&mut [0; 1]))
                .await
                .is_err()
        );
        served.stop().await;
    }

    #[tokio::test]
    async fn attributions_beyond_the_bound_are_reset_at_once() {
        let state = running();
        let mut adopter = session(&state, 1, 4);
        let gate = Arc::new(Gate::default());
        let _opened = gate.opened_on_drop();
        let served = serve_with(
            &state,
            {
                let gate = gate.clone();
                move |_, _, _| {
                    gate.pass();
                    Err(Denial::NotFound)
                }
            },
            LONG,
        )
        .await;
        let mut waiting = Vec::new();
        for _ in 0..MAX_ATTRIBUTIONS {
            waiting.push(served.connect().await);
        }
        gate.entered(MAX_ATTRIBUTIONS).await;
        let mut beyond = served.connect().await;
        assert_reset(&mut beyond).await;
        assert_eq!(gate.entered.load(Ordering::SeqCst), MAX_ATTRIBUTIONS);
        gate.release();
        for client in &mut waiting {
            assert_reset(client).await;
        }
        let mut after = served.connect().await;
        assert_reset(&mut after).await;
        assert_eq!(gate.entered.load(Ordering::SeqCst), MAX_ATTRIBUTIONS + 1);
        served.stop().await;
        assert!(adopter.try_recv().is_err());
    }

    #[tokio::test]
    async fn shutdown_ends_the_loop_and_aborts_the_attributions_in_flight() {
        let state = running();
        let mut adopter = session(&state, 1, 4);
        let gate = Arc::new(Gate::default());
        let _opened = gate.opened_on_drop();
        let returned = Arc::new(AtomicUsize::new(0));
        let served = serve_with(
            &state,
            {
                let (gate, returned) = (gate.clone(), returned.clone());
                move |_, _, _| {
                    gate.pass();
                    returned.fetch_add(1, Ordering::SeqCst);
                    to(1)
                }
            },
            LONG,
        )
        .await;
        let addr = served.addr;
        let mut client = served.connect().await;
        gate.entered(1).await;
        served.stop().await;
        assert_reset(&mut client).await;
        assert!(TcpStream::connect(addr).await.is_err());
        gate.release();
        timeout(Duration::from_secs(5), async {
            while returned.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(adopter.try_recv().is_err());
    }

    #[tokio::test]
    async fn refusals_are_logged_by_kind_without_addresses_ports_or_pids() {
        let logs = crate::test_logs::capture();
        let state = running();
        let mut adopter = session(&state, 1, 4);
        type Lookup = fn() -> Result<Original<u32>, Denial>;
        let lookups: Arc<Mutex<Vec<Lookup>>> = Arc::new(Mutex::new(vec![
            || to(9),
            || to(1),
            || Err(Denial::NotInJob),
            || Err(Denial::Lookup(format!("access denied for {DESTINATION}"))),
        ]));
        let served = serve_with(
            &state,
            {
                let lookups = lookups.clone();
                move |_, _, _| (lookups.lock().unwrap().pop().unwrap())()
            },
            LONG,
        )
        .await;
        let mut addresses = vec![served.addr.to_string(), DESTINATION.to_owned()];
        for _ in 0..2 {
            let mut client = served.connect().await;
            addresses.push(client.local_addr().unwrap().to_string());
            assert_reset(&mut client).await;
        }
        let client = served.connect().await;
        addresses.push(client.local_addr().unwrap().to_string());
        adopted(&mut adopter).await;
        let mut gone = served.connect().await;
        addresses.push(gone.local_addr().unwrap().to_string());
        assert_reset(&mut gone).await;
        served.stop().await;

        let refused = logs.lines(" DEBUG ");
        assert_eq!(refused.len(), 3, "{:?}", logs.lines(""));
        assert!(refused[0].contains("lookup"), "{refused:?}");
        assert!(refused[1].contains("not-in-job"), "{refused:?}");
        assert!(refused[2].contains("session"), "{refused:?}");
        for line in logs.lines("") {
            for address in &addresses {
                assert!(!line.contains(address.as_str()), "{line}");
            }
            assert!(!line.contains(&PID.to_string()), "{line}");
            assert!(!line.contains("access denied"), "{line}");
        }
    }
}
