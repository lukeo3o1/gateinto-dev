use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tracing::{debug, warn};

use super::state::{Generation, State};
use crate::http::Authority;
#[cfg(windows)]
use crate::job::Job;
#[cfg(windows)]
use crate::proxy::Attribution;
use crate::proxy::{self, Denial, Original};

pub(crate) const MAX_ATTRIBUTIONS: usize = 64;

const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

#[cfg(windows)]
mod windows;

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

#[cfg_attr(not(any(test, windows)), allow(dead_code))]
pub(crate) async fn serve<K, J, A>(
    listener: TcpListener,
    state: Arc<State<K, J>>,
    generation: Generation,
    attribution: Arc<A>,
    handshake_timeout: Duration,
    shutdown: impl Future<Output = ()>,
) where
    K: Ord + Clone + Send + Sync + 'static,
    J: Send + Sync + 'static,
    A: Attribute<K, J>,
{
    let dispatcher = Arc::new(Dispatcher {
        state,
        generation,
        attribution,
        handshake_timeout,
    });
    run(listener, dispatcher, reflectable, shutdown).await;
}

fn reflectable(peer: SocketAddr, local: SocketAddr) -> bool {
    let peer = peer.ip().to_canonical();
    !peer.is_loopback() && peer != local.ip().to_canonical() && !of_this_host(peer)
}

// A table that cannot be read counts as remote: that costs at most an attribution permit, while
// counting a remote peer as local would reset a genuine stream.
#[cfg(windows)]
fn of_this_host(ip: IpAddr) -> bool {
    windows::addresses().is_ok_and(|table| among(ip, table))
}

// Transparent sessions exist only on Windows. Elsewhere only an address of this host can be bound,
// which keeps the check testable; any failure counts as remote, as above.
#[cfg(not(windows))]
fn of_this_host(ip: IpAddr) -> bool {
    std::net::UdpSocket::bind((ip, 0)).is_ok()
}

#[cfg(any(windows, test))]
#[derive(Debug, Clone, Copy)]
enum DadState {
    Invalid,
    Tentative,
    Duplicate,
    Deprecated,
    Preferred,
}

// An address that is not in use (tentative, duplicate or invalid) counts as remote too.
#[cfg(any(windows, test))]
fn among(ip: IpAddr, table: impl IntoIterator<Item = (std::net::Ipv4Addr, DadState)>) -> bool {
    let IpAddr::V4(ip) = ip.to_canonical() else {
        return false;
    };
    table.into_iter().any(|(address, state)| {
        address == ip && matches!(state, DadState::Preferred | DadState::Deprecated)
    })
}

async fn run<K, J, A>(
    listener: TcpListener,
    dispatcher: Arc<Dispatcher<K, J, A>>,
    reflectable: impl Fn(SocketAddr, SocketAddr) -> bool,
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
                    let local = match reflected(&stream, peer, &reflectable) {
                        Ok(local) => local,
                        Err(denial) => {
                            refused(&denial);
                            proxy::reset(stream);
                            continue;
                        }
                    };
                    let Ok(permit) = attributions.clone().try_acquire_owned() else {
                        debug!("refused a transparent connection: too many attributions in flight");
                        proxy::reset(stream);
                        continue;
                    };
                    dispatches.spawn(dispatcher.clone().dispatch(
                        Unadopted(Some(stream)),
                        peer,
                        local,
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

fn reflected(
    stream: &TcpStream,
    peer: SocketAddr,
    reflectable: impl Fn(SocketAddr, SocketAddr) -> bool,
) -> Result<SocketAddr, Denial> {
    let local = stream
        .local_addr()
        .map_err(|error| Denial::Lookup(error.to_string()))?;
    if !reflectable(peer, local) {
        return Err(Denial::SelfTarget);
    }
    Ok(local)
}

fn refused(denial: &Denial) {
    debug!(denial = denial.kind(), "refused a transparent connection");
}

struct Unadopted(Option<TcpStream>);

impl Unadopted {
    fn adopt<K: Ord + Clone, J>(
        mut self,
        state: &State<K, J>,
        generation: Generation,
        session: &K,
        target: Authority,
    ) -> bool {
        let Some(stream) = self.0.take() else {
            return false;
        };
        state
            .adopt(generation, session, stream, target)
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

struct Dispatcher<K, J, A> {
    state: Arc<State<K, J>>,
    generation: Generation,
    attribution: Arc<A>,
    handshake_timeout: Duration,
}

impl<K, J, A> Dispatcher<K, J, A>
where
    K: Ord + Clone + Send + Sync + 'static,
    J: Send + Sync + 'static,
    A: Attribute<K, J>,
{
    async fn dispatch(
        self: Arc<Self>,
        stream: Unadopted,
        peer: SocketAddr,
        local: SocketAddr,
        permit: OwnedSemaphorePermit,
    ) {
        let Original {
            session,
            destination,
            ..
        } = match self.attribute(peer, local, permit).await {
            Ok(found) => found,
            Err(denial) => return refused(&denial),
        };
        let target = Authority::from(destination);
        if !stream.adopt(&self.state, self.generation, &session, target) {
            debug!("refused a transparent connection: its session has closed or cannot take it");
        }
    }

    async fn attribute(
        &self,
        peer: SocketAddr,
        local: SocketAddr,
        permit: OwnedSemaphorePermit,
    ) -> Result<Original<K>, Denial> {
        let jobs = self.state.jobs(self.generation);
        let attribution = self.attribution.clone();
        let deadline = tokio::time::Instant::now() + self.handshake_timeout;
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
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::{Duration, Instant};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpSocket, TcpStream};
    use tokio::sync::{mpsc, oneshot};
    use tokio::task::JoinHandle;
    use tokio::time::timeout;

    use super::*;
    use crate::http::Authority;
    use crate::proxy::{Adopter, Denial, Original};
    use crate::transparent::state::{Begin, Generation, Phase, State, Terminate};

    type Sessions = State<u32, ()>;
    type Adopted = mpsc::Receiver<(TcpStream, Authority)>;

    const PID: u32 = 987_654_321;
    const DESTINATION: &str = "203.0.113.7:443";
    const LONG: Duration = Duration::from_secs(30);

    impl Terminate for () {
        fn terminate(&self) -> std::io::Result<()> {
            Ok(())
        }
    }

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

    fn start(state: &Arc<Sessions>) -> Generation {
        let Begin::Start(starter) = state.begin() else {
            panic!("the engine state is not stopped");
        };
        let generation = starter.generation();
        starter.finish(Ok(())).unwrap();
        generation
    }

    fn running() -> Arc<Sessions> {
        let state = Arc::new(State::new());
        start(&state);
        state
    }

    fn current(state: &Sessions) -> Generation {
        let Phase::Running(generation) = state.phase() else {
            panic!("the engine is not running");
        };
        generation
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

    async fn listening<S>(start: impl FnOnce(TcpListener, oneshot::Receiver<()>) -> S) -> Served
    where
        S: Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel();
        let served = tokio::spawn(start(listener, stopped));
        Served {
            addr,
            stop: Some(stop),
            served,
        }
    }

    async fn serve_in<F>(
        state: &Arc<Sessions>,
        generation: Generation,
        attribution: F,
        handshake: Duration,
        reflectable: impl Fn(SocketAddr, SocketAddr) -> bool + Send + 'static,
    ) -> Served
    where
        F: Fn(SocketAddr, SocketAddr, &[(u32, Arc<()>)]) -> Result<Original<u32>, Denial>
            + Send
            + Sync
            + 'static,
    {
        let dispatcher = Arc::new(Dispatcher {
            state: state.clone(),
            generation,
            attribution: Arc::new(Fake(attribution)),
            handshake_timeout: handshake,
        });
        listening(|listener, stopped| {
            run(listener, dispatcher, reflectable, async {
                let _ = stopped.await;
            })
        })
        .await
    }

    async fn serve_with<F>(state: &Arc<Sessions>, attribution: F, handshake: Duration) -> Served
    where
        F: Fn(SocketAddr, SocketAddr, &[(u32, Arc<()>)]) -> Result<Original<u32>, Denial>
            + Send
            + Sync
            + 'static,
    {
        serve_in(state, current(state), attribution, handshake, |_, _| true).await
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

    #[test]
    fn only_a_remote_peer_other_than_the_local_address_can_be_reflected() {
        let addr = |text: &str| text.parse::<SocketAddr>().unwrap();
        let local = addr("192.168.1.10:50123");
        for peer in [
            "127.0.0.1:50000",
            "127.45.6.7:50000",
            "[::1]:50000",
            "[::ffff:127.0.0.1]:50000",
            "192.168.1.10:50000",
            "192.168.1.10:50123",
            "[::ffff:192.168.1.10]:50000",
        ] {
            assert!(!reflectable(addr(peer), local), "{peer}");
        }
        let mapped = addr("[::ffff:192.168.1.10]:50123");
        assert!(!reflectable(addr("192.168.1.10:50000"), mapped));
        for peer in [
            "203.0.113.7:50000",
            "203.0.113.7:50123",
            "[::ffff:203.0.113.7]:50000",
        ] {
            assert!(reflectable(addr(peer), local), "{peer}");
            assert!(reflectable(addr(peer), mapped), "{peer}");
        }
        let v6 = addr("[2001:db8::1]:50123");
        assert!(reflectable(addr("[2001:db8::7]:50000"), v6));
        assert!(!reflectable(addr("[2001:db8::1]:50000"), v6));
    }

    fn host() -> Ipv4Addr {
        let probe = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        // Connecting a UDP socket sends nothing; it only picks the address of the outbound route.
        probe
            .connect((Ipv4Addr::new(192, 0, 2, 1), 9))
            .expect("this host has no IPv4 default route");
        let std::net::IpAddr::V4(ip) = probe.local_addr().unwrap().ip() else {
            panic!("the probe is not IPv4");
        };
        assert!(
            !ip.is_loopback() && !ip.is_unspecified(),
            "this host has no non-loopback IPv4 address"
        );
        ip
    }

    #[test]
    fn a_peer_with_another_address_of_this_host_is_not_reflectable() {
        let host = host();
        for local in [
            "127.0.0.1:50123",
            "[::ffff:127.0.0.1]:50123",
            "203.0.113.9:50123",
        ] {
            let local = local.parse().unwrap();
            for peer in [
                SocketAddr::from((host, 50000)),
                SocketAddr::from((host.to_ipv6_mapped(), 50000)),
            ] {
                assert!(!reflectable(peer, local), "{peer} {local}");
            }
        }
    }

    #[test]
    fn only_addresses_of_this_host_are_local() {
        assert!(of_this_host(host().into()));
        for remote in DOCUMENTATION {
            assert!(!of_this_host(remote.parse().unwrap()), "{remote}");
        }
    }

    const DOCUMENTATION: [&str; 3] = ["203.0.113.7", "198.51.100.7", "2001:db8::7"];

    #[test]
    fn a_peer_matches_an_address_of_the_table_canonically() {
        let ip = |text: &str| text.parse::<std::net::IpAddr>().unwrap();
        let table = [
            (Ipv4Addr::new(192, 168, 1, 10), DadState::Preferred),
            (Ipv4Addr::new(10, 0, 0, 5), DadState::Deprecated),
        ];
        for local in [
            "192.168.1.10",
            "::ffff:192.168.1.10",
            "10.0.0.5",
            "::ffff:10.0.0.5",
        ] {
            assert!(among(ip(local), table), "{local}");
        }
        for remote in [
            "192.168.1.11",
            "10.0.0.6",
            "::ffff:10.0.0.6",
            "::192.168.1.10",
            "fe80::1",
            "::1",
        ] {
            assert!(!among(ip(remote), table), "{remote}");
        }
        assert!(!among(ip("192.168.1.10"), []));
    }

    #[test]
    fn only_a_preferred_or_deprecated_address_is_of_this_host() {
        let address = Ipv4Addr::new(192, 168, 1, 10);
        for (state, local) in [
            (DadState::Preferred, true),
            (DadState::Deprecated, true),
            (DadState::Tentative, false),
            (DadState::Duplicate, false),
            (DadState::Invalid, false),
        ] {
            for peer in [address.into(), address.to_ipv6_mapped().into()] {
                assert_eq!(among(peer, [(address, state)]), local, "{peer} {state:?}");
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn the_address_table_lists_this_hosts_address_and_no_documentation_address() {
        let table = windows::addresses().unwrap();
        assert!(among(host().into(), table.iter().copied()), "{table:?}");
        for remote in DOCUMENTATION {
            assert!(
                !among(remote.parse().unwrap(), table.iter().copied()),
                "{remote}"
            );
        }
    }

    async fn the_real_listener_resets_without_attributing(client: TcpSocket) {
        let logs = crate::test_logs::capture();
        let state = running();
        let mut adopter = session(&state, 1, 4);
        let called = Arc::new(AtomicUsize::new(0));
        let generation = current(&state);
        let attribution = Arc::new(Fake({
            let called = called.clone();
            move |_: SocketAddr, _: SocketAddr, _: &[(u32, Arc<()>)]| {
                called.fetch_add(1, Ordering::SeqCst);
                to(1)
            }
        }));
        let served = listening({
            let state = state.clone();
            move |listener, stopped| {
                serve(listener, state, generation, attribution, LONG, async {
                    let _ = stopped.await;
                })
            }
        })
        .await;
        let mut client = client.connect(served.addr).await.unwrap();
        let addresses = [
            client.local_addr().unwrap().to_string(),
            served.addr.to_string(),
        ];
        assert_reset(&mut client).await;
        served.stop().await;
        assert_eq!(called.load(Ordering::SeqCst), 0);
        assert!(adopter.try_recv().is_err());
        let refused = logs.lines(" DEBUG ");
        assert_eq!(refused.len(), 1, "{:?}", logs.lines(""));
        assert!(refused[0].contains("self-target"), "{refused:?}");
        for address in addresses {
            assert!(!refused[0].contains(&address), "{refused:?}");
        }
    }

    #[tokio::test]
    async fn the_listener_resets_a_loopback_peer_without_attributing_it() {
        the_real_listener_resets_without_attributing(TcpSocket::new_v4().unwrap()).await;
    }

    // Windows may refuse a client bound to a non-loopback address that dials a loopback listener
    // (strong host model), so this runs where that is known to work.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_listener_resets_a_peer_with_another_address_of_this_host_without_attributing_it() {
        let client = TcpSocket::new_v4().unwrap();
        client.bind(SocketAddr::from((host(), 0))).unwrap();
        the_real_listener_resets_without_attributing(client).await;
    }

    #[tokio::test]
    async fn peers_that_can_never_be_reflected_take_no_permit_and_reach_no_attribution() {
        let state = running();
        let mut adopter = session(&state, 1, 4);
        let gate = Arc::new(Gate::default());
        let _opened = gate.opened_on_drop();
        let genuine = TcpSocket::new_v4().unwrap();
        genuine
            .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .unwrap();
        let port = genuine.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let served = serve_in(
            &state,
            current(&state),
            {
                let (gate, seen) = (gate.clone(), seen.clone());
                move |peer: SocketAddr, _, _| {
                    seen.lock().unwrap().push(peer);
                    if peer.port() == port {
                        return to(1);
                    }
                    gate.pass();
                    Err(Denial::NotFound)
                }
            },
            LONG,
            move |peer, local| peer.port() == port || reflectable(peer, local),
        )
        .await;
        for _ in 0..=MAX_ATTRIBUTIONS {
            let mut direct = served.connect().await;
            assert_reset(&mut direct).await;
        }
        let client = genuine.connect(served.addr).await.unwrap();
        let (stream, _) = adopted(&mut adopter).await;
        assert_eq!(stream.peer_addr().unwrap(), client.local_addr().unwrap());
        assert_eq!(*seen.lock().unwrap(), [client.local_addr().unwrap()]);
        assert_eq!(gate.entered.load(Ordering::SeqCst), 0);
        served.stop().await;
    }

    #[tokio::test]
    async fn an_older_generations_listener_dispatches_into_no_newer_session() {
        let state = Arc::new(State::new());
        let old = start(&state);
        let mut old_adopter = session(&state, 1, 4);
        let snapshots = Arc::new(Mutex::new(Vec::new()));
        let attribution = |snapshots: Arc<Mutex<Vec<Vec<u32>>>>| {
            move |_: SocketAddr, _: SocketAddr, jobs: &[(u32, Arc<()>)]| {
                let keys = jobs.iter().map(|(key, _)| *key).collect();
                snapshots.lock().unwrap().push(keys);
                to(2)
            }
        };
        let old_served = serve_in(&state, old, attribution(snapshots.clone()), LONG, |_, _| {
            true
        })
        .await;
        assert_eq!(state.stop(old), [1]);
        let new = start(&state);
        let mut new_adopter = session(&state, 2, 4);

        let mut stale = old_served.connect().await;
        assert_reset(&mut stale).await;
        assert_eq!(*snapshots.lock().unwrap(), [Vec::<u32>::new()]);
        assert!(new_adopter.try_recv().is_err());

        let new_served = serve_in(&state, new, attribution(snapshots.clone()), LONG, |_, _| {
            true
        })
        .await;
        let _client = new_served.connect().await;
        adopted(&mut new_adopter).await;
        assert_eq!(*snapshots.lock().unwrap(), [vec![], vec![2]]);
        old_served.stop().await;
        new_served.stop().await;
        assert!(old_adopter.try_recv().is_err());
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
