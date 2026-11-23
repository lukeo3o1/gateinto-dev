use std::collections::HashMap;
use std::io;
use std::mem::offset_of;
use std::net::SocketAddr;
use std::ptr::null_mut;
use std::sync::Arc;
use std::time::Instant;

use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP_STATE_CLOSE_WAIT, MIB_TCP_STATE_ESTAB, MIB_TCP_STATE_TIME_WAIT,
    MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    TCP_TABLE_OWNER_PID_CONNECTIONS,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::Security::{EqualSid, TOKEN_QUERY};
use windows_sys::Win32::System::JobObjects::IsProcessInJob;
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

use super::{
    Denial, Family, LOOKUP_ATTEMPTS, LOOKUP_DELAY, Original, Owners, Row, TcpState, all_rows,
    confirmed, entries, lookup, one_session, original, retry, v4, v6,
};
use crate::job::Job;
use crate::token::{Handle, TokenUserInfo};

const TABLE_ATTEMPTS: u32 = 8;

pub(crate) struct Attribution {
    own: TokenUserInfo,
}

impl Attribution {
    pub(crate) fn new() -> io::Result<Self> {
        Ok(Self {
            own: TokenUserInfo::current()?,
        })
    }

    pub(crate) fn original<K: Clone>(
        &self,
        peer: SocketAddr,
        local: SocketAddr,
        jobs: &[(K, Arc<Job>)],
        deadline: Instant,
    ) -> Result<Original<K>, Denial> {
        self.attribute(peer, local, jobs, deadline, rows)
    }

    fn attribute<K: Clone>(
        &self,
        peer: SocketAddr,
        local: SocketAddr,
        jobs: &[(K, Arc<Job>)],
        deadline: Instant,
        tables: impl Fn(Family) -> io::Result<Vec<Row>>,
    ) -> Result<Original<K>, Denial> {
        retry(deadline, || {
            let mut owners = Admissions {
                own: &self.own,
                jobs,
                verdicts: HashMap::new(),
                held: Vec::new(),
            };
            confirmed(|| owners.read(peer, local, &tables))
        })
    }
}

struct Admissions<'a, K> {
    own: &'a TokenUserInfo,
    jobs: &'a [(K, Arc<Job>)],
    verdicts: HashMap<u32, Result<K, Denial>>,
    held: Vec<Handle>,
}

impl<K: Clone> Admissions<'_, K> {
    fn read(
        &mut self,
        peer: SocketAddr,
        local: SocketAddr,
        tables: impl Fn(Family) -> io::Result<Vec<Row>>,
    ) -> Result<Original<K>, Denial> {
        original(all_rows(peer, tables)?, peer, local, |pid| self.admit(pid))
    }

    fn admit(&mut self, pid: u32) -> Result<K, Denial> {
        if let Some(verdict) = self.verdicts.get(&pid) {
            return verdict.clone();
        }
        let verdict = open(pid).and_then(|process| {
            let verdict = same_user(&process, self.own)
                .and_then(|()| one_session(self.jobs, |job| in_job(&process, job)));
            self.held.push(process);
            verdict
        });
        self.verdicts.insert(pid, verdict.clone());
        verdict
    }
}

pub(super) struct System {
    own: TokenUserInfo,
    job: Option<Arc<Job>>,
}

impl System {
    pub(super) fn new(job: Option<Arc<Job>>) -> io::Result<Self> {
        Ok(Self {
            own: TokenUserInfo::current()?,
            job,
        })
    }

    fn owner(&self, peer: SocketAddr, local: SocketAddr) -> Result<Option<u32>, Denial> {
        lookup(peer, local, rows)
    }

    fn find(&self, peer: SocketAddr, local: SocketAddr) -> Result<u32, Denial> {
        for attempt in 1..=LOOKUP_ATTEMPTS {
            if let Some(pid) = self.owner(peer, local)? {
                return Ok(pid);
            }
            if attempt < LOOKUP_ATTEMPTS {
                std::thread::sleep(LOOKUP_DELAY);
            }
        }
        Err(Denial::NotFound)
    }
}

impl Owners for System {
    fn check(&self, peer: SocketAddr, local: SocketAddr, _: Instant) -> Result<(), Denial> {
        let pid = self.find(peer, local)?;
        let process = open(pid)?;
        if self.owner(peer, local)? != Some(pid) {
            return Err(Denial::NotFound);
        }
        same_user(&process, &self.own)?;
        if let Some(job) = &self.job
            && !in_job(&process, job)?
        {
            return Err(Denial::NotInJob);
        }
        Ok(())
    }
}

fn failed(error: io::Error) -> Denial {
    Denial::Lookup(error.to_string())
}

fn open(pid: u32) -> Result<Handle, Denial> {
    // SAFETY: OpenProcess returns an owned handle or null.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(failed(io::Error::last_os_error()));
    }
    Ok(Handle(process))
}

fn same_user(process: &Handle, own: &TokenUserInfo) -> Result<(), Denial> {
    let mut token = null_mut();
    // SAFETY: process is open with query access; token receives an owned handle.
    if unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut token) } == 0 {
        return Err(failed(io::Error::last_os_error()));
    }
    let user = TokenUserInfo::of(&Handle(token)).map_err(failed)?;
    // SAFETY: both SIDs point into live TOKEN_USER buffers.
    if unsafe { EqualSid(user.sid(), own.sid()) } == 0 {
        return Err(Denial::OtherUser);
    }
    Ok(())
}

fn in_job(process: &Handle, job: &Job) -> Result<bool, Denial> {
    let mut inside = 0;
    // SAFETY: both handles are open and inside is writable.
    if unsafe { IsProcessInJob(process.0, job.handle(), &mut inside) } == 0 {
        return Err(failed(io::Error::last_os_error()));
    }
    Ok(inside != 0)
}

fn rows(family: Family) -> io::Result<Vec<Row>> {
    match family {
        Family::V4 => {
            let table = table(AF_INET)?;
            // SAFETY: the table holds a MIB_TCPTABLE_OWNER_PID followed by its rows, which are
            // plain integers.
            let rows = unsafe {
                entries::<MIB_TCPROW_OWNER_PID>(&table, offset_of!(MIB_TCPTABLE_OWNER_PID, table))
            }?;
            Ok(rows
                .iter()
                .map(|row| Row {
                    local: v4(row.dwLocalAddr, row.dwLocalPort),
                    remote: v4(row.dwRemoteAddr, row.dwRemotePort),
                    pid: row.dwOwningPid,
                    state: tcp_state(row.dwState),
                })
                .collect())
        }
        Family::V6 => {
            let table = table(AF_INET6)?;
            // SAFETY: the table holds a MIB_TCP6TABLE_OWNER_PID followed by its rows, which are
            // plain integers and byte arrays.
            let rows = unsafe {
                entries::<MIB_TCP6ROW_OWNER_PID>(&table, offset_of!(MIB_TCP6TABLE_OWNER_PID, table))
            }?;
            Ok(rows
                .iter()
                .map(|row| Row {
                    local: v6(row.ucLocalAddr, row.dwLocalPort),
                    remote: v6(row.ucRemoteAddr, row.dwRemotePort),
                    pid: row.dwOwningPid,
                    state: tcp_state(row.dwState),
                })
                .collect())
        }
    }
}

fn tcp_state(state: u32) -> TcpState {
    match state.cast_signed() {
        MIB_TCP_STATE_ESTAB => TcpState::Established,
        MIB_TCP_STATE_CLOSE_WAIT => TcpState::CloseWait,
        MIB_TCP_STATE_TIME_WAIT => TcpState::TimeWait,
        _ => TcpState::Other,
    }
}

fn table(family: u16) -> io::Result<Vec<u64>> {
    let mut size = 0;
    let mut buffer: Vec<u64> = Vec::new();
    for _ in 0..TABLE_ATTEMPTS {
        // SAFETY: buffer is 8-byte aligned and holds size bytes, or is null with size 0.
        let status = unsafe {
            GetExtendedTcpTable(
                if buffer.is_empty() {
                    null_mut()
                } else {
                    buffer.as_mut_ptr().cast()
                },
                &mut size,
                0,
                u32::from(family),
                TCP_TABLE_OWNER_PID_CONNECTIONS,
                0,
            )
        };
        match status {
            NO_ERROR => return Ok(buffer),
            ERROR_INSUFFICIENT_BUFFER => buffer = vec![0; (size as usize).div_ceil(8)],
            error => return Err(io::Error::from_raw_os_error(error as i32)),
        }
    }
    Err(io::Error::other("the connection table kept growing"))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::net::{IpAddr, Ipv4Addr};
    use std::os::windows::io::AsRawSocket;
    use std::time::Duration;

    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpSocket, TcpStream};
    use windows_sys::Win32::Networking::WinSock::{IPPROTO_IPV6, IPV6_V6ONLY, setsockopt};

    use super::*;
    use crate::job::Process;
    use crate::transparent::listener::reserve;

    const CLIENT: &str = "a_client_holds_its_connection_until_the_server_ends_it";
    const IPV4: &str = "ipv4";
    const DUAL_STACK: &str = "dual-stack";
    const SESSION: &str = "session";
    const LISTENER_PORT: u16 = 1;

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(10)
    }

    // Without the engine no socket of the listener is connected to the peer, so the tests add
    // the row that reflection would give its accepted socket.
    fn reflected_to(
        peer: SocketAddr,
        local: SocketAddr,
    ) -> impl Fn(Family) -> io::Result<Vec<Row>> {
        move |family| {
            let mut found = rows(family)?;
            if family == Family::V4 {
                found.push(Row {
                    local,
                    remote: peer,
                    pid: std::process::id(),
                    state: TcpState::Established,
                });
            }
            Ok(found)
        }
    }

    fn host() -> Ipv4Addr {
        let probe = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        // Connecting a UDP socket sends nothing; it only picks the address of the outbound route.
        probe.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).unwrap();
        let IpAddr::V4(ip) = probe.local_addr().unwrap().ip() else {
            panic!("the probe is not IPv4");
        };
        assert!(
            !ip.is_loopback() && !ip.is_unspecified(),
            "this host has no non-loopback IPv4 address"
        );
        ip
    }

    struct Client {
        process: Process,
        peer: SocketAddr,
        server: SocketAddr,
        _accepted: TcpStream,
    }

    impl Client {
        async fn start(job: &Arc<Job>, mode: &str) -> Self {
            let listener = TcpListener::bind((host(), 0)).await.unwrap();
            let server = listener.local_addr().unwrap();
            let name = format!("{}::{CLIENT}", module_path!().split_once("::").unwrap().1);
            let args = [
                "--exact",
                &name,
                "--ignored",
                "--test-threads=1",
                &server.to_string(),
                mode,
            ]
            .map(OsString::from);
            let process = job.spawn(&std::env::current_exe().unwrap(), &args).unwrap();
            let (accepted, peer) = tokio::time::timeout(Duration::from_secs(60), listener.accept())
                .await
                .expect("the client did not connect")
                .unwrap();
            Self {
                process,
                peer,
                server,
                _accepted: accepted,
            }
        }

        fn reflected(&self, listener_port: u16) -> (SocketAddr, SocketAddr) {
            (
                SocketAddr::new(self.server.ip(), self.peer.port()),
                SocketAddr::new(self.peer.ip(), listener_port),
            )
        }
    }

    async fn attributed_to_its_session(mode: &str) {
        let job = Arc::new(Job::new().unwrap());
        let jobs = [
            ("other", Arc::new(Job::new().unwrap())),
            (SESSION, job.clone()),
        ];
        let mut client = Client::start(&job, mode).await;
        let (peer, local) = client.reflected(LISTENER_PORT);
        let found = Attribution::new().unwrap().attribute(
            peer,
            local,
            &jobs,
            far(),
            reflected_to(peer, local),
        );
        assert_eq!(
            found,
            Ok(Original {
                pid: client.process.id(),
                session: SESSION,
                destination: client.server,
            })
        );
        client.process.kill().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_client_in_a_session_job_is_attributed_to_that_session_with_its_destination() {
        attributed_to_its_session(IPV4).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_dual_stack_client_is_attributed_through_its_ipv4_mapped_row() {
        attributed_to_its_session(DUAL_STACK).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_client_in_a_job_of_no_live_session_is_refused() {
        let job = Arc::new(Job::new().unwrap());
        let mut client = Client::start(&job, IPV4).await;
        let (peer, local) = client.reflected(LISTENER_PORT);
        let attribution = Attribution::new().unwrap();
        let other = [(SESSION, Arc::new(Job::new().unwrap()))];
        assert_eq!(
            attribution.attribute(peer, local, &other, far(), reflected_to(peer, local)),
            Err(Denial::NotInJob)
        );
        assert_eq!(
            attribution.attribute::<&str>(peer, local, &[], far(), reflected_to(peer, local)),
            Err(Denial::NotInJob)
        );
        client.process.kill().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_owner_outside_every_session_job_is_refused() {
        let listener = TcpListener::bind((host(), 0)).await.unwrap();
        let server = listener.local_addr().unwrap();
        let _stream = TcpStream::connect(server).await.unwrap();
        let (_accepted, client) = listener.accept().await.unwrap();
        let jobs = [(SESSION, Arc::new(Job::new().unwrap()))];
        let peer = SocketAddr::new(server.ip(), client.port());
        let local = SocketAddr::new(client.ip(), LISTENER_PORT);
        let found = Attribution::new().unwrap().attribute(
            peer,
            local,
            &jobs,
            far(),
            reflected_to(peer, local),
        );
        assert_eq!(found, Err(Denial::NotInJob));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_client_that_dialed_the_listener_itself_is_refused() {
        let job = Arc::new(Job::new().unwrap());
        let jobs = [(SESSION, job.clone())];
        let mut client = Client::start(&job, IPV4).await;
        let (peer, local) = client.reflected(client.server.port());
        assert_eq!(
            Attribution::new()
                .unwrap()
                .original(peer, local, &jobs, far()),
            Err(Denial::SelfTarget)
        );
        client.process.kill().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_process_outside_the_job_that_dials_the_listener_from_a_client_port_is_refused() {
        let job = Arc::new(Job::new().unwrap());
        let jobs = [(SESSION, job.clone())];
        let mut client = Client::start(&job, IPV4).await;
        let listener = reserve().unwrap().listen().unwrap();
        let target = SocketAddr::new(client.peer.ip(), listener.local_addr().unwrap().port());
        let dialer = TcpSocket::new_v4().unwrap();
        dialer.set_reuseaddr(true).unwrap();
        dialer.bind(client.peer).unwrap();
        let (dialed, accepted) = tokio::join!(dialer.connect(target), listener.accept());
        let _dialed = dialed.unwrap();
        let (accepted, peer) = accepted.unwrap();
        assert_eq!(peer, client.peer);
        let local = accepted.local_addr().unwrap();
        assert_eq!(
            Attribution::new()
                .unwrap()
                .original(peer, local, &jobs, far()),
            Err(Denial::SelfTarget)
        );
        client.process.kill().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_process_outside_the_job_that_dials_from_a_client_port_and_resets_is_not_found() {
        let job = Arc::new(Job::new().unwrap());
        let jobs = [(SESSION, job.clone())];
        let mut client = Client::start(&job, IPV4).await;
        let listener = reserve().unwrap().listen().unwrap();
        let target = SocketAddr::new(client.peer.ip(), listener.local_addr().unwrap().port());
        let dialer = TcpSocket::new_v4().unwrap();
        dialer.set_reuseaddr(true).unwrap();
        dialer.bind(client.peer).unwrap();
        let (dialed, accepted) = tokio::join!(dialer.connect(target), listener.accept());
        let (mut accepted, peer) = accepted.unwrap();
        let local = accepted.local_addr().unwrap();
        crate::proxy::reset(dialed.unwrap());
        let read = tokio::time::timeout(Duration::from_secs(10), accepted.read(&mut [0; 1]))
            .await
            .expect("the reset did not arrive");
        assert_eq!(
            read.map_err(|error| error.kind()),
            Err(io::ErrorKind::ConnectionReset)
        );
        assert_eq!(
            Attribution::new()
                .unwrap()
                .original(peer, local, &jobs, far()),
            Err(Denial::NotFound)
        );
        client.process.kill().await.unwrap();
    }

    #[test]
    fn table_states_map_to_the_states_the_matcher_tells_apart() {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            MIB_TCP_STATE_CLOSED, MIB_TCP_STATE_DELETE_TCB, MIB_TCP_STATE_FIN_WAIT2,
            MIB_TCP_STATE_LAST_ACK,
        };

        assert_eq!(
            tcp_state(MIB_TCP_STATE_ESTAB.cast_unsigned()),
            TcpState::Established
        );
        assert_eq!(
            tcp_state(MIB_TCP_STATE_CLOSE_WAIT.cast_unsigned()),
            TcpState::CloseWait
        );
        assert_eq!(
            tcp_state(MIB_TCP_STATE_TIME_WAIT.cast_unsigned()),
            TcpState::TimeWait
        );
        for other in [
            MIB_TCP_STATE_CLOSED,
            MIB_TCP_STATE_FIN_WAIT2,
            MIB_TCP_STATE_LAST_ACK,
            MIB_TCP_STATE_DELETE_TCB,
        ] {
            assert_eq!(tcp_state(other.cast_unsigned()), TcpState::Other, "{other}");
        }
        assert_eq!(tcp_state(u32::MAX), TcpState::Other);
    }

    #[test]
    fn a_connection_without_a_row_is_not_found_and_a_late_lookup_times_out() {
        let idle = std::net::TcpListener::bind((host(), 0)).unwrap();
        let peer = idle.local_addr().unwrap();
        let local = SocketAddr::new(peer.ip(), LISTENER_PORT);
        let jobs = [(SESSION, Arc::new(Job::new().unwrap()))];
        let attribution = Attribution::new().unwrap();
        assert_eq!(
            attribution.attribute(peer, local, &jobs, far(), reflected_to(peer, local)),
            Err(Denial::NotFound)
        );
        assert_eq!(
            attribution.original(peer, local, &jobs, Instant::now()),
            Err(Denial::TimedOut)
        );
    }

    async fn dual_stack(server: SocketAddr) -> TcpStream {
        let IpAddr::V4(ip) = server.ip() else {
            panic!("the server is not IPv4");
        };
        let socket = TcpSocket::new_v6().unwrap();
        let both: i32 = 0;
        // SAFETY: the socket is open and both is an i32 of the given length.
        let set = unsafe {
            setsockopt(
                socket.as_raw_socket() as usize,
                IPPROTO_IPV6,
                IPV6_V6ONLY,
                (&raw const both).cast(),
                size_of_val(&both) as i32,
            )
        };
        assert_eq!(set, 0, "{}", io::Error::last_os_error());
        socket
            .connect(SocketAddr::new(ip.to_ipv6_mapped().into(), server.port()))
            .await
            .unwrap()
    }

    #[ignore = "started inside a job by the attribution tests"]
    #[tokio::test(flavor = "current_thread")]
    async fn a_client_holds_its_connection_until_the_server_ends_it() {
        let args: Vec<String> = std::env::args().collect();
        let Some(server) = args.iter().find_map(|arg| arg.parse().ok()) else {
            return;
        };
        let mut stream = if args.iter().any(|arg| arg == DUAL_STACK) {
            dual_stack(server).await
        } else {
            TcpStream::connect(server).await.unwrap()
        };
        let mut rest = Vec::new();
        let _ = stream.read_to_end(&mut rest).await;
    }
}
