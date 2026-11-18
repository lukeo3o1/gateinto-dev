use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use crate::job::Job;

#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Denial {
    NotFound,
    OtherUser,
    NotInJob,
    Ambiguous,
    SelfTarget,
    Lookup(String),
    TimedOut,
}

impl fmt::Display for Denial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("no process owns the connection"),
            Self::OtherUser => f.write_str("the connection comes from another OS user"),
            Self::NotInJob => f.write_str("the connection comes from outside the session's job"),
            Self::Ambiguous => {
                f.write_str("the connection matches more than one process or session")
            }
            Self::SelfTarget => {
                f.write_str("the connection is addressed to the transparent listener itself")
            }
            Self::Lookup(error) => write!(f, "looking up the connection owner failed: {error}"),
            Self::TimedOut => {
                f.write_str("the owner lookup did not finish within the handshake timeout")
            }
        }
    }
}

pub(crate) trait Owners: Send + Sync {
    fn check(&self, peer: SocketAddr, local: SocketAddr, deadline: Instant) -> Result<(), Denial>;
}

const LOOKUP_ATTEMPTS: u32 = 5;
const LOOKUP_DELAY: std::time::Duration = std::time::Duration::from_millis(5);

#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Row {
    pub(crate) local: SocketAddr,
    pub(crate) remote: SocketAddr,
    pub(crate) pid: u32,
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn v4(addr: u32, port: u32) -> SocketAddr {
    SocketAddr::from((addr.to_ne_bytes(), port_of(port)))
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn v6(addr: [u8; 16], port: u32) -> SocketAddr {
    SocketAddr::from((addr, port_of(port)))
}

fn port_of(port: u32) -> u16 {
    let [high, low, ..] = port.to_ne_bytes();
    u16::from_be_bytes([high, low])
}

fn same(a: SocketAddr, b: SocketAddr) -> bool {
    a.ip().to_canonical() == b.ip().to_canonical() && a.port() == b.port()
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn owner(
    rows: impl IntoIterator<Item = Row>,
    peer: SocketAddr,
    local: SocketAddr,
) -> Option<u32> {
    rows.into_iter()
        .find(|row| row.pid != 0 && same(row.local, peer) && same(row.remote, local))
        .map(|row| row.pid)
}

#[cfg_attr(not(any(windows, target_os = "linux")), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
    V4,
    V6,
}

#[cfg_attr(not(any(windows, target_os = "linux")), allow(dead_code))]
fn families(peer: SocketAddr) -> &'static [Family] {
    if peer.ip().to_canonical().is_ipv4() {
        &[Family::V4, Family::V6]
    } else {
        &[Family::V6]
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn lookup(
    peer: SocketAddr,
    local: SocketAddr,
    tables: impl Fn(Family) -> io::Result<Vec<Row>>,
) -> Result<Option<u32>, Denial> {
    for &family in families(peer) {
        let rows = tables(family).map_err(|error| Denial::Lookup(error.to_string()))?;
        if let Some(pid) = owner(rows, peer, local) {
            return Ok(Some(pid));
        }
    }
    Ok(None)
}

#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Original<K> {
    pub(crate) pid: u32,
    pub(crate) session: K,
    pub(crate) destination: SocketAddr,
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn original<K>(
    rows: impl IntoIterator<Item = Row>,
    peer: SocketAddr,
    local: SocketAddr,
    mut admit: impl FnMut(u32) -> Result<K, Denial>,
) -> Result<Original<K>, Denial> {
    let rows: Vec<Row> = rows.into_iter().collect();
    let remote = peer.ip().to_canonical();
    if remote.is_loopback()
        || rows
            .iter()
            .any(|row| same(row.local, peer) && same(row.remote, local))
    {
        return Err(Denial::SelfTarget);
    }
    let client = SocketAddr::new(local.ip(), peer.port());
    let mut seen = Vec::new();
    let mut found = None;
    let mut refused = None;
    for row in rows {
        let candidate = (row.pid, row.remote.port());
        if row.pid == 0
            || row.remote.port() == 0
            || !same(row.local, client)
            || row.remote.ip().to_canonical() != remote
            || seen.contains(&candidate)
        {
            continue;
        }
        seen.push(candidate);
        match admit(row.pid) {
            Ok(_) if found.is_some() => return Err(Denial::Ambiguous),
            Ok(session) => {
                found = Some(Original {
                    pid: row.pid,
                    session,
                    destination: SocketAddr::new(remote, row.remote.port()),
                });
            }
            Err(denial @ (Denial::OtherUser | Denial::NotInJob)) => {
                refused.get_or_insert(denial);
            }
            Err(denial) => return Err(denial),
        }
    }
    found.ok_or_else(|| refused.unwrap_or(Denial::NotFound))
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn one_session<K: Clone, J>(
    jobs: &[(K, J)],
    mut inside: impl FnMut(&J) -> Result<bool, Denial>,
) -> Result<K, Denial> {
    let mut found = None;
    for (key, job) in jobs {
        if inside(job)? {
            if found.is_some() {
                return Err(Denial::Ambiguous);
            }
            found = Some(key);
        }
    }
    found.cloned().ok_or(Denial::NotInJob)
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn all_rows(
    peer: SocketAddr,
    tables: impl Fn(Family) -> io::Result<Vec<Row>>,
) -> Result<Vec<Row>, Denial> {
    let mut rows = Vec::new();
    for &family in families(peer) {
        rows.extend(tables(family).map_err(|error| Denial::Lookup(error.to_string()))?);
    }
    Ok(rows)
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn confirmed<K>(
    mut pass: impl FnMut() -> Result<Original<K>, Denial>,
) -> Result<Option<Original<K>>, Denial> {
    let mut read = || match pass() {
        Err(Denial::NotFound) => Ok(None),
        result => result.map(Some),
    };
    let Some(found) = read()? else {
        return Ok(None);
    };
    let Some(again) = read()? else {
        return Ok(None);
    };
    Ok((again.pid == found.pid && again.destination == found.destination).then_some(again))
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn retry<T>(
    deadline: Instant,
    mut attempt: impl FnMut() -> Result<Option<T>, Denial>,
) -> Result<T, Denial> {
    for tried in 1..=LOOKUP_ATTEMPTS {
        if Instant::now() >= deadline {
            return Err(Denial::TimedOut);
        }
        if let Some(found) = attempt()? {
            return Ok(found);
        }
        if tried < LOOKUP_ATTEMPTS {
            std::thread::sleep(
                LOOKUP_DELAY.min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }
    Err(Denial::NotFound)
}

/// # Safety
///
/// `R` must be valid for any bit pattern, and `buffer` must be empty or start with a `u32` row
/// count whose rows of type `R`, from byte `offset` on, lie in the buffer when the count fits it.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) unsafe fn entries<R>(buffer: &[u64], offset: usize) -> io::Result<&[R]> {
    if buffer.is_empty() {
        return Ok(&[]);
    }
    let count = buffer.as_ptr().cast::<u32>();
    // SAFETY: the buffer is not empty, so it holds at least the aligned u32 count.
    let count = unsafe { *count } as usize;
    let fits = count
        .checked_mul(size_of::<R>())
        .and_then(|rows| rows.checked_add(offset))
        .is_some_and(|end| end <= size_of_val(buffer));
    if !fits || !offset.is_multiple_of(align_of::<R>()) || align_of::<R>() > align_of::<u64>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the connection table is shorter than its row count",
        ));
    }
    // SAFETY: the rows lie in the buffer, are aligned, and R is valid for any bit pattern.
    Ok(unsafe {
        std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>().add(offset).cast::<R>(), count)
    })
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(crate) mod procfs;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
pub(crate) use linux::pidfd_probe;

#[cfg(windows)]
pub(crate) fn system(job: Option<Arc<Job>>) -> io::Result<Arc<dyn Owners>> {
    Ok(Arc::new(windows::System::new(job)?))
}

#[cfg(target_os = "linux")]
pub(crate) fn system(job: Option<Arc<Job>>) -> io::Result<Arc<dyn Owners>> {
    #[cfg(test)]
    if job.is_some() {
        return Ok(tests::fake(Err(Denial::NotInJob)));
    }
    if job.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "os_user authentication cannot check session membership on Linux",
        ));
    }
    Ok(Arc::new(linux::System::new()))
}

#[cfg(not(any(windows, target_os = "linux")))]
pub(crate) fn system(job: Option<Arc<Job>>) -> io::Result<Arc<dyn Owners>> {
    #[cfg(test)]
    if job.is_some() {
        return Ok(tests::fake(Err(Denial::NotInJob)));
    }
    let _ = job;
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "os_user authentication is only available on Windows and Linux",
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV6};
    use std::sync::Mutex;
    use std::time::Duration;

    use super::*;

    pub(crate) struct Fake {
        verdict: Result<(), Denial>,
        delay: Duration,
        pub(crate) seen: Mutex<Vec<(SocketAddr, SocketAddr)>>,
    }

    pub(crate) fn fake(verdict: Result<(), Denial>) -> Arc<Fake> {
        slow(verdict, Duration::ZERO)
    }

    pub(crate) fn slow(verdict: Result<(), Denial>, delay: Duration) -> Arc<Fake> {
        Arc::new(Fake {
            verdict,
            delay,
            seen: Mutex::new(Vec::new()),
        })
    }

    impl Owners for Fake {
        fn check(&self, peer: SocketAddr, local: SocketAddr, _: Instant) -> Result<(), Denial> {
            self.seen.lock().unwrap().push((peer, local));
            std::thread::sleep(self.delay);
            self.verdict.clone()
        }
    }

    fn port(port: u16) -> u32 {
        let [high, low] = port.to_be_bytes();
        u32::from_ne_bytes([high, low, 0xAB, 0xCD])
    }

    #[test]
    fn ipv4_rows_hold_the_address_and_the_port_in_network_byte_order() {
        let addr = u32::from_ne_bytes([127, 0, 0, 1]);
        assert_eq!(
            v4(addr, port(443)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 443))
        );
        assert_eq!(
            v4(addr, port(0xC001)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0xC001))
        );
    }

    #[test]
    fn ipv6_rows_hold_the_address_bytes_and_the_port_in_network_byte_order() {
        assert_eq!(
            v6(Ipv6Addr::LOCALHOST.octets(), port(50_000)),
            SocketAddr::from((Ipv6Addr::LOCALHOST, 50_000))
        );
    }

    fn row(local: &str, remote: &str, pid: u32) -> Row {
        Row {
            local: local.parse().unwrap(),
            remote: remote.parse().unwrap(),
            pid,
        }
    }

    #[test]
    fn the_owner_is_the_row_whose_local_end_is_the_peer_and_remote_end_is_the_listener() {
        let rows = [
            row("127.0.0.1:8080", "127.0.0.1:50000", 1),
            row("127.0.0.1:50000", "127.0.0.1:9090", 2),
            row("127.0.0.1:50000", "127.0.0.1:8080", 3),
        ];
        let peer = "127.0.0.1:50000".parse().unwrap();
        let local = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(owner(rows, peer, local), Some(3));
        assert_eq!(owner(rows, local, peer), Some(1));
        assert_eq!(owner(rows, peer, "127.0.0.2:8080".parse().unwrap()), None);
        assert_eq!(owner([], peer, local), None);
    }

    #[test]
    fn ipv6_owners_match_regardless_of_scope_and_mapped_ipv4_matches_ipv4() {
        let rows = [
            row("[::1]:50000", "[::1]:8080", 4),
            row("127.0.0.1:50001", "127.0.0.1:8080", 5),
        ];
        let peer = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 50000, 7, 3));
        assert_eq!(owner(rows, peer, "[::1]:8080".parse().unwrap()), Some(4));
        let mapped = "[::ffff:127.0.0.1]:50001".parse().unwrap();
        let listener = "[::ffff:127.0.0.1]:8080".parse().unwrap();
        assert_eq!(owner(rows, mapped, listener), Some(5));
        assert_eq!(owner(rows, "[::1]:50001".parse().unwrap(), listener), None);
    }

    #[test]
    fn rows_without_an_owning_process_lose_to_rows_with_one() {
        let peer = "127.0.0.1:50000".parse().unwrap();
        let local = "127.0.0.1:8080".parse().unwrap();
        let idle = row("127.0.0.1:50000", "127.0.0.1:8080", 0);
        let live = row("127.0.0.1:50000", "127.0.0.1:8080", 9);
        assert_eq!(owner([idle, live], peer, local), Some(9));
        assert_eq!(owner([live, idle], peer, local), Some(9));
        assert_eq!(owner([idle], peer, local), None);
    }

    #[test]
    fn an_ipv4_peer_is_also_looked_up_as_a_mapped_row_in_the_ipv6_table() {
        let peer: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let mapped = row("[::ffff:127.0.0.1]:50000", "[::ffff:127.0.0.1]:8080", 6);
        let asked = Mutex::new(Vec::new());
        let tables = |family: Family| {
            asked.lock().unwrap().push(family);
            Ok(match family {
                Family::V4 => vec![row("127.0.0.1:50001", "127.0.0.1:8080", 1)],
                Family::V6 => vec![mapped],
            })
        };
        assert_eq!(lookup(peer, local, tables).unwrap(), Some(6));
        assert_eq!(*asked.lock().unwrap(), [Family::V4, Family::V6]);
    }

    #[test]
    fn an_ipv4_match_does_not_read_the_ipv6_table_and_an_ipv6_peer_reads_only_it() {
        let asked = Mutex::new(Vec::new());
        let tables = |family: Family| {
            asked.lock().unwrap().push(family);
            Ok(vec![
                row("127.0.0.1:50000", "127.0.0.1:8080", 2),
                row("[::1]:50000", "[::1]:8080", 3),
            ])
        };
        let v4 = "127.0.0.1:50000".parse().unwrap();
        assert_eq!(
            lookup(v4, "127.0.0.1:8080".parse().unwrap(), tables).unwrap(),
            Some(2)
        );
        let v6 = "[::1]:50000".parse().unwrap();
        assert_eq!(
            lookup(v6, "[::1]:8080".parse().unwrap(), tables).unwrap(),
            Some(3)
        );
        assert_eq!(*asked.lock().unwrap(), [Family::V4, Family::V6]);
    }

    #[test]
    fn a_table_error_is_a_lookup_denial() {
        let peer = "127.0.0.1:50000".parse().unwrap();
        let local = "127.0.0.1:8080".parse().unwrap();
        let failing = |_| Err(io::Error::other("table unavailable"));
        assert_eq!(
            lookup(peer, local, failing),
            Err(Denial::Lookup("table unavailable".to_owned()))
        );
    }

    fn table(count: u32, rows: &[[u32; 2]]) -> Vec<u64> {
        let mut words = vec![u64::from(count)];
        words.extend(
            rows.iter()
                .map(|[a, b]| u64::from(*a) | (u64::from(*b) << 32)),
        );
        words
    }

    #[test]
    fn table_entries_are_read_after_the_offset() {
        let buffer = table(2, &[[1, 2], [3, 4]]);
        // SAFETY: [u32; 2] is valid for any bit pattern and the buffer holds the count and rows.
        let rows = unsafe { entries::<[u32; 2]>(&buffer, 8) }.unwrap();
        assert_eq!(rows, [[1, 2], [3, 4]]);
        // SAFETY: as above.
        assert!(unsafe { entries::<[u32; 2]>(&[], 8) }.unwrap().is_empty());
    }

    #[test]
    fn a_row_count_beyond_the_buffer_is_a_lookup_error() {
        for (buffer, offset) in [
            (table(3, &[[1, 2], [3, 4]]), 8),
            (table(2, &[[1, 2], [3, 4]]), 16),
            (table(u32::MAX, &[]), 8),
            (vec![0], 16),
        ] {
            // SAFETY: [u32; 2] is valid for any bit pattern; the count is checked against the buffer.
            let error = unsafe { entries::<[u32; 2]>(&buffer, offset) }.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{buffer:?}");
        }
    }

    const CLIENT: &str = "192.168.1.10:50000";
    const PEER: &str = "203.0.113.7:50000";
    const LISTENER: &str = "192.168.1.10:50123";
    const DESTINATION: &str = "203.0.113.7:443";

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    struct Verdicts {
        verdicts: Vec<(u32, Result<&'static str, Denial>)>,
        asked: Vec<u32>,
    }

    impl Verdicts {
        fn admit(&mut self, pid: u32) -> Result<&'static str, Denial> {
            self.asked.push(pid);
            self.verdicts
                .iter()
                .find(|(owner, _)| *owner == pid)
                .map_or(Err(Denial::NotInJob), |(_, verdict)| verdict.clone())
        }
    }

    fn admitting(verdicts: &[(u32, Result<&'static str, Denial>)]) -> Verdicts {
        Verdicts {
            verdicts: verdicts.to_vec(),
            asked: Vec::new(),
        }
    }

    fn found(pid: u32, session: &'static str, destination: &str) -> Original<&'static str> {
        Original {
            pid,
            session,
            destination: addr(destination),
        }
    }

    #[test]
    fn the_original_destination_is_the_remote_port_of_the_one_admitted_client_row() {
        let rows = [
            row(LISTENER, PEER, 1),
            row("192.168.1.10:50001", DESTINATION, 2),
            row(CLIENT, DESTINATION, 7),
            row("192.168.1.10:443", PEER, 3),
        ];
        let mut owners = admitting(&[(7, Ok("session"))]);
        assert_eq!(
            original(rows, addr(PEER), addr(LISTENER), |pid| owners.admit(pid)),
            Ok(found(7, "session", DESTINATION))
        );
        assert_eq!(owners.asked, [7]);
    }

    #[test]
    fn without_a_client_row_the_connection_is_not_found() {
        let mut owners = admitting(&[]);
        assert_eq!(
            original([], addr(PEER), addr(LISTENER), |pid| owners.admit(pid)),
            Err(Denial::NotFound)
        );
        let mut owners = admitting(&[]);
        let rows = [
            row(LISTENER, PEER, 1),
            row("192.168.1.10:50001", DESTINATION, 2),
        ];
        assert_eq!(
            original(rows, addr(PEER), addr(LISTENER), |pid| owners.admit(pid)),
            Err(Denial::NotFound)
        );
        assert!(owners.asked.is_empty());
    }

    #[test]
    fn two_admitted_client_rows_are_ambiguous() {
        let rows = [
            row(CLIENT, DESTINATION, 7),
            row(CLIENT, "203.0.113.7:80", 8),
        ];
        let mut owners = admitting(&[(7, Ok("a")), (8, Ok("b"))]);
        assert_eq!(
            original(rows, addr(PEER), addr(LISTENER), |pid| owners.admit(pid)),
            Err(Denial::Ambiguous)
        );
        let rows = [
            row(CLIENT, DESTINATION, 7),
            row(CLIENT, "203.0.113.7:80", 7),
        ];
        let mut owners = admitting(&[(7, Ok("a"))]);
        assert_eq!(
            original(rows, addr(PEER), addr(LISTENER), |pid| owners.admit(pid)),
            Err(Denial::Ambiguous)
        );
    }

    #[test]
    fn rows_without_an_owning_process_are_never_candidates() {
        let idle = row(CLIENT, "203.0.113.7:80", 0);
        let mut owners = admitting(&[(0, Ok("idle")), (7, Ok("session"))]);
        assert_eq!(
            original([idle], addr(PEER), addr(LISTENER), |pid| owners.admit(pid)),
            Err(Denial::NotFound)
        );
        assert!(owners.asked.is_empty());
        let mut owners = admitting(&[(0, Ok("idle")), (7, Ok("session"))]);
        let rows = [idle, row(CLIENT, DESTINATION, 7)];
        assert_eq!(
            original(rows, addr(PEER), addr(LISTENER), |pid| owners.admit(pid)),
            Ok(found(7, "session", DESTINATION))
        );
    }

    #[test]
    fn a_left_over_row_of_another_owner_does_not_make_two() {
        for refusal in [Denial::NotInJob, Denial::OtherUser] {
            let stale = row(CLIENT, "203.0.113.7:8443", 9);
            for rows in [
                [stale, row(CLIENT, DESTINATION, 7)],
                [row(CLIENT, DESTINATION, 7), stale],
            ] {
                let mut owners = admitting(&[(7, Ok("session")), (9, Err(refusal.clone()))]);
                assert_eq!(
                    original(rows, addr(PEER), addr(LISTENER), |pid| owners.admit(pid)),
                    Ok(found(7, "session", DESTINATION)),
                    "{refusal}"
                );
                assert_eq!(owners.asked.len(), 2);
            }
        }
    }

    #[test]
    fn an_owner_that_could_not_be_attributed_ends_the_lookup_next_to_an_admitted_row() {
        for failure in [
            Denial::Lookup("access denied".to_owned()),
            Denial::TimedOut,
            Denial::Ambiguous,
        ] {
            let unknown = row(CLIENT, "203.0.113.7:8443", 9);
            for rows in [
                [unknown, row(CLIENT, DESTINATION, 7)],
                [row(CLIENT, DESTINATION, 7), unknown],
            ] {
                let mut owners = admitting(&[(7, Ok("session")), (9, Err(failure.clone()))]);
                assert_eq!(
                    original(rows, addr(PEER), addr(LISTENER), |pid| owners.admit(pid)),
                    Err(failure.clone()),
                    "{rows:?}"
                );
            }
        }
    }

    #[test]
    fn when_no_owner_is_admitted_the_first_refusal_is_the_denial() {
        for refusal in [Denial::NotInJob, Denial::OtherUser] {
            let mut owners = admitting(&[(7, Err(refusal.clone()))]);
            assert_eq!(
                original(
                    [row(CLIENT, DESTINATION, 7)],
                    addr(PEER),
                    addr(LISTENER),
                    |pid| owners.admit(pid)
                ),
                Err(refusal)
            );
        }
        let rows = [
            row(CLIENT, DESTINATION, 7),
            row(CLIENT, "203.0.113.7:80", 8),
        ];
        let mut owners = admitting(&[(7, Err(Denial::OtherUser)), (8, Err(Denial::NotInJob))]);
        assert_eq!(
            original(rows, addr(PEER), addr(LISTENER), |pid| owners.admit(pid)),
            Err(Denial::OtherUser)
        );
    }

    #[test]
    fn the_client_row_must_have_the_accepted_local_address_and_the_peer_address() {
        let mut owners = admitting(&[(7, Ok("session"))]);
        let rows = [row(CLIENT, DESTINATION, 7)];
        let elsewhere = addr("192.168.1.11:50123");
        assert_eq!(
            original(rows, addr(PEER), elsewhere, |pid| owners.admit(pid)),
            Err(Denial::NotFound)
        );
        for rows in [
            [row("192.168.1.11:50000", DESTINATION, 7)],
            [row("192.168.1.10:50001", DESTINATION, 7)],
            [row(CLIENT, "203.0.113.8:443", 7)],
        ] {
            let mut owners = admitting(&[(7, Ok("session"))]);
            assert_eq!(
                original(rows, addr(PEER), addr(LISTENER), |pid| owners.admit(pid)),
                Err(Denial::NotFound),
                "{rows:?}"
            );
        }
    }

    #[test]
    fn mapped_rows_of_a_dual_stack_client_give_an_ipv4_destination() {
        let mapped = row("[::ffff:192.168.1.10]:50000", "[::ffff:203.0.113.7]:443", 7);
        for (peer, local) in [
            (PEER, LISTENER),
            ("[::ffff:203.0.113.7]:50000", "[::ffff:192.168.1.10]:50123"),
        ] {
            let mut owners = admitting(&[(7, Ok("session"))]);
            let matched =
                original([mapped], addr(peer), addr(local), |pid| owners.admit(pid)).unwrap();
            assert_eq!(matched.destination, addr(DESTINATION));
            assert!(matched.destination.is_ipv4());
        }
    }

    #[test]
    fn a_client_that_dialed_the_listener_itself_is_refused() {
        for (client, remote, peer, listener) in [
            (CLIENT, LISTENER, "192.168.1.10:50000", LISTENER),
            (
                "127.0.0.1:50000",
                "127.0.0.1:50123",
                "127.0.0.1:50000",
                "127.0.0.1:50123",
            ),
            (
                "[::ffff:192.168.1.10]:50000",
                "[::ffff:192.168.1.10]:50123",
                "192.168.1.10:50000",
                LISTENER,
            ),
        ] {
            let mut owners = admitting(&[(7, Ok("session"))]);
            assert_eq!(
                original(
                    [row(client, remote, 7)],
                    addr(peer),
                    addr(listener),
                    |pid| owners.admit(pid)
                ),
                Err(Denial::SelfTarget),
                "{client}"
            );
        }
        let mut owners = admitting(&[(7, Ok("session"))]);
        let rows = [row(CLIENT, "203.0.113.7:50123", 7)];
        assert_eq!(
            original(rows, addr(PEER), addr(LISTENER), |pid| owners.admit(pid)),
            Ok(found(7, "session", "203.0.113.7:50123"))
        );
    }

    #[test]
    fn a_socket_that_dialed_the_listener_refuses_the_connection_whatever_else_matches() {
        let in_job = row(CLIENT, "192.168.1.11:61000", 7);
        for (peer, rows) in [
            (
                CLIENT,
                [
                    row(CLIENT, LISTENER, 9),
                    row(CLIENT, "192.168.1.10:61000", 7),
                ],
            ),
            (
                "192.168.1.11:50000",
                [in_job, row("192.168.1.11:50000", LISTENER, 9)],
            ),
            (
                "192.168.1.11:50000",
                [in_job, row("192.168.1.11:50000", LISTENER, 0)],
            ),
            (
                "192.168.1.11:50000",
                [
                    in_job,
                    row(
                        "[::ffff:192.168.1.11]:50000",
                        "[::ffff:192.168.1.10]:50123",
                        9,
                    ),
                ],
            ),
        ] {
            let mut owners = admitting(&[(7, Ok("session"))]);
            assert_eq!(
                original(rows, addr(peer), addr(LISTENER), |pid| owners.admit(pid)),
                Err(Denial::SelfTarget),
                "{rows:?}"
            );
            assert!(owners.asked.is_empty());
        }
    }

    #[test]
    fn a_loopback_peer_is_refused_before_any_row_is_considered() {
        let shared = [
            row("127.0.0.1:50000", "127.0.0.1:50123", 9),
            row("127.0.0.1:50000", "127.0.0.1:61000", 7),
        ];
        let mut owners = admitting(&[(7, Ok("session"))]);
        let (peer, listener) = (addr("127.0.0.1:50000"), addr("127.0.0.1:50123"));
        assert_eq!(
            original(shared, peer, listener, |pid| owners.admit(pid)),
            Err(Denial::SelfTarget)
        );
        assert!(owners.asked.is_empty());
        for (peer, remote) in [
            ("127.45.6.7:50000", "127.45.6.7:443"),
            ("[::1]:50000", "[::1]:443"),
            ("[::ffff:127.0.0.1]:50000", "127.0.0.1:443"),
        ] {
            let mut owners = admitting(&[(7, Ok("session"))]);
            let rows = [row(CLIENT, remote, 7)];
            assert_eq!(
                original(rows, addr(peer), addr(LISTENER), |pid| owners.admit(pid)),
                Err(Denial::SelfTarget),
                "{peer}"
            );
            assert!(owners.asked.is_empty());
        }
    }

    #[test]
    fn the_same_socket_listed_in_both_tables_is_one_candidate() {
        let rows = [
            row(CLIENT, DESTINATION, 7),
            row("[::ffff:192.168.1.10]:50000", "[::ffff:203.0.113.7]:443", 7),
        ];
        let mut owners = admitting(&[(7, Ok("session"))]);
        assert_eq!(
            original(rows, addr(PEER), addr(LISTENER), |pid| owners.admit(pid)),
            Ok(found(7, "session", DESTINATION))
        );
        assert_eq!(owners.asked, [7]);
    }

    #[test]
    fn ports_match_exactly_up_to_the_boundaries() {
        let rows = [
            row("192.168.1.10:0", "203.0.113.7:1", 5),
            row("192.168.1.10:65535", "203.0.113.7:65535", 7),
        ];
        let mut owners = admitting(&[(5, Ok("zero")), (7, Ok("session"))]);
        let highest = addr("203.0.113.7:65535");
        assert_eq!(
            original(rows, highest, addr(LISTENER), |pid| owners.admit(pid)),
            Ok(found(7, "session", "203.0.113.7:65535"))
        );
        assert_eq!(owners.asked, [7]);
        let lowest = addr("203.0.113.7:1");
        let mut owners = admitting(&[(7, Ok("session"))]);
        let rows = [row("192.168.1.10:1", "203.0.113.7:1", 7)];
        assert_eq!(
            original(rows, lowest, addr(LISTENER), |pid| owners.admit(pid)),
            Ok(found(7, "session", "203.0.113.7:1"))
        );
        let mut owners = admitting(&[(7, Ok("session"))]);
        let rows = [row("192.168.1.10:1", "203.0.113.7:0", 7)];
        assert_eq!(
            original(rows, lowest, addr(LISTENER), |pid| owners.admit(pid)),
            Err(Denial::NotFound)
        );
        assert!(owners.asked.is_empty());
    }

    #[test]
    fn an_owner_belongs_to_the_one_session_whose_job_holds_it() {
        let jobs = [(1, "a"), (2, "b"), (3, "c")];
        assert_eq!(one_session(&jobs, |job| Ok(*job == "b")), Ok(2));
        assert_eq!(one_session(&jobs, |_| Ok(false)), Err(Denial::NotInJob));
        assert_eq!(
            one_session::<u8, &str>(&[], |_| Ok(true)),
            Err(Denial::NotInJob)
        );
        assert_eq!(
            one_session(&jobs, |job| Ok(*job != "b")),
            Err(Denial::Ambiguous)
        );
        let failing = |job: &&str| {
            if *job == "c" {
                Err(Denial::Lookup("access denied".to_owned()))
            } else {
                Ok(*job == "a")
            }
        };
        assert_eq!(
            one_session(&jobs, failing),
            Err(Denial::Lookup("access denied".to_owned()))
        );
    }

    #[test]
    fn an_ipv4_peer_reads_both_tables_and_an_ipv6_peer_only_the_ipv6_one() {
        let asked = Mutex::new(Vec::new());
        let tables = |family: Family| {
            asked.lock().unwrap().push(family);
            Ok(match family {
                Family::V4 => vec![row("192.168.1.10:50001", DESTINATION, 2)],
                Family::V6 => vec![row(
                    "[::ffff:192.168.1.10]:50000",
                    "[::ffff:203.0.113.7]:443",
                    7,
                )],
            })
        };
        let rows = all_rows(addr(PEER), tables).unwrap();
        assert_eq!(
            rows,
            [
                row("192.168.1.10:50001", DESTINATION, 2),
                row("[::ffff:192.168.1.10]:50000", "[::ffff:203.0.113.7]:443", 7),
            ]
        );
        let mut owners = admitting(&[(7, Ok("session"))]);
        assert_eq!(
            original(rows, addr(PEER), addr(LISTENER), |pid| owners.admit(pid)),
            Ok(found(7, "session", DESTINATION))
        );
        assert_eq!(*asked.lock().unwrap(), [Family::V4, Family::V6]);
        asked.lock().unwrap().clear();
        all_rows(addr("[2001:db8::7]:50000"), tables).unwrap();
        assert_eq!(*asked.lock().unwrap(), [Family::V6]);
        let failing = |family| match family {
            Family::V4 => Ok(Vec::new()),
            Family::V6 => Err(io::Error::other("table unavailable")),
        };
        assert_eq!(
            all_rows(addr(PEER), failing),
            Err(Denial::Lookup("table unavailable".to_owned()))
        );
    }

    fn passes(
        results: Vec<Result<Original<&'static str>, Denial>>,
    ) -> (Result<Option<Original<&'static str>>, Denial>, usize) {
        let mut results = results.into_iter();
        let mut count = 0;
        let confirmed = confirmed(|| {
            count += 1;
            results.next().unwrap()
        });
        (confirmed, count)
    }

    #[test]
    fn a_match_counts_only_when_a_second_reading_agrees_on_the_owner_and_destination() {
        let first = found(7, "session", DESTINATION);
        assert_eq!(
            passes(vec![
                Ok(first.clone()),
                Ok(found(7, "session", DESTINATION))
            ]),
            (Ok(Some(first.clone())), 2)
        );
        for again in [
            Ok(found(8, "session", DESTINATION)),
            Ok(found(7, "session", "203.0.113.7:80")),
            Err(Denial::NotFound),
        ] {
            assert_eq!(passes(vec![Ok(first.clone()), again]), (Ok(None), 2));
        }
        assert_eq!(passes(vec![Err(Denial::NotFound)]), (Ok(None), 1));
        assert_eq!(
            passes(vec![Err(Denial::OtherUser)]),
            (Err(Denial::OtherUser), 1)
        );
        assert_eq!(
            passes(vec![Ok(first), Err(Denial::Ambiguous)]),
            (Err(Denial::Ambiguous), 2)
        );
    }

    #[test]
    fn retries_end_with_the_first_match_or_not_found_after_the_last_attempt() {
        let far = Instant::now() + Duration::from_secs(10);
        let mut tried = 0;
        let third = retry(far, || {
            tried += 1;
            Ok((tried == 3).then_some(tried))
        });
        assert_eq!((third, tried), (Ok(3), 3));
        let mut tried = 0;
        let never = retry::<()>(far, || {
            tried += 1;
            Ok(None)
        });
        assert_eq!((never, tried), (Err(Denial::NotFound), LOOKUP_ATTEMPTS));
        let mut tried = 0;
        let refused = retry::<()>(far, || {
            tried += 1;
            Err(Denial::OtherUser)
        });
        assert_eq!((refused, tried), (Err(Denial::OtherUser), 1));
    }

    #[test]
    fn retries_stop_at_the_deadline() {
        let mut tried = 0;
        let late = retry::<()>(Instant::now(), || {
            tried += 1;
            Ok(None)
        });
        assert_eq!((late, tried), (Err(Denial::TimedOut), 0));
        let mut tried = 0;
        let soon = Instant::now() + LOOKUP_DELAY + LOOKUP_DELAY / 2;
        let timed_out = retry::<()>(soon, || {
            tried += 1;
            Ok(None)
        });
        assert_eq!(timed_out, Err(Denial::TimedOut));
        assert!(tried < LOOKUP_ATTEMPTS, "{tried}");
        assert!(Instant::now() >= soon);
    }

    #[test]
    fn denials_name_their_reason() {
        for (denial, reason) in [
            (Denial::NotFound, "no process owns"),
            (Denial::OtherUser, "another OS user"),
            (Denial::NotInJob, "outside the session's job"),
            (Denial::Ambiguous, "more than one"),
            (Denial::SelfTarget, "the transparent listener itself"),
            (
                Denial::Lookup("access denied".to_owned()),
                "failed: access denied",
            ),
            (
                Denial::TimedOut,
                "did not finish within the handshake timeout",
            ),
        ] {
            assert!(denial.to_string().contains(reason), "{denial}");
        }
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    #[test]
    fn the_system_lookup_is_unavailable_outside_windows_and_linux() {
        let error = system(None).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(
            error
                .to_string()
                .contains("only available on Windows and Linux")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_system_lookup_loads_on_linux() {
        assert!(system(None).is_ok());
    }

    #[cfg(not(windows))]
    #[test]
    fn a_test_job_stands_in_for_the_system_lookup_and_admits_nobody() {
        let owners = system(Some(Arc::new(Job::fake()))).unwrap();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 1));
        let checked = owners.check(addr, addr, Instant::now());
        assert!(matches!(checked, Err(Denial::NotInJob)));
    }
}
