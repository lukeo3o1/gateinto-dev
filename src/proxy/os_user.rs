use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::job::Job;

#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Denial {
    NotFound,
    OtherUser,
    NotInJob,
    Lookup(String),
    TimedOut,
}

impl fmt::Display for Denial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("no process owns the connection"),
            Self::OtherUser => f.write_str("the connection comes from another OS user"),
            Self::NotInJob => {
                f.write_str("the connection comes from outside the session's browser")
            }
            Self::Lookup(error) => write!(f, "looking up the connection owner failed: {error}"),
            Self::TimedOut => {
                f.write_str("the owner lookup did not finish within the handshake timeout")
            }
        }
    }
}

pub(crate) trait Owners: Send + Sync {
    fn check(&self, peer: SocketAddr, local: SocketAddr) -> Result<(), Denial>;
}

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

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn owner(
    rows: impl IntoIterator<Item = Row>,
    peer: SocketAddr,
    local: SocketAddr,
) -> Option<u32> {
    let same = |a: SocketAddr, b: SocketAddr| {
        a.ip().to_canonical() == b.ip().to_canonical() && a.port() == b.port()
    };
    rows.into_iter()
        .find(|row| row.pid != 0 && same(row.local, peer) && same(row.remote, local))
        .map(|row| row.pid)
}

#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
    V4,
    V6,
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn lookup(
    peer: SocketAddr,
    local: SocketAddr,
    tables: impl Fn(Family) -> io::Result<Vec<Row>>,
) -> Result<Option<u32>, Denial> {
    let read = |family| tables(family).map_err(|error| Denial::Lookup(error.to_string()));
    if peer.ip().to_canonical().is_ipv4()
        && let Some(pid) = owner(read(Family::V4)?, peer, local)
    {
        return Ok(Some(pid));
    }
    Ok(owner(read(Family::V6)?, peer, local))
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

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub(crate) fn system(job: Option<Arc<Job>>) -> io::Result<Arc<dyn Owners>> {
    Ok(Arc::new(windows::System::new(job)?))
}

#[cfg(not(windows))]
pub(crate) fn system(_: Option<Arc<Job>>) -> io::Result<Arc<dyn Owners>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "os_user authentication is only available on Windows",
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
        fn check(&self, peer: SocketAddr, local: SocketAddr) -> Result<(), Denial> {
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

    #[test]
    fn denials_name_their_reason() {
        for (denial, reason) in [
            (Denial::NotFound, "no process owns"),
            (Denial::OtherUser, "another OS user"),
            (Denial::NotInJob, "outside the session's browser"),
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

    #[cfg(not(windows))]
    #[test]
    fn the_system_lookup_is_unavailable_outside_windows() {
        let error = system(None).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("only available on Windows"));
    }
}
