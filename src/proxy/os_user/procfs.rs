use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

use super::{Family, same};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct LinuxRow {
    pub(super) local: SocketAddr,
    pub(super) remote: SocketAddr,
    pub(super) uid: u32,
    pub(super) inode: u64,
}

pub(super) fn table(family: Family, text: &str) -> io::Result<Vec<LinuxRow>> {
    let mut lines = text.lines();
    if lines
        .next()
        .and_then(|header| header.split_ascii_whitespace().next())
        != Some("sl")
    {
        return Err(invalid("the connection table has no header"));
    }
    lines
        .map(|line| row(family, line).ok_or_else(|| invalid("malformed connection table row")))
        .collect()
}

pub(super) fn connection(
    rows: impl IntoIterator<Item = LinuxRow>,
    peer: SocketAddr,
    local: SocketAddr,
) -> Option<LinuxRow> {
    rows.into_iter()
        .find(|row| row.inode != 0 && same(row.local, peer) && same(row.remote, local))
}

pub(super) fn uids(status: &str) -> io::Result<[u32; 4]> {
    let mut lines = status.lines().filter_map(|line| line.strip_prefix("Uid:"));
    let (Some(fields), None) = (lines.next(), lines.next()) else {
        return Err(invalid("the process status has no single Uid line"));
    };
    fields
        .strip_prefix('\t')
        .and_then(|fields| fields.split('\t').map(decimal).collect::<Option<Vec<_>>>())
        .and_then(|uids| uids.try_into().ok())
        .ok_or_else(|| invalid("malformed Uid line in the process status"))
}

pub(super) fn cgroup(text: &str) -> io::Result<&str> {
    let mut unified = None;
    for line in text.lines() {
        let mut parts = line.splitn(3, ':');
        let (Some(id), Some(controllers), Some(path)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(invalid("malformed process cgroup line"));
        };
        let id = decimal::<u32>(id).ok_or_else(|| invalid("malformed process cgroup id"))?;
        if !path.starts_with('/') {
            return Err(invalid("malformed process cgroup path"));
        }
        if id == 0 && (!controllers.is_empty() || unified.replace(path).is_some()) {
            return Err(invalid("the process has no single cgroup v2 line"));
        }
    }
    unified.ok_or_else(|| invalid("the process has no cgroup v2 line"))
}

fn row(family: Family, line: &str) -> Option<LinuxRow> {
    let fields: Vec<&str> = line.split_ascii_whitespace().collect();
    let [slot, local, remote, _, _, _, _, uid, _, inode, _, _, ..] = fields[..] else {
        return None;
    };
    decimal::<u32>(slot.strip_suffix(':')?)?;
    Some(LinuxRow {
        local: endpoint(family, local)?,
        remote: endpoint(family, remote)?,
        uid: decimal(uid)?,
        inode: decimal(inode)?,
    })
}

fn endpoint(family: Family, text: &str) -> Option<SocketAddr> {
    let (addr, port) = text.split_once(':')?;
    let port = u16::from_str_radix(hex(port, 4)?, 16).ok()?;
    let ip = match family {
        Family::V4 => IpAddr::from(Ipv4Addr::from(word(addr)?)),
        Family::V6 => {
            let addr = hex(addr, 32)?;
            let mut octets = [0; 16];
            for (index, octet) in octets.as_chunks_mut::<4>().0.iter_mut().enumerate() {
                *octet = word(addr.get(index * 8..index * 8 + 8)?)?;
            }
            IpAddr::from(octets)
        }
    };
    Some(SocketAddr::new(ip, port))
}

// The kernel prints each network-order 32-bit word of an address as a host-order integer.
fn word(text: &str) -> Option<[u8; 4]> {
    Some(u32::from_str_radix(hex(text, 8)?, 16).ok()?.to_ne_bytes())
}

fn hex(text: &str, len: usize) -> Option<&str> {
    (text.len() == len && text.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(text)
}

fn decimal<T: FromStr>(text: &str) -> Option<T> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:ACBF 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3128 1 00000000af2085bd 100 0 0 10 0
   1: 0100007F:C350 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 48213 1 00000000c3e1a7f2 20 4 30 10 -1
   2: 0100007F:C351 0100007F:1F90 06 00000000:00000000 03:00001770 00000000     0        0 0 3 0000000000000000
   3: 0A00020F:9C40 B80D0120:01BB 01 00000000:00000000 02:000005DC 00000000  1001        0 48977 2 000000005b1d8e40 20 4 1 10 -1
";

    const TCP6: &str = "\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:C350 00000000000000000000000001000000:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 51234 1 00000000d1c2b3a4 20 4 30 10 -1
   1: 0000000000000000FFFF00000100007F:C352 0000000000000000FFFF00000100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 51301 1 00000000e5f6a7b8 20 4 30 10 -1
   2: B80D0120000000000000000001000000:01BB B80D0120000000000000000002000000:D431 01 00000000:00000000 00:00000000 00000000  1002        0 51388 1 00000000f9e8d7c6 20 4 30 10 -1
";

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn row(local: &str, remote: &str, uid: u32, inode: u64) -> LinuxRow {
        LinuxRow {
            local: addr(local),
            remote: addr(remote),
            uid,
            inode,
        }
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn ipv4_rows_hold_host_order_addresses_and_plain_ports() {
        let padded = TCP.replace('\n', "                      \n");
        assert_eq!(
            table(Family::V4, &padded).unwrap(),
            table(Family::V4, TCP).unwrap()
        );
        assert_eq!(
            table(Family::V4, TCP).unwrap(),
            [
                row("127.0.0.1:44223", "0.0.0.0:0", 0, 3128),
                row("127.0.0.1:50000", "127.0.0.1:8080", 1000, 48213),
                row("127.0.0.1:50001", "127.0.0.1:8080", 0, 0),
                row("15.2.0.10:40000", "32.1.13.184:443", 1001, 48977),
            ]
        );
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn ipv6_rows_hold_each_word_in_host_order_and_keep_mapped_addresses() {
        assert_eq!(
            table(Family::V6, TCP6).unwrap(),
            [
                row("[::1]:50000", "[::1]:8080", 1000, 51234),
                row(
                    "[::ffff:127.0.0.1]:50002",
                    "[::ffff:127.0.0.1]:8080",
                    1000,
                    51301
                ),
                row("[2001:db8::1]:443", "[2001:db8::2]:54321", 1002, 51388),
            ]
        );
    }

    #[test]
    fn a_table_with_only_its_header_has_no_rows() {
        for text in [TCP, TCP6] {
            let header = text.lines().next().unwrap();
            assert!(table(Family::V4, header).unwrap().is_empty());
            assert!(
                table(Family::V6, &format!("{header}\n"))
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn a_malformed_table_is_an_error() {
        let header = TCP.lines().next().unwrap();
        let line = TCP.lines().nth(2).unwrap();
        let mut cases = vec![String::new(), line.to_owned(), format!("garbage\n{line}")];
        let twelfth = line.split_whitespace().nth(11).unwrap();
        let end = twelfth.as_ptr() as usize - line.as_ptr() as usize;
        for index in 1..=end {
            cases.push(format!("{header}\n{}", &line[..index]));
        }
        for (from, to) in [
            ("   1:", "   1;"),
            ("   1:", "    :"),
            ("0100007F:C350", "0100007F:C35"),
            ("0100007F:C350", "100007F:C350"),
            ("0100007F:C350", "+100007F:C350"),
            ("0100007F:C350", "0100007G:C350"),
            ("0100007F:C350", "0100007F:+350"),
            ("0100007F:C350", "0100007F:C3500"),
            ("0100007F:C350", "0100007FC350"),
            ("0100007F:C350", "0100007F:C350:0"),
            ("0100007F:C350", "0000000000000000FFFF00000100007F:C350"),
            ("  1000  ", "  -1000  "),
            ("  1000  ", "  +1000  "),
            ("  1000  ", "  4294967296  "),
            ("  1000  ", "  10a0  "),
            (" 48213 ", " 48213x "),
            (" 48213 ", " -1 "),
            (" 48213 ", " 18446744073709551616 "),
        ] {
            let broken = line.replacen(from, to, 1);
            assert_ne!(broken, line, "{from} -> {to}");
            cases.push(format!("{header}\n{broken}"));
        }
        cases.push(format!("{header}\n{line}\n\n{line}"));
        for case in cases {
            assert_eq!(
                table(Family::V4, &case).unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{case:?}"
            );
        }
        for case in [
            TCP.to_owned(),
            TCP6.replacen("0000000000000000FFFF00000100007F", "FFFF00000100007F", 1),
            TCP6.replacen(":C350", ":C35", 1),
        ] {
            assert_eq!(
                table(Family::V6, &case).unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{case:?}"
            );
        }
    }

    #[test]
    fn the_parsers_are_total_on_garbled_input() {
        let line = TCP.lines().nth(2).unwrap().as_bytes();
        for seed in 0u32..2000 {
            let mut bytes = line.to_vec();
            let mut state = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
            for _ in 0..1 + seed % 4 {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                let at = state as usize % bytes.len();
                bytes[at] = (state >> 8) as u8;
            }
            let text = format!(
                "{}\n{}",
                TCP.lines().next().unwrap(),
                String::from_utf8_lossy(&bytes)
            );
            let _ = table(Family::V4, &text);
            let _ = table(Family::V6, &text);
            let _ = uids(&text);
            let _ = cgroup(&text);
        }
    }

    #[test]
    fn the_connection_is_the_row_from_the_peer_to_the_listener_with_an_inode() {
        let rows = [
            row("127.0.0.1:8080", "127.0.0.1:50000", 1000, 1),
            row("127.0.0.1:50000", "127.0.0.1:9090", 1000, 2),
            row("127.0.0.1:50000", "127.0.0.1:8080", 0, 0),
            row("127.0.0.1:50000", "127.0.0.1:8080", 1000, 3),
        ];
        let peer = addr("127.0.0.1:50000");
        let local = addr("127.0.0.1:8080");
        assert_eq!(connection(rows, peer, local), Some(rows[3]));
        assert_eq!(connection(rows, local, peer), Some(rows[0]));
        assert_eq!(connection(rows, peer, addr("127.0.0.2:8080")), None);
        assert_eq!(connection(rows[..3].iter().copied(), peer, local), None);
        assert_eq!(connection([], peer, local), None);
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn mapped_rows_match_ipv4_peers_and_ipv6_rows_match_ipv6_peers() {
        let rows = table(Family::V6, TCP6).unwrap();
        let mapped = connection(
            rows.iter().copied(),
            addr("127.0.0.1:50002"),
            addr("127.0.0.1:8080"),
        );
        assert_eq!(mapped.map(|row| row.inode), Some(51301));
        let v6 = connection(
            rows.iter().copied(),
            addr("[::1]:50000"),
            addr("[::1]:8080"),
        );
        assert_eq!(v6.map(|row| row.inode), Some(51234));
        let none = connection(rows, addr("127.0.0.1:50000"), addr("127.0.0.1:8080"));
        assert_eq!(none, None);
    }

    const STATUS: &str = "\
Name:\tbash
Umask:\t0022
State:\tS (sleeping)
Tgid:\t4242
Ngid:\t0
Pid:\t4242
PPid:\t4200
TracerPid:\t0
Uid:\t1000\t1001\t1002\t1003
Gid:\t1000\t1000\t1000\t1000
FDSize:\t256
Groups:\t4 24 27 1000
";

    #[test]
    fn status_holds_the_real_effective_saved_and_filesystem_uids() {
        assert_eq!(uids(STATUS).unwrap(), [1000, 1001, 1002, 1003]);
        assert_eq!(
            uids("Uid:\t4294967295\t0\t0\t0").unwrap(),
            [u32::MAX, 0, 0, 0]
        );
    }

    #[test]
    fn a_status_without_exactly_one_well_formed_uid_line_is_an_error() {
        let line = "Uid:\t1000\t1001\t1002\t1003";
        let mut cases = vec![
            String::new(),
            STATUS.replace(line, ""),
            STATUS.replace("Name:\tbash", &format!("Name:\tx\n{line}")),
            format!("{STATUS}{line}\n"),
        ];
        for broken in [
            "Uid:\t1000\t1001\t1002",
            "Uid:\t1000\t1001\t1002\t1003\t1004",
            "Uid:",
            "Uid:\t1000\t1001\t1002\t-1",
            "Uid:\t1000\t1001\t1002\t+1",
            "Uid:\t1000\t1001\t1002\t4294967296",
            "Uid:\t1000\t1001\t1002\t10a3",
            "Uid:\t1000 x\t1001\t1002\t1003",
        ] {
            cases.push(STATUS.replace(line, broken));
        }
        for index in 1..=line.rfind('\t').unwrap() + 1 {
            cases.push(STATUS.replace(line, &line[..index]));
        }
        for case in cases {
            assert_eq!(
                uids(&case).unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{case:?}"
            );
        }
    }

    #[test]
    fn the_cgroup_is_the_v2_path_also_on_hybrid_hierarchies() {
        let path =
            "/user.slice/user-1000.slice/user@1000.service/app.slice/gateinto-terminal-1-2-3.scope";
        assert_eq!(cgroup(&format!("0::{path}\n")).unwrap(), path);
        let hybrid = format!("12:cpuset:/\n4:memory:/user.slice\n1:name=systemd:/a:b\n0::{path}\n");
        assert_eq!(cgroup(&hybrid).unwrap(), path);
        assert_eq!(cgroup("0::/\n").unwrap(), "/");
        assert_eq!(cgroup("0::/a:b\n").unwrap(), "/a:b");
    }

    #[test]
    fn a_cgroup_without_exactly_one_well_formed_v2_line_is_an_error() {
        for case in [
            "",
            "\n",
            "12:cpuset:/\n1:name=systemd:/\n",
            "0::/a\n0::/b\n",
            "0::/a\n\n",
            "0::\n",
            "0::a\n",
            "0:/a\n",
            "0:cpu:/a\n",
            "x:cpu:/\n0::/a\n",
            "12:cpuset\n0::/a\n",
            "12:cpuset:\n0::/a\n",
            "-1:cpu:/\n0::/a\n",
            "+1:cpu:/\n0::/a\n",
        ] {
            assert_eq!(
                cgroup(case).unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{case:?}"
            );
        }
    }
}
