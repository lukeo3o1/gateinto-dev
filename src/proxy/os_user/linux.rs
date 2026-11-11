use std::fs;
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::time::Instant;

use super::procfs::{self, LinuxRow};
use super::{Denial, Family, LOOKUP_ATTEMPTS, LOOKUP_DELAY, Owners, families};

pub(super) struct System {
    root: PathBuf,
    uid: u32,
}

enum Holder {
    Ours,
    Other,
}

#[derive(Debug)]
enum Failure {
    Gone,
    Fatal(Denial),
    Skipped(io::Error),
}

impl System {
    pub(super) fn new() -> Self {
        // SAFETY: geteuid has no preconditions and always succeeds.
        Self::at(PathBuf::from("/proc"), unsafe { libc::geteuid() })
    }

    fn at(root: PathBuf, uid: u32) -> Self {
        Self { root, uid }
    }

    fn find(&self, peer: SocketAddr, local: SocketAddr) -> Result<LinuxRow, Denial> {
        for attempt in 1..=LOOKUP_ATTEMPTS {
            if let Some(row) = self.row(peer, local)? {
                return Ok(row);
            }
            if attempt < LOOKUP_ATTEMPTS {
                std::thread::sleep(LOOKUP_DELAY);
            }
        }
        Err(Denial::NotFound)
    }

    fn row(&self, peer: SocketAddr, local: SocketAddr) -> Result<Option<LinuxRow>, Denial> {
        for &family in families(peer) {
            let path = self.root.join("net").join(match family {
                Family::V4 => "tcp",
                Family::V6 => "tcp6",
            });
            let rows = fs::read_to_string(&path)
                .and_then(|text| procfs::table(family, &text))
                .map_err(|error| Denial::Lookup(format!("{}: {error}", path.display())))?;
            if let Some(row) = procfs::connection(rows, peer, local) {
                return Ok(Some(row));
            }
        }
        Ok(None)
    }

    fn holder(&self, inode: u64, deadline: Instant) -> Result<(), Denial> {
        let socket = format!("socket:[{inode}]");
        let unreadable =
            |error: io::Error| Denial::Lookup(format!("{}: {error}", self.root.display()));
        let mut other = false;
        let mut skipped = None;
        for entry in fs::read_dir(&self.root).map_err(unreadable)? {
            let entry = entry.map_err(unreadable)?;
            let Some(pid) = entry.file_name().to_str().and_then(procfs::decimal::<i32>) else {
                continue;
            };
            if Instant::now() >= deadline {
                return Err(Denial::TimedOut);
            }
            match self.inspect(pid, &entry.path(), &socket).map_err(failure) {
                Ok(Some(Holder::Ours)) => return Ok(()),
                Ok(Some(Holder::Other)) => other = true,
                Ok(None) | Err(Failure::Gone) => {}
                Err(Failure::Fatal(denial)) => return Err(denial),
                Err(Failure::Skipped(error)) => {
                    skipped.get_or_insert_with(|| format!("process {pid}: {error}"));
                }
            }
        }
        Err(match (other, skipped) {
            (true, _) => Denial::OtherUser,
            (false, Some(error)) => Denial::Lookup(error),
            (false, None) => Denial::NotFound,
        })
    }

    fn inspect(&self, pid: i32, dir: &Path, socket: &str) -> io::Result<Option<Holder>> {
        let status = dir.join("status");
        if !procfs::uids(&fs::read_to_string(&status)?)?.contains(&self.uid) {
            return Ok(None);
        }
        let pidfd = pidfd_open(pid)?;
        if !holds(&dir.join("fd"), socket)? {
            return Ok(None);
        }
        let uids = procfs::uids(&fs::read_to_string(&status)?)?;
        if exited(&pidfd)? {
            return Ok(None);
        }
        Ok(Some(if uids == [self.uid; 4] {
            Holder::Ours
        } else {
            Holder::Other
        }))
    }
}

impl Owners for System {
    fn check(&self, peer: SocketAddr, local: SocketAddr, deadline: Instant) -> Result<(), Denial> {
        let row = self.find(peer, local)?;
        if row.uid != self.uid {
            return Err(Denial::OtherUser);
        }
        self.holder(row.inode, deadline)?;
        match self.row(peer, local)? {
            Some(again) if again.inode == row.inode => Ok(()),
            _ => Err(Denial::NotFound),
        }
    }
}

fn holds(fds: &Path, socket: &str) -> io::Result<bool> {
    for entry in fs::read_dir(fds)? {
        match fs::read_link(entry?.path()) {
            Ok(link) if link.as_os_str() == socket => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

fn pidfd_open(pid: libc::pid_t) -> io::Result<OwnedFd> {
    let flags: libc::c_uint = 0;
    // SAFETY: pidfd_open only reads its two integer arguments.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel returned a new descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

fn exited(pidfd: &OwnedFd) -> io::Result<bool> {
    let mut poll = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        // SAFETY: poll gets one valid pollfd and does not keep it.
        if unsafe { libc::poll(&mut poll, 1, 0) } >= 0 {
            return Ok(poll.revents != 0);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn failure(error: io::Error) -> Failure {
    match error.raw_os_error() {
        Some(libc::ENOENT | libc::ESRCH) => Failure::Gone,
        Some(libc::ENOSYS) => Failure::Fatal(Denial::Lookup(format!(
            "pidfd_open is unavailable; Linux 5.3 or later is needed: {error}"
        ))),
        _ => Failure::Skipped(error),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::IpAddr;
    use std::os::unix::fs::symlink;
    use std::process::{Child, Command};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    use super::*;

    const UID: u32 = 4242;
    const OTHER: u32 = 4343;
    const INODE: u64 = 98765;

    fn peer() -> SocketAddr {
        "127.0.0.1:50000".parse().unwrap()
    }

    fn listener() -> SocketAddr {
        "127.0.0.1:8080".parse().unwrap()
    }

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    fn me() -> u32 {
        std::process::id()
    }

    struct Tree {
        root: PathBuf,
    }

    impl Tree {
        fn new() -> Self {
            static TREES: AtomicU32 = AtomicU32::new(0);
            let root = std::env::temp_dir().join(format!(
                "gateinto-procfs-{}-{}",
                me(),
                TREES.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(root.join("net")).unwrap();
            let tree = Self { root };
            tree.rows(&[], &[]);
            tree
        }

        fn rows(
            &self,
            v4: &[(SocketAddr, SocketAddr, u32, u64)],
            v6: &[(SocketAddr, SocketAddr, u32, u64)],
        ) {
            for (name, rows) in [("tcp", v4), ("tcp6", v6)] {
                let mut text = "  sl  local_address rem_address   st tx_queue rx_queue tr \
                                tm->when retrnsmt   uid  timeout inode\n"
                    .to_owned();
                for (slot, (local, remote, uid, inode)) in rows.iter().enumerate() {
                    text.push_str(&format!(
                        "   {slot}: {} {} 01 00000000:00000000 00:00000000 00000000 {uid:5} \
                         0 {inode} 1 0000000000000000 20 4 30 10 -1\n",
                        hex(*local),
                        hex(*remote)
                    ));
                }
                fs::write(self.root.join("net").join(name), text).unwrap();
            }
        }

        fn connection(&self, uid: u32, inode: u64) {
            self.rows(&[(peer(), listener(), uid, inode)], &[]);
        }

        fn process(&self, pid: u32, uids: [u32; 4], sockets: &[u64]) {
            let dir = self.status(pid, uids);
            fs::create_dir(dir.join("fd")).unwrap();
            for (fd, inode) in [0, 1, 2].into_iter().zip([1, 2, 3]).chain(
                sockets
                    .iter()
                    .enumerate()
                    .map(|(index, inode)| (index + 3, *inode)),
            ) {
                symlink(
                    format!("socket:[{inode}]"),
                    dir.join("fd").join(fd.to_string()),
                )
                .unwrap();
            }
            symlink("/dev/null", dir.join("fd").join("99")).unwrap();
        }

        fn unreadable(&self, pid: u32, uids: [u32; 4]) {
            let dir = self.status(pid, uids);
            fs::write(dir.join("fd"), "").unwrap();
        }

        fn status(&self, pid: u32, [real, effective, saved, fs]: [u32; 4]) -> PathBuf {
            let dir = self.root.join(pid.to_string());
            fs::create_dir(&dir).unwrap();
            fs::write(
                dir.join("status"),
                format!(
                    "Name:\tclient\nPid:\t{pid}\nUid:\t{real}\t{effective}\t{saved}\t{fs}\n\
                     Gid:\t1\t1\t1\t1\n"
                ),
            )
            .unwrap();
            dir
        }

        fn check(&self) -> Result<(), Denial> {
            self.check_until(far())
        }

        fn check_until(&self, deadline: Instant) -> Result<(), Denial> {
            System::at(self.root.clone(), UID).check(peer(), listener(), deadline)
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn hex(addr: SocketAddr) -> String {
        let ip = match addr.ip() {
            IpAddr::V4(ip) => format!("{:08X}", u32::from_ne_bytes(ip.octets())),
            IpAddr::V6(ip) => ip
                .octets()
                .as_chunks::<4>()
                .0
                .iter()
                .map(|word| format!("{:08X}", u32::from_ne_bytes(*word)))
                .collect(),
        };
        format!("{ip}:{:04X}", addr.port())
    }

    struct Kid(Child);

    impl Kid {
        fn sleeping() -> Self {
            Self(Command::new("/bin/sleep").arg("60").spawn().unwrap())
        }

        fn zombie() -> Self {
            let kid = Self(Command::new("/bin/true").spawn().unwrap());
            let stat = format!("/proc/{}/stat", kid.pid());
            let until = Instant::now() + Duration::from_secs(10);
            while !fs::read_to_string(&stat)
                .unwrap()
                .rsplit_once(") ")
                .is_some_and(|(_, rest)| rest.starts_with('Z'))
            {
                assert!(Instant::now() < until, "the child did not exit");
                std::thread::sleep(Duration::from_millis(5));
            }
            kid
        }

        fn reaped() -> u32 {
            let mut kid = Command::new("/bin/true").spawn().unwrap();
            kid.wait().unwrap();
            kid.id()
        }

        fn pid(&self) -> u32 {
            self.0.id()
        }
    }

    impl Drop for Kid {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn a_live_holder_of_our_uid_is_accepted() {
        let tree = Tree::new();
        tree.connection(UID, INODE);
        tree.process(me(), [UID; 4], &[INODE]);
        assert_eq!(tree.check(), Ok(()));
    }

    #[test]
    fn an_ipv4_peer_is_also_found_as_a_mapped_row_and_an_ipv6_peer_in_tcp6() {
        let tree = Tree::new();
        let mapped = |addr: SocketAddr| match addr.ip() {
            IpAddr::V4(ip) => SocketAddr::new(ip.to_ipv6_mapped().into(), addr.port()),
            IpAddr::V6(_) => addr,
        };
        tree.rows(&[], &[(mapped(peer()), mapped(listener()), UID, INODE)]);
        tree.process(me(), [UID; 4], &[INODE]);
        assert_eq!(tree.check(), Ok(()));
        let (v6, server) = (
            "[::1]:50000".parse().unwrap(),
            "[::1]:8080".parse().unwrap(),
        );
        tree.rows(&[], &[(v6, server, UID, INODE)]);
        let system = System::at(tree.root.clone(), UID);
        assert_eq!(system.check(v6, server, far()), Ok(()));
        assert_eq!(
            system.check(peer(), listener(), far()),
            Err(Denial::NotFound)
        );
        fs::write(tree.root.join("net/tcp"), "garbage\n").unwrap();
        assert_eq!(system.check(v6, server, far()), Ok(()));
    }

    #[test]
    fn no_row_is_not_found() {
        let tree = Tree::new();
        tree.rows(&[(listener(), peer(), UID, INODE)], &[]);
        tree.process(me(), [UID; 4], &[INODE]);
        assert_eq!(tree.check(), Err(Denial::NotFound));
    }

    #[test]
    fn a_row_of_another_uid_is_another_user() {
        let tree = Tree::new();
        tree.connection(OTHER, INODE);
        tree.process(me(), [UID; 4], &[INODE]);
        assert_eq!(tree.check(), Err(Denial::OtherUser));
    }

    #[test]
    fn a_row_with_inode_0_is_ignored() {
        let tree = Tree::new();
        tree.connection(UID, 0);
        tree.process(me(), [UID; 4], &[0]);
        assert_eq!(tree.check(), Err(Denial::NotFound));
    }

    #[test]
    fn a_connection_that_no_process_holds_is_not_found() {
        let tree = Tree::new();
        tree.connection(UID, INODE);
        tree.process(me(), [UID; 4], &[INODE + 1]);
        let kid = Kid::sleeping();
        tree.process(kid.pid(), [UID; 4], &[]);
        assert_eq!(tree.check(), Err(Denial::NotFound));
    }

    #[test]
    fn an_unreadable_process_next_to_a_readable_holder_is_accepted() {
        let tree = Tree::new();
        tree.connection(UID, INODE);
        let kid = Kid::sleeping();
        tree.unreadable(kid.pid(), [UID; 4]);
        tree.process(me(), [UID; 4], &[INODE]);
        assert_eq!(tree.check(), Ok(()));
    }

    #[test]
    fn an_unreadable_process_and_no_holder_is_a_lookup_denial() {
        let tree = Tree::new();
        tree.connection(UID, INODE);
        let kid = Kid::sleeping();
        tree.unreadable(kid.pid(), [UID; 4]);
        tree.process(me(), [UID; 4], &[INODE + 1]);
        assert!(matches!(tree.check(), Err(Denial::Lookup(_))));
    }

    #[test]
    fn a_malformed_status_of_our_uid_is_a_lookup_denial() {
        let tree = Tree::new();
        tree.connection(UID, INODE);
        let kid = Kid::sleeping();
        tree.process(kid.pid(), [UID; 4], &[]);
        fs::write(
            tree.root.join(kid.pid().to_string()).join("status"),
            format!("Uid:\t{UID}\t{UID}\t{UID}\nUid:\t{UID}\t{UID}\t{UID}\t{UID}\n"),
        )
        .unwrap();
        assert!(matches!(tree.check(), Err(Denial::Lookup(_))));
    }

    #[test]
    fn processes_of_other_uids_are_not_inspected() {
        let tree = Tree::new();
        tree.connection(UID, INODE);
        tree.unreadable(1, [OTHER; 4]);
        tree.process(me(), [OTHER; 4], &[INODE]);
        assert_eq!(tree.check(), Err(Denial::NotFound));
    }

    #[test]
    fn a_holder_with_any_other_uid_is_another_user() {
        for index in 0..4 {
            let tree = Tree::new();
            tree.connection(UID, INODE);
            let mut uids = [UID; 4];
            uids[index] = OTHER;
            tree.process(me(), uids, &[INODE]);
            assert_eq!(tree.check(), Err(Denial::OtherUser), "{uids:?}");
        }
    }

    #[test]
    fn a_holder_of_our_uid_wins_over_a_holder_of_another_uid() {
        let tree = Tree::new();
        tree.connection(UID, INODE);
        let kid = Kid::sleeping();
        tree.process(kid.pid(), [UID, UID, OTHER, UID], &[INODE]);
        tree.process(me(), [UID; 4], &[INODE]);
        assert_eq!(tree.check(), Ok(()));
    }

    #[test]
    fn a_zombie_holder_is_not_found() {
        let tree = Tree::new();
        tree.connection(UID, INODE);
        let kid = Kid::zombie();
        tree.process(kid.pid(), [UID; 4], &[INODE]);
        assert_eq!(tree.check(), Err(Denial::NotFound));
    }

    #[test]
    fn an_exited_holder_is_not_found() {
        let tree = Tree::new();
        tree.connection(UID, INODE);
        tree.process(Kid::reaped(), [UID; 4], &[INODE]);
        assert_eq!(tree.check(), Err(Denial::NotFound));
    }

    #[test]
    fn a_reached_deadline_stops_the_scan() {
        let tree = Tree::new();
        tree.connection(UID, INODE);
        tree.process(me(), [UID; 4], &[INODE]);
        assert_eq!(tree.check_until(Instant::now()), Err(Denial::TimedOut));
    }

    #[test]
    fn an_unreadable_table_is_a_lookup_denial() {
        let tree = Tree::new();
        tree.process(me(), [UID; 4], &[INODE]);
        fs::remove_file(tree.root.join("net/tcp")).unwrap();
        assert!(matches!(tree.check(), Err(Denial::Lookup(_))));
        tree.connection(UID, INODE);
        fs::write(tree.root.join("net/tcp6"), "garbage\n").unwrap();
        assert_eq!(tree.check(), Ok(()));
        fs::write(tree.root.join("net/tcp"), "garbage\n").unwrap();
        assert!(matches!(tree.check(), Err(Denial::Lookup(_))));
    }

    #[test]
    fn a_kernel_without_pidfd_open_is_a_lookup_denial_and_a_vanished_process_is_ignored() {
        let fatal = failure(io::Error::from_raw_os_error(libc::ENOSYS));
        assert!(
            matches!(&fatal, Failure::Fatal(Denial::Lookup(error)) if error.contains("Linux 5.3")),
            "{fatal:?}"
        );
        for gone in [libc::ESRCH, libc::ENOENT] {
            assert!(matches!(
                failure(io::Error::from_raw_os_error(gone)),
                Failure::Gone
            ));
        }
        for skipped in [libc::EACCES, libc::ENOTDIR] {
            assert!(matches!(
                failure(io::Error::from_raw_os_error(skipped)),
                Failure::Skipped(_)
            ));
        }
    }

    #[test]
    fn the_system_lookup_reads_proc_as_the_effective_user() {
        let system = System::new();
        assert_eq!(system.root, PathBuf::from("/proc"));
        // SAFETY: geteuid has no preconditions and always succeeds.
        assert_eq!(system.uid, unsafe { libc::geteuid() });
    }
}
