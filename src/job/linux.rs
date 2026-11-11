use std::fs::{self, Metadata};
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Component, Path, PathBuf};

use crate::proxy::procfs;

const CGROUP_V2: &str = "terminal sessions need the cgroup v2 hierarchy mounted at /sys/fs/cgroup";
const OWN_CGROUP: &str = "terminal sessions need the cgroup of this process to be visible under \
                          /sys/fs/cgroup, which a container or a cgroup namespace can prevent";
const RUNTIME_DIR: &str = "terminal sessions need XDG_RUNTIME_DIR to name an absolute directory \
                           of this user that no one else can access";
const USER_MANAGER: &str = "terminal sessions need the systemd user manager: \
                            $XDG_RUNTIME_DIR/bus or $XDG_RUNTIME_DIR/systemd must belong to this \
                            user; log in through systemd-logind or enable lingering with \
                            `loginctl enable-linger`";
const DELEGATED: &str = "terminal sessions need the cgroup of the systemd user manager under \
                         /sys/fs/cgroup/user.slice to be delegated to this user";
const SYSTEMD_RUN_MISSING: &str = "terminal sessions need systemd-run at /usr/bin/systemd-run or \
                                   /bin/systemd-run; it is not looked up on PATH";
const SYSTEMD_RUN_UNSAFE: &str = "terminal sessions need systemd-run to be an executable file \
                                  owned by root or this user that no one else can write";

const SYSTEMD_RUN: [&str; 2] = ["/usr/bin/systemd-run", "/bin/systemd-run"];

pub(super) struct Host {
    proc: PathBuf,
    cgroup: PathBuf,
    runtime: Option<PathBuf>,
    uid: u32,
    candidates: Vec<PathBuf>,
}

impl Host {
    pub(super) fn current() -> Self {
        Self {
            proc: PathBuf::from("/proc"),
            cgroup: PathBuf::from("/sys/fs/cgroup"),
            runtime: std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
            // SAFETY: geteuid has no preconditions and always succeeds.
            uid: unsafe { libc::geteuid() },
            candidates: SYSTEMD_RUN.iter().map(PathBuf::from).collect(),
        }
    }

    pub(super) fn check(&self) -> io::Result<PathBuf> {
        self.cgroup_v2()?;
        self.own_cgroup()?;
        self.user_manager()?;
        self.delegated()?;
        self.systemd_run()
    }

    fn cgroup_v2(&self) -> io::Result<()> {
        if !lstat(&self.cgroup.join("cgroup.controllers")).is_some_and(|m| m.is_file()) {
            return Err(refuse(CGROUP_V2));
        }
        Ok(())
    }

    fn own_cgroup(&self) -> io::Result<()> {
        let text =
            fs::read_to_string(self.proc.join("self/cgroup")).map_err(|_| refuse(OWN_CGROUP))?;
        let own = procfs::cgroup(&text).map_err(|_| refuse(OWN_CGROUP))?;
        let own = Path::new(own)
            .strip_prefix("/")
            .map_err(|_| refuse(OWN_CGROUP))?;
        if own
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
            && lstat(&self.cgroup.join(own)).is_some_and(|m| m.is_dir())
        {
            Ok(())
        } else {
            Err(refuse(OWN_CGROUP))
        }
    }

    fn user_manager(&self) -> io::Result<()> {
        let runtime = self
            .runtime
            .as_deref()
            .filter(|runtime| runtime.is_absolute())
            .ok_or_else(|| refuse(RUNTIME_DIR))?;
        if !lstat(runtime).is_some_and(|m| m.is_dir() && self.owns(&m) && m.mode() & 0o077 == 0) {
            return Err(refuse(RUNTIME_DIR));
        }
        let bus = self.entry(&runtime.join("bus"), |m| m.file_type().is_socket())?;
        let manager = self.entry(&runtime.join("systemd"), Metadata::is_dir)?;
        if bus || manager {
            Ok(())
        } else {
            Err(refuse(USER_MANAGER))
        }
    }

    fn entry(&self, path: &Path, kind: impl Fn(&Metadata) -> bool) -> io::Result<bool> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if kind(&metadata) && self.owns(&metadata) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            _ => Err(refuse(USER_MANAGER)),
        }
    }

    fn delegated(&self) -> io::Result<()> {
        let uid = self.uid;
        let path = self
            .cgroup
            .join(format!("user.slice/user-{uid}.slice/user@{uid}.service"));
        if lstat(&path).is_some_and(|m| m.is_dir() && self.owns(&m)) {
            Ok(())
        } else {
            Err(refuse(DELEGATED))
        }
    }

    fn systemd_run(&self) -> io::Result<PathBuf> {
        for candidate in &self.candidates {
            if !candidate.is_absolute() {
                return Err(refuse(SYSTEMD_RUN_MISSING));
            }
            match fs::metadata(candidate) {
                Ok(m)
                    if m.is_file()
                        && (m.uid() == 0 || self.owns(&m))
                        && m.mode() & 0o022 == 0
                        && m.mode() & 0o111 != 0 =>
                {
                    return Ok(candidate.clone());
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                _ => return Err(refuse(SYSTEMD_RUN_UNSAFE)),
            }
        }
        Err(refuse(SYSTEMD_RUN_MISSING))
    }

    fn owns(&self, metadata: &Metadata) -> bool {
        metadata.uid() == self.uid
    }
}

fn lstat(path: &Path) -> Option<Metadata> {
    fs::symlink_metadata(path).ok()
}

fn refuse(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::os::unix::net::UnixListener;
    use std::path::Path;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    const OTHER: u32 = 4242;
    const STRANGER: u32 = 4343;

    fn euid() -> u32 {
        // SAFETY: geteuid has no preconditions and always succeeds.
        unsafe { libc::geteuid() }
    }

    struct Tree {
        root: PathBuf,
    }

    impl Tree {
        fn new() -> Self {
            static TREES: AtomicU32 = AtomicU32::new(0);
            let root = std::env::temp_dir().join(format!(
                "gateinto-containment-{}-{}",
                std::process::id(),
                TREES.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&root);
            let tree = Self { root };
            let uid = euid();
            tree.file(
                "proc/self/cgroup",
                &format!("0::/user.slice/user-{uid}.slice/session-2.scope\n"),
            );
            tree.file("cgroup/cgroup.controllers", "cpu memory pids\n");
            tree.dir(&format!(
                "cgroup/user.slice/user-{uid}.slice/session-2.scope"
            ));
            tree.dir(&format!(
                "cgroup/user.slice/user-{uid}.slice/user@{uid}.service/app.slice"
            ));
            tree.dir("run/systemd");
            tree.mode("run", 0o700);
            drop(UnixListener::bind(tree.path("run/bus")).unwrap());
            for helper in ["usr/bin/systemd-run", "bin/systemd-run"] {
                tree.file(helper, "#!/bin/sh\n");
                tree.mode(helper, 0o755);
            }
            tree
        }

        fn path(&self, relative: &str) -> PathBuf {
            self.root.join(relative)
        }

        fn file(&self, relative: &str, text: &str) {
            let path = self.path(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }

        fn dir(&self, relative: &str) {
            fs::create_dir_all(self.path(relative)).unwrap();
        }

        fn mode(&self, relative: &str, mode: u32) {
            fs::set_permissions(self.path(relative), fs::Permissions::from_mode(mode)).unwrap();
        }

        fn remove(&self, relative: &str) {
            let path = self.path(relative);
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(path).unwrap(),
                Ok(_) => fs::remove_file(path).unwrap(),
                Err(error) => panic!("{relative}: {error}"),
            }
        }

        fn link(&self, relative: &str, target: &str) {
            symlink(target, self.path(relative)).unwrap();
        }

        fn delegated(&self) -> String {
            let uid = euid();
            format!("cgroup/user.slice/user-{uid}.slice/user@{uid}.service")
        }

        fn host(&self) -> Host {
            self.host_of(euid())
        }

        fn host_of(&self, uid: u32) -> Host {
            Host {
                proc: self.path("proc"),
                cgroup: self.path("cgroup"),
                runtime: Some(self.path("run")),
                uid,
                candidates: vec![
                    self.path("usr/bin/systemd-run"),
                    self.path("bin/systemd-run"),
                ],
            }
        }

        fn check(&self) -> io::Result<PathBuf> {
            self.host().check()
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[track_caller]
    fn refused<T: std::fmt::Debug>(result: io::Result<T>) -> String {
        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported, "{error}");
        error.to_string()
    }

    fn from_current_dir(path: &Path) -> PathBuf {
        let mut relative = PathBuf::new();
        for _ in std::env::current_dir().unwrap().components().skip(1) {
            relative.push("..");
        }
        relative.push(path.strip_prefix("/").unwrap());
        assert!(relative.is_relative());
        assert!(fs::symlink_metadata(&relative).is_ok(), "{relative:?}");
        relative
    }

    #[test]
    fn a_complete_tree_passes_with_the_systemd_run_from_usr_bin() {
        let tree = Tree::new();
        assert_eq!(tree.check().unwrap(), tree.path("usr/bin/systemd-run"));
    }

    #[test]
    fn the_own_cgroup_may_be_anywhere_in_the_hierarchy() {
        let tree = Tree::new();
        let uid = euid();
        for path in [
            "/".to_owned(),
            format!("/user.slice/user-{uid}.slice/user@{uid}.service/app.slice"),
            format!("/user.slice/user-{uid}.slice/session-2.scope"),
        ] {
            tree.file("proc/self/cgroup", &format!("0::{path}\n"));
            assert!(tree.check().is_ok(), "{path}");
        }
        tree.file(
            "proc/self/cgroup",
            &format!("1:name=systemd:/x\n0::/user.slice/user-{uid}.slice/session-2.scope\n"),
        );
        assert!(tree.check().is_ok());
    }

    #[test]
    fn without_the_unified_hierarchy_cgroup_v2_is_missing() {
        let tree = Tree::new();
        tree.remove("cgroup/cgroup.controllers");
        assert_eq!(refused(tree.check()), CGROUP_V2);
        tree.dir("cgroup/cgroup.controllers");
        assert_eq!(refused(tree.check()), CGROUP_V2);
        tree.remove("cgroup/cgroup.controllers");
        tree.file("controllers", "cpu\n");
        tree.link("cgroup/cgroup.controllers", "../controllers");
        assert_eq!(refused(tree.check()), CGROUP_V2);
        tree.remove("cgroup/cgroup.controllers");
        tree.file(
            "proc/self/cgroup",
            "12:cpuset:/\n1:name=systemd:/user.slice\n0::/user.slice\n",
        );
        assert_eq!(refused(tree.check()), CGROUP_V2);
    }

    #[test]
    fn the_own_cgroup_must_be_a_directory_of_the_hierarchy() {
        let tree = Tree::new();
        let uid = euid();
        let scope = format!("/user.slice/user-{uid}.slice/session-2.scope");
        for text in [
            String::new(),
            "\n".to_owned(),
            "12:cpuset:/\n".to_owned(),
            format!("0::{scope}\n0::{scope}\n"),
            format!("0:cpu:{scope}\n"),
            "0::/missing.scope\n".to_owned(),
            format!("0::{scope} (deleted)\n"),
            format!("0::/../cgroup{scope}\n"),
            format!("0::{scope}/../session-2.scope\n"),
            "0::/cgroup.controllers\n".to_owned(),
        ] {
            tree.file("proc/self/cgroup", &text);
            assert_eq!(refused(tree.check()), OWN_CGROUP, "{text:?}");
        }
        tree.remove("proc/self/cgroup");
        assert_eq!(refused(tree.check()), OWN_CGROUP);
    }

    #[test]
    fn xdg_runtime_dir_must_be_an_absolute_private_directory_of_this_user() {
        let tree = Tree::new();
        let mut host = tree.host();
        for runtime in [
            None,
            Some(PathBuf::new()),
            Some(PathBuf::from("run")),
            Some(from_current_dir(&tree.path("run"))),
            Some(tree.path("missing")),
            Some(tree.path("proc/self/cgroup")),
        ] {
            host.runtime = runtime.clone();
            assert_eq!(refused(host.check()), RUNTIME_DIR, "{runtime:?}");
        }
        tree.link("linked", "run");
        host.runtime = Some(tree.path("linked"));
        assert_eq!(refused(host.check()), RUNTIME_DIR);
        for mode in [0o750, 0o705, 0o701, 0o710] {
            tree.mode("run", mode);
            assert_eq!(refused(tree.check()), RUNTIME_DIR, "{mode:o}");
        }
        tree.mode("run", 0o700);
        assert!(tree.check().is_ok());
    }

    #[test]
    fn the_user_manager_needs_its_bus_or_its_directory() {
        let tree = Tree::new();
        tree.remove("run/systemd");
        assert!(tree.check().is_ok());
        tree.dir("run/systemd");
        tree.remove("run/bus");
        assert!(tree.check().is_ok());
        tree.remove("run/systemd");
        assert_eq!(refused(tree.check()), USER_MANAGER);
        tree.file("run/systemd", "");
        assert_eq!(refused(tree.check()), USER_MANAGER);
        tree.remove("run/systemd");
        tree.dir("elsewhere");
        tree.link("run/systemd", "../elsewhere");
        assert_eq!(refused(tree.check()), USER_MANAGER);
        tree.remove("run/systemd");
        tree.dir("run/systemd");
        tree.file("run/bus", "");
        assert_eq!(refused(tree.check()), USER_MANAGER);
        tree.remove("run/bus");
        drop(UnixListener::bind(tree.path("socket")).unwrap());
        tree.link("run/bus", "../socket");
        assert_eq!(refused(tree.check()), USER_MANAGER);
    }

    #[test]
    fn the_delegated_cgroup_must_be_a_directory() {
        let tree = Tree::new();
        let delegated = tree.delegated();
        tree.remove(&delegated);
        assert_eq!(refused(tree.check()), DELEGATED);
        tree.file(&delegated, "");
        assert_eq!(refused(tree.check()), DELEGATED);
        tree.remove(&delegated);
        tree.dir("cgroup/user.slice/elsewhere");
        tree.link(&delegated, "../elsewhere");
        assert_eq!(refused(tree.check()), DELEGATED);
    }

    #[test]
    fn pieces_of_another_user_are_refused() {
        let tree = Tree::new();
        let host = tree.host_of(OTHER);
        assert_eq!(refused(host.user_manager()), RUNTIME_DIR);
        assert_eq!(refused(host.delegated()), DELEGATED);
        tree.dir(&format!(
            "cgroup/user.slice/user-{OTHER}.slice/user@{OTHER}.service"
        ));
        assert_eq!(refused(host.delegated()), DELEGATED);
        if euid() == 0 {
            std::os::unix::fs::chown(tree.path("usr/bin/systemd-run"), Some(STRANGER), None)
                .unwrap();
        }
        assert_eq!(refused(host.systemd_run()), SYSTEMD_RUN_UNSAFE);
        if euid() == 0 {
            std::os::unix::fs::chown(tree.path("run"), Some(OTHER), None).unwrap();
            for entry in ["run/bus", "run/systemd"] {
                std::os::unix::fs::chown(tree.path(entry), Some(STRANGER), None).unwrap();
            }
            assert_eq!(refused(host.user_manager()), USER_MANAGER);
            std::os::unix::fs::chown(tree.path("run/systemd"), Some(OTHER), None).unwrap();
            assert_eq!(refused(host.user_manager()), USER_MANAGER);
            std::os::unix::fs::chown(tree.path("run/bus"), Some(OTHER), None).unwrap();
            assert!(host.user_manager().is_ok());

            tree.file("foreign/systemd-run", "#!/bin/sh\n");
            tree.mode("foreign/systemd-run", 0o755);
            std::os::unix::fs::chown(tree.path("foreign/systemd-run"), Some(STRANGER), None)
                .unwrap();
            tree.remove("usr/bin/systemd-run");
            tree.link("usr/bin/systemd-run", "../../foreign/systemd-run");
            let link = fs::symlink_metadata(tree.path("usr/bin/systemd-run")).unwrap();
            assert_eq!(std::os::unix::fs::MetadataExt::uid(&link), 0);
            assert_eq!(refused(tree.host().systemd_run()), SYSTEMD_RUN_UNSAFE);
        }
    }

    #[test]
    fn systemd_run_is_taken_from_usr_bin_then_from_bin() {
        let tree = Tree::new();
        tree.remove("usr/bin/systemd-run");
        assert_eq!(tree.check().unwrap(), tree.path("bin/systemd-run"));
        tree.remove("bin/systemd-run");
        assert_eq!(refused(tree.check()), SYSTEMD_RUN_MISSING);
        tree.file("usr/bin/systemd-run", "");
        tree.mode("usr/bin/systemd-run", 0o755);
        tree.link("bin/systemd-run", "../usr/bin/systemd-run");
        tree.remove("usr/bin/systemd-run");
        assert_eq!(refused(tree.check()), SYSTEMD_RUN_MISSING);
    }

    #[test]
    fn a_systemd_run_behind_a_symlink_is_its_target() {
        let tree = Tree::new();
        tree.remove("usr/bin/systemd-run");
        tree.link("usr/bin/systemd-run", "../../bin/systemd-run");
        assert_eq!(tree.check().unwrap(), tree.path("usr/bin/systemd-run"));
        tree.mode("bin/systemd-run", 0o775);
        assert_eq!(refused(tree.check()), SYSTEMD_RUN_UNSAFE);
    }

    #[test]
    fn an_unsafe_systemd_run_is_refused_without_falling_back() {
        let tree = Tree::new();
        for mode in [0o775, 0o757, 0o777, 0o644, 0o600] {
            tree.mode("usr/bin/systemd-run", mode);
            assert_eq!(refused(tree.check()), SYSTEMD_RUN_UNSAFE, "{mode:o}");
        }
        tree.remove("usr/bin/systemd-run");
        tree.dir("usr/bin/systemd-run");
        tree.mode("usr/bin/systemd-run", 0o755);
        assert_eq!(refused(tree.check()), SYSTEMD_RUN_UNSAFE);
        tree.remove("usr/bin/systemd-run");
        tree.file("usr/bin/systemd-run", "");
        tree.mode("usr/bin/systemd-run", 0o755);
        let mut host = tree.host();
        host.candidates = vec![
            tree.path("usr/bin/systemd-run/systemd-run"),
            tree.path("bin/systemd-run"),
        ];
        assert_eq!(refused(host.check()), SYSTEMD_RUN_UNSAFE);
    }

    #[test]
    fn systemd_run_is_never_resolved_against_the_current_directory() {
        let tree = Tree::new();
        let mut host = tree.host();
        for first in [
            PathBuf::from("systemd-run"),
            from_current_dir(&tree.path("bin/systemd-run")),
        ] {
            host.candidates = vec![first.clone(), tree.path("bin/systemd-run")];
            assert_eq!(refused(host.check()), SYSTEMD_RUN_MISSING, "{first:?}");
        }
    }

    #[test]
    fn the_first_missing_piece_is_reported() {
        let tree = Tree::new();
        tree.remove("usr/bin/systemd-run");
        tree.remove("bin/systemd-run");
        assert_eq!(refused(tree.check()), SYSTEMD_RUN_MISSING);
        tree.remove(&tree.delegated());
        assert_eq!(refused(tree.check()), DELEGATED);
        tree.remove("run/bus");
        tree.remove("run/systemd");
        assert_eq!(refused(tree.check()), USER_MANAGER);
        tree.remove("run");
        assert_eq!(refused(tree.check()), RUNTIME_DIR);
        tree.remove("proc");
        assert_eq!(refused(tree.check()), OWN_CGROUP);
        tree.remove("cgroup");
        assert_eq!(refused(tree.check()), CGROUP_V2);
    }

    #[test]
    fn the_current_host_uses_the_fixed_paths_and_the_effective_uid() {
        let host = Host::current();
        assert_eq!(host.proc, Path::new("/proc"));
        assert_eq!(host.cgroup, Path::new("/sys/fs/cgroup"));
        assert_eq!(
            host.runtime,
            std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from)
        );
        assert_eq!(host.uid, euid());
        assert_eq!(
            host.candidates,
            [
                Path::new("/usr/bin/systemd-run"),
                Path::new("/bin/systemd-run")
            ]
        );
        assert!(host.candidates.iter().all(|path| path.is_absolute()));
    }

    #[test]
    fn the_real_host_is_ready_or_names_the_missing_piece() {
        if let Err(error) = Host::current().check() {
            assert_eq!(error.kind(), io::ErrorKind::Unsupported, "{error}");
            assert!(
                [
                    CGROUP_V2,
                    OWN_CGROUP,
                    RUNTIME_DIR,
                    USER_MANAGER,
                    DELEGATED,
                    SYSTEMD_RUN_MISSING,
                    SYSTEMD_RUN_UNSAFE,
                ]
                .contains(&error.to_string().as_str()),
                "{error}"
            );
        }
    }
}
