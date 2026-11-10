use super::xdg::Roots;
use super::{keyfile, mimeapps};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const MAX_FILE_SIZE: u64 = 1 << 20;

pub(crate) fn registered_command(roots: &Roots, scheme: &str) -> Option<String> {
    let applications: Vec<PathBuf> = roots
        .data_home
        .iter()
        .chain(&roots.data_dirs)
        .map(|dir| dir.join("applications"))
        .collect();
    let names: Vec<String> = roots
        .desktops
        .iter()
        .map(|desktop| format!("{desktop}-mimeapps.list"))
        .chain(["mimeapps.list".to_owned()])
        .collect();
    let dirs = roots
        .config_home
        .iter()
        .chain(&roots.config_dirs)
        .chain(&applications);
    for dir in dirs {
        for name in &names {
            let Some(text) = read(&dir.join(name)) else {
                continue;
            };
            for id in mimeapps::default_ids(&text, scheme) {
                if let Some(entry) = installed(&applications, id) {
                    return exec(&entry).map(str::to_owned);
                }
            }
        }
    }
    None
}

fn installed(applications: &[PathBuf], id: &str) -> Option<String> {
    if !is_desktop_id(id) {
        return None;
    }
    applications.iter().find_map(|dir| read(&dir.join(id)))
}

fn read(path: &Path) -> Option<String> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE_SIZE + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > MAX_FILE_SIZE {
        return None;
    }
    String::from_utf8(bytes).ok()
}

fn is_desktop_id(id: &str) -> bool {
    id.ends_with(".desktop") && !id.contains(['/', '\\']) && !id.contains(char::is_control)
}

fn exec(entry: &str) -> Option<&str> {
    keyfile::values(entry, "Desktop Entry", |key| key == "Exec").last()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            static RUNS: AtomicU32 = AtomicU32::new(0);
            let dir = std::env::temp_dir().join(format!(
                "gateinto-lookup-{}-{}",
                std::process::id(),
                RUNS.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn roots(&self, desktops: &[&str]) -> Roots {
            Roots {
                config_home: Some(self.0.join("config")),
                config_dirs: vec![self.0.join("etc1"), self.0.join("etc2")],
                data_home: Some(self.0.join("data")),
                data_dirs: vec![self.0.join("share1"), self.0.join("share2")],
                desktops: desktops.iter().map(|name| (*name).to_owned()).collect(),
            }
        }

        fn write(&self, path: &str, text: &str) {
            let path = self.0.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }

        fn default(&self, path: &str, ids: &str) {
            self.write(
                path,
                &format!("[Default Applications]\nx-scheme-handler/gateinto={ids}\n"),
            );
        }

        fn install(&self, dir: &str, id: &str, exec: &str) {
            self.write(
                &format!("{dir}/applications/{id}"),
                &format!("[Desktop Entry]\nType=Application\nExec={exec}\n"),
            );
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn lookup(scratch: &Scratch) -> Option<String> {
        registered_command(&scratch.roots(&[]), "gateinto")
    }

    #[test]
    fn nothing_is_registered_without_a_default() {
        let scratch = Scratch::new();
        assert_eq!(lookup(&scratch), None);
        scratch.install("data", "gateinto.desktop", "ours");
        scratch.default("config/mimeapps.list", "");
        assert_eq!(lookup(&scratch), None);
    }

    #[test]
    fn the_exec_of_the_installed_default_is_returned() {
        let scratch = Scratch::new();
        scratch.default("config/mimeapps.list", "gateinto.desktop;");
        scratch.install("data", "gateinto.desktop", "\"/opt/gateinto\" open -- %u");
        assert_eq!(
            lookup(&scratch).as_deref(),
            Some("\"/opt/gateinto\" open -- %u")
        );
        assert_eq!(registered_command(&scratch.roots(&[]), "other"), None);
    }

    #[test]
    fn uninstalled_ids_are_skipped_in_order() {
        let scratch = Scratch::new();
        scratch.default(
            "config/mimeapps.list",
            "missing.desktop;foo.desktop;gateinto.desktop",
        );
        scratch.install("data", "gateinto.desktop", "ours");
        scratch.install("share2", "foo.desktop", "foo");
        assert_eq!(lookup(&scratch).as_deref(), Some("foo"));
    }

    #[test]
    fn a_file_without_an_installed_id_falls_through_to_the_next() {
        let scratch = Scratch::new();
        scratch.default("config/mimeapps.list", "missing.desktop");
        scratch.default("etc2/mimeapps.list", "gateinto.desktop");
        scratch.install("data", "gateinto.desktop", "ours");
        assert_eq!(lookup(&scratch).as_deref(), Some("ours"));
    }

    #[test]
    fn files_are_read_in_the_lookup_order() {
        let scratch = Scratch::new();
        let files = [
            "config/kde-mimeapps.list",
            "config/gnome-mimeapps.list",
            "config/mimeapps.list",
            "etc1/kde-mimeapps.list",
            "etc1/mimeapps.list",
            "etc2/gnome-mimeapps.list",
            "etc2/mimeapps.list",
            "data/applications/kde-mimeapps.list",
            "data/applications/mimeapps.list",
            "share1/applications/gnome-mimeapps.list",
            "share1/applications/mimeapps.list",
            "share2/applications/kde-mimeapps.list",
            "share2/applications/mimeapps.list",
        ];
        for (index, file) in files.iter().enumerate() {
            scratch.default(file, &format!("app{index}.desktop"));
            scratch.install(
                "data",
                &format!("app{index}.desktop"),
                &format!("app{index}"),
            );
        }
        let roots = scratch.roots(&["kde", "gnome"]);
        for (index, file) in files.iter().enumerate() {
            assert_eq!(
                registered_command(&roots, "gateinto"),
                Some(format!("app{index}")),
                "{file}"
            );
            std::fs::remove_file(scratch.0.join(file)).unwrap();
        }
        assert_eq!(registered_command(&roots, "gateinto"), None);
    }

    #[test]
    fn desktop_specific_files_are_read_only_for_the_current_desktops() {
        let scratch = Scratch::new();
        scratch.default("config/kde-mimeapps.list", "kde.desktop");
        scratch.default("config/mimeapps.list", "gateinto.desktop");
        scratch.install("data", "kde.desktop", "kde");
        scratch.install("data", "gateinto.desktop", "ours");
        assert_eq!(lookup(&scratch).as_deref(), Some("ours"));
        assert_eq!(
            registered_command(&scratch.roots(&["gnome"]), "gateinto").as_deref(),
            Some("ours")
        );
        assert_eq!(
            registered_command(&scratch.roots(&["gnome", "kde"]), "gateinto").as_deref(),
            Some("kde")
        );
    }

    #[test]
    fn desktop_files_are_found_in_data_home_before_the_data_dirs() {
        let scratch = Scratch::new();
        scratch.default("config/mimeapps.list", "gateinto.desktop");
        scratch.install("share2", "gateinto.desktop", "share2");
        assert_eq!(lookup(&scratch).as_deref(), Some("share2"));
        scratch.install("share1", "gateinto.desktop", "share1");
        assert_eq!(lookup(&scratch).as_deref(), Some("share1"));
        scratch.install("data", "gateinto.desktop", "data");
        assert_eq!(lookup(&scratch).as_deref(), Some("data"));
    }

    #[test]
    fn missing_roots_are_skipped() {
        let scratch = Scratch::new();
        scratch.default("etc1/mimeapps.list", "gateinto.desktop");
        scratch.install("share1", "gateinto.desktop", "ours");
        let roots = Roots {
            config_home: None,
            data_home: None,
            ..scratch.roots(&[])
        };
        assert_eq!(
            registered_command(&roots, "gateinto").as_deref(),
            Some("ours")
        );
    }

    #[test]
    fn only_exec_in_the_desktop_entry_group_is_read() {
        let scratch = Scratch::new();
        scratch.default("config/mimeapps.list", "gateinto.desktop");
        scratch.write(
            "data/applications/gateinto.desktop",
            "# Exec=comment\n[Desktop Entry]\nExec[de]=localized\nTryExec=try\n\
             Exec = ours \n[Desktop Action new]\nExec=action\n",
        );
        assert_eq!(lookup(&scratch).as_deref(), Some("ours"));
    }

    #[test]
    fn an_installed_default_without_exec_has_no_command() {
        let scratch = Scratch::new();
        scratch.default("config/mimeapps.list", "gateinto.desktop");
        scratch.default("etc1/mimeapps.list", "other.desktop");
        scratch.write(
            "data/applications/gateinto.desktop",
            "[Desktop Entry]\nType=Application\n[Desktop Action new]\nExec=action\n",
        );
        scratch.install("data", "other.desktop", "other");
        assert_eq!(lookup(&scratch), None);
    }

    #[test]
    fn unreadable_list_files_and_ids_are_skipped() {
        let scratch = Scratch::new();
        std::fs::create_dir_all(scratch.0.join("config/mimeapps.list")).unwrap();
        std::fs::create_dir_all(scratch.0.join("etc1")).unwrap();
        std::fs::write(scratch.0.join("etc1/mimeapps.list"), b"\xff\xfe").unwrap();
        scratch.default("etc2/mimeapps.list", "dir.desktop;gateinto.desktop");
        std::fs::create_dir_all(scratch.0.join("data/applications/dir.desktop")).unwrap();
        scratch.install("data", "gateinto.desktop", "ours");
        assert_eq!(lookup(&scratch).as_deref(), Some("ours"));
    }

    fn mkfifo(path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    }

    #[test]
    fn an_unreadable_desktop_file_falls_through_to_the_same_id_in_later_data_dirs() {
        let scratch = Scratch::new();
        scratch.default("config/mimeapps.list", "gateinto.desktop");
        std::fs::create_dir_all(scratch.0.join("data/applications/gateinto.desktop")).unwrap();
        std::fs::create_dir_all(scratch.0.join("share1/applications")).unwrap();
        std::fs::write(
            scratch.0.join("share1/applications/gateinto.desktop"),
            b"\xff\xfe",
        )
        .unwrap();
        scratch.install("share2", "gateinto.desktop", "share2");
        assert_eq!(lookup(&scratch).as_deref(), Some("share2"));
    }

    #[test]
    fn fifos_are_skipped_without_blocking() {
        let scratch = Scratch::new();
        mkfifo(&scratch.0.join("config/mimeapps.list"));
        scratch.default("etc1/mimeapps.list", "gateinto.desktop");
        mkfifo(&scratch.0.join("data/applications/gateinto.desktop"));
        scratch.install("share1", "gateinto.desktop", "share1");
        assert_eq!(lookup(&scratch).as_deref(), Some("share1"));
    }

    #[test]
    fn oversized_files_are_skipped() {
        let scratch = Scratch::new();
        let padding = "#".repeat(MAX_FILE_SIZE as usize);
        scratch.write(
            "config/mimeapps.list",
            &format!("[Default Applications]\nx-scheme-handler/gateinto=big.desktop\n{padding}"),
        );
        scratch.default("etc1/mimeapps.list", "gateinto.desktop");
        scratch.install("data", "big.desktop", "big");
        scratch.write(
            "data/applications/gateinto.desktop",
            &format!("[Desktop Entry]\nExec=big\n{padding}"),
        );
        scratch.install("share1", "gateinto.desktop", "share1");
        assert_eq!(lookup(&scratch).as_deref(), Some("share1"));
    }

    #[test]
    fn device_files_behind_symlinks_are_skipped() {
        let scratch = Scratch::new();
        std::fs::create_dir_all(scratch.0.join("config")).unwrap();
        std::os::unix::fs::symlink("/dev/zero", scratch.0.join("config/mimeapps.list")).unwrap();
        scratch.default("etc1/mimeapps.list", "gateinto.desktop");
        std::fs::create_dir_all(scratch.0.join("data/applications")).unwrap();
        std::os::unix::fs::symlink(
            "/dev/zero",
            scratch.0.join("data/applications/gateinto.desktop"),
        )
        .unwrap();
        scratch.install("share1", "gateinto.desktop", "share1");
        assert_eq!(lookup(&scratch).as_deref(), Some("share1"));
    }

    #[test]
    fn a_file_of_exactly_the_size_limit_is_read() {
        let scratch = Scratch::new();
        let entry = "[Desktop Entry]\nExec=ours\n";
        scratch.default("config/mimeapps.list", "gateinto.desktop");
        scratch.write(
            "data/applications/gateinto.desktop",
            &format!(
                "{entry}{}",
                "#".repeat(MAX_FILE_SIZE as usize - entry.len())
            ),
        );
        assert_eq!(lookup(&scratch).as_deref(), Some("ours"));
    }

    #[test]
    fn ids_that_could_leave_the_applications_directory_are_rejected() {
        let scratch = Scratch::new();
        scratch.write("data/escaped.desktop", "[Desktop Entry]\nExec=escaped\n");
        scratch.write(
            "data/applications/sub/x.desktop",
            "[Desktop Entry]\nExec=sub\n",
        );
        scratch.write(
            "data/applications/a\\b.desktop",
            "[Desktop Entry]\nExec=slash\n",
        );
        scratch.write("data/applications/plain", "[Desktop Entry]\nExec=plain\n");
        for ids in [
            "../escaped.desktop",
            "sub/x.desktop",
            "/etc/x.desktop",
            "a\\\\b.desktop",
            "plain",
            ".",
            "..",
        ] {
            scratch.default("config/mimeapps.list", ids);
            assert_eq!(lookup(&scratch), None, "{ids}");
        }
    }

    #[test]
    fn an_escaped_separator_does_not_split_an_id() {
        let scratch = Scratch::new();
        scratch.default("config/mimeapps.list", "a\\;b.desktop;gateinto.desktop");
        scratch.install("data", "b.desktop", "split");
        scratch.install("data", "gateinto.desktop", "ours");
        assert_eq!(lookup(&scratch).as_deref(), Some("ours"));
    }

    #[test]
    fn files_written_by_other_tools_are_understood() {
        let scratch = Scratch::new();
        scratch.write(
            "config/mimeapps.list",
            "\u{feff}[Default Applications]\r\nX-Scheme-Handler/gateinto = gateinto.desktop;\r\n",
        );
        scratch.write(
            "data/applications/gateinto.desktop",
            "\u{feff}[Desktop Entry]\r\nExec=ours\r\n",
        );
        assert_eq!(lookup(&scratch).as_deref(), Some("ours"));
    }

    #[test]
    fn ids_are_not_mapped_to_subdirectories() {
        let scratch = Scratch::new();
        scratch.default("config/mimeapps.list", "kde4-foo.desktop");
        scratch.write(
            "data/applications/kde4/foo.desktop",
            "[Desktop Entry]\nExec=foo\n",
        );
        assert_eq!(lookup(&scratch), None);
    }

    #[test]
    fn scratch_directories_are_removed() {
        let dir = Scratch::new().0.clone();
        assert!(!Path::new(&dir).exists());
    }
}
