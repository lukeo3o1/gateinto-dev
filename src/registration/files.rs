use std::ffi::OsString;
use std::fmt;
use std::fs::{DirBuilder, File, OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

pub(crate) const MAX_FILE_SIZE: u64 = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Links {
    Follow,
    Refuse,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Contents {
    Missing,
    Text(String),
    Refused(Refusal),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    Symlink,
    NotRegular,
    TooLarge,
    NotUtf8,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Exactly(u32),
    KeepOr(u32),
}

#[derive(Debug)]
pub(crate) enum FileError {
    Io(PathBuf, io::Error),
    Symlink(PathBuf),
    NotRegular(PathBuf),
    NotADirectory(PathBuf),
    ForeignDirectory { path: PathBuf, uid: u32 },
    OutsideAnchor { path: PathBuf, anchor: PathBuf },
}

impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(path, error) => write!(f, "{}: {error}", path.display()),
            Self::Symlink(path) => {
                write!(
                    f,
                    "{} is a symbolic link; refusing to follow it",
                    path.display()
                )
            }
            Self::NotRegular(path) => write!(f, "{} is not a regular file", path.display()),
            Self::NotADirectory(path) => write!(f, "{} is not a directory", path.display()),
            Self::ForeignDirectory { path, uid } => write!(
                f,
                "directory {} is owned by uid {uid}, not by the current user",
                path.display()
            ),
            Self::OutsideAnchor { path, anchor } => {
                write!(f, "{} is not inside {}", path.display(), anchor.display())
            }
        }
    }
}

impl std::error::Error for FileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(_, error) => Some(error),
            _ => None,
        }
    }
}

const TEMP_ATTEMPTS: u32 = 64;

pub(crate) fn read(path: &Path, links: Links) -> Result<Contents, FileError> {
    let mut options = OpenOptions::new();
    let flags = match links {
        Links::Follow => libc::O_NONBLOCK,
        Links::Refuse => libc::O_NONBLOCK | libc::O_NOFOLLOW,
    };
    options.read(true).custom_flags(flags);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Contents::Missing),
        Err(error) if links == Links::Refuse && error.raw_os_error() == Some(libc::ELOOP) => {
            return Ok(Contents::Refused(Refusal::Symlink));
        }
        Err(error) => return Err(FileError::Io(path.to_owned(), error)),
    };
    let io = |error| FileError::Io(path.to_owned(), error);
    if !file.metadata().map_err(io)?.is_file() {
        return Ok(Contents::Refused(Refusal::NotRegular));
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE_SIZE + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() as u64 > MAX_FILE_SIZE {
        return Ok(Contents::Refused(Refusal::TooLarge));
    }
    Ok(String::from_utf8(bytes).map_or(Contents::Refused(Refusal::NotUtf8), Contents::Text))
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn write(anchor: &Path, path: &Path, bytes: &[u8], mode: Mode) -> Result<(), FileError> {
    write_with(anchor, path, bytes, mode, |from, to| {
        std::fs::rename(from, to)
    })
}

fn write_with(
    anchor: &Path,
    path: &Path,
    bytes: &[u8],
    mode: Mode,
    rename: impl Fn(&Path, &Path) -> io::Result<()>,
) -> Result<(), FileError> {
    let dir = owned_dir(anchor, path, Missing::Create)?.ok_or_else(|| {
        FileError::Io(anchor.to_owned(), io::Error::from(io::ErrorKind::NotFound))
    })?;
    let io = |error| FileError::Io(path.to_owned(), error);
    let existing = regular_mode(path)?;
    let mode = match (mode, existing) {
        (Mode::Exactly(mode), _) | (Mode::KeepOr(mode), None) => mode,
        (Mode::KeepOr(_), Some(existing)) => existing & 0o777,
    };
    let (temp, mut file) = create_temp(path).map_err(io)?;
    let published = file
        .set_permissions(Permissions::from_mode(mode))
        .and_then(|()| file.write_all(bytes))
        .and_then(|()| file.sync_all())
        .and_then(|()| rename(&temp, path));
    if published.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    published.map_err(io)?;
    sync_dir(path, &dir)
}

fn create_temp(path: &Path) -> io::Result<(PathBuf, File)> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW);
    let mut attempt = 0;
    loop {
        let temp = temp_name(path, attempt);
        match options.open(&temp) {
            Err(error)
                if error.kind() == io::ErrorKind::AlreadyExists && attempt + 1 < TEMP_ATTEMPTS =>
            {
                attempt += 1;
            }
            opened => return opened.map(|file| (temp, file)),
        }
    }
}

fn temp_name(path: &Path, attempt: u32) -> PathBuf {
    let mut name = OsString::from(".");
    name.push(path.file_name().unwrap_or_default());
    name.push(format!(".{}.{attempt}.tmp", std::process::id()));
    path.with_file_name(name)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn remove(anchor: &Path, path: &Path) -> Result<bool, FileError> {
    let Some(dir) = owned_dir(anchor, path, Missing::Absent)? else {
        return Ok(false);
    };
    if regular_mode(path)?.is_none() {
        return Ok(false);
    }
    std::fs::remove_file(path).map_err(|error| FileError::Io(path.to_owned(), error))?;
    sync_dir(path, &dir)?;
    Ok(true)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Missing {
    Create,
    Absent,
}

fn owned_dir(anchor: &Path, path: &Path, missing: Missing) -> Result<Option<File>, FileError> {
    let outside = || FileError::OutsideAnchor {
        path: path.to_owned(),
        anchor: anchor.to_owned(),
    };
    let levels = path
        .parent()
        .filter(|_| path.file_name().is_some())
        .and_then(|dir| dir.strip_prefix(anchor).ok())
        .filter(|levels| {
            levels
                .components()
                .all(|level| matches!(level, Component::Normal(_)))
        })
        .ok_or_else(outside)?;
    let Some(mut dir) = open_owned_dir(anchor)? else {
        return Ok(None);
    };
    let mut current = anchor.to_owned();
    for level in levels {
        current.push(level);
        dir = match open_owned_dir(&current)? {
            Some(dir) => dir,
            None if missing == Missing::Create => {
                match DirBuilder::new().mode(0o700).create(&current) {
                    Err(error) if error.kind() != io::ErrorKind::AlreadyExists => {
                        return Err(FileError::Io(current, error));
                    }
                    _ => {}
                }
                open_owned_dir(&current)?.ok_or_else(|| {
                    FileError::Io(current.clone(), io::Error::from(io::ErrorKind::NotFound))
                })?
            }
            None => return Ok(None),
        };
    }
    Ok(Some(dir))
}

fn open_owned_dir(dir: &Path) -> Result<Option<File>, FileError> {
    let io = |error| FileError::Io(dir.to_owned(), error);
    let handle = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(dir)
    {
        Ok(handle) => handle,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) if error.raw_os_error() == Some(libc::ENOTDIR) => {
            return Err(FileError::NotADirectory(dir.to_owned()));
        }
        Err(error) => return Err(io(error)),
    };
    let uid = handle.metadata().map_err(io)?.uid();
    if uid != euid() {
        return Err(FileError::ForeignDirectory {
            path: dir.to_owned(),
            uid,
        });
    }
    Ok(Some(handle))
}

fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

fn regular_mode(path: &Path) -> Result<Option<u32>, FileError> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(FileError::Io(path.to_owned(), error)),
        Ok(metadata) if metadata.is_symlink() => Err(FileError::Symlink(path.to_owned())),
        Ok(metadata) if !metadata.is_file() => Err(FileError::NotRegular(path.to_owned())),
        Ok(metadata) => Ok(Some(metadata.mode())),
    }
}

fn sync_dir(path: &Path, dir: &File) -> Result<(), FileError> {
    dir.sync_all()
        .map_err(|error| FileError::Io(path.parent().unwrap_or(path).to_owned(), error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            static RUNS: AtomicU32 = AtomicU32::new(0);
            let dir = std::env::temp_dir().join(format!(
                "gateinto-files-{}-{}",
                std::process::id(),
                RUNS.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }

        fn names(&self, dir: &str) -> Vec<String> {
            let mut names: Vec<String> = std::fs::read_dir(self.path(dir))
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect();
            names.sort();
            names
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn mode(path: &Path) -> u32 {
        std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
    }

    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn unique(name: &str) -> String {
        format!("gateinto-files-{}-{name}", std::process::id())
    }

    // Root owns every directory it creates, so a foreign directory is made by handing a scratch
    // directory to nobody; any other user meets one in `/`.
    fn foreign_target(scratch: &Scratch) -> PathBuf {
        if euid() != 0 {
            return PathBuf::from("/");
        }
        let dir = scratch.path("foreign");
        std::fs::create_dir(&dir).unwrap();
        std::os::unix::fs::chown(&dir, Some(65534), Some(65534)).unwrap();
        dir
    }

    fn foreign_inside(scratch: &Scratch) -> PathBuf {
        let target = foreign_target(scratch);
        if target.starts_with(&scratch.0) {
            return target;
        }
        let link = scratch.path("foreign");
        symlink(&target, &link).unwrap();
        link
    }

    #[test]
    fn a_new_file_is_written_with_the_given_mode() {
        let scratch = Scratch::new();
        let path = scratch.path("gateinto.desktop");
        write(&scratch.0, &path, b"entry", Mode::Exactly(0o600)).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"entry");
        assert_eq!(mode(&path), 0o600);
        assert_eq!(scratch.names(""), ["gateinto.desktop"]);
    }

    #[test]
    fn a_new_file_gets_the_fallback_mode_when_keeping_the_mode() {
        let scratch = Scratch::new();
        let path = scratch.path("mimeapps.list");
        write(&scratch.0, &path, b"list", Mode::KeepOr(0o644)).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"list");
        assert_eq!(mode(&path), 0o644);
    }

    #[test]
    fn an_existing_file_is_replaced_with_the_given_mode() {
        let scratch = Scratch::new();
        let path = scratch.path("gateinto.desktop");
        std::fs::write(&path, b"old contents that are longer").unwrap();
        chmod(&path, 0o644);
        write(&scratch.0, &path, b"new", Mode::Exactly(0o600)).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert_eq!(mode(&path), 0o600);
        assert_eq!(scratch.names(""), ["gateinto.desktop"]);
    }

    #[test]
    fn an_existing_mode_is_kept_regardless_of_the_umask() {
        let scratch = Scratch::new();
        let path = scratch.path("mimeapps.list");
        std::fs::write(&path, b"old").unwrap();
        chmod(&path, 0o664);
        write(&scratch.0, &path, b"new", Mode::KeepOr(0o644)).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert_eq!(mode(&path), 0o664);
    }

    #[test]
    fn special_bits_of_an_existing_mode_are_dropped() {
        let scratch = Scratch::new();
        let path = scratch.path("mimeapps.list");
        std::fs::write(&path, b"old").unwrap();
        chmod(&path, 0o4755);
        write(&scratch.0, &path, b"new", Mode::KeepOr(0o644)).unwrap();
        assert_eq!(mode(&path), 0o755);
    }

    #[test]
    fn missing_directories_below_the_anchor_are_created_private() {
        let scratch = Scratch::new();
        let path = scratch.path("config/applications/gateinto.desktop");
        write(&scratch.0, &path, b"entry", Mode::Exactly(0o600)).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"entry");
        assert_eq!(mode(&scratch.path("config")), 0o700);
        assert_eq!(mode(&scratch.path("config/applications")), 0o700);
    }

    #[test]
    fn a_missing_anchor_is_not_created() {
        let scratch = Scratch::new();
        let anchor = scratch.path("home");
        let path = anchor.join("config/mimeapps.list");
        assert!(matches!(
            write(&anchor, &path, b"new", Mode::KeepOr(0o644)),
            Err(FileError::Io(missing, error))
                if missing == anchor && error.kind() == io::ErrorKind::NotFound
        ));
        assert!(scratch.names("").is_empty());
    }

    #[test]
    fn a_path_outside_the_anchor_is_refused() {
        let scratch = Scratch::new();
        let anchor = scratch.path("home");
        std::fs::create_dir(&anchor).unwrap();
        for path in [
            scratch.path("other/mimeapps.list"),
            scratch.path("home/../other/mimeapps.list"),
            scratch.path("mimeapps.list"),
        ] {
            assert!(matches!(
                write(&anchor, &path, b"new", Mode::KeepOr(0o644)),
                Err(FileError::OutsideAnchor { path: refused, .. }) if refused == path
            ));
            assert!(matches!(
                remove(&anchor, &path),
                Err(FileError::OutsideAnchor { .. })
            ));
        }
        assert_eq!(scratch.names(""), ["home"]);
    }

    #[test]
    fn an_anchor_owned_by_another_user_is_refused_before_creating_anything() {
        let scratch = Scratch::new();
        let anchor = foreign_target(&scratch);
        let level = anchor.join(unique("config"));
        let path = level.join("applications/gateinto.desktop");
        assert!(matches!(
            write(&anchor, &path, b"new", Mode::Exactly(0o600)),
            Err(FileError::ForeignDirectory { path: refused, uid })
                if refused == anchor && uid != euid()
        ));
        assert!(!level.exists());
    }

    #[test]
    fn a_level_owned_by_another_user_is_refused_before_creating_below_it() {
        let scratch = Scratch::new();
        let foreign = foreign_inside(&scratch);
        let level = foreign.join(unique("config"));
        let path = level.join("applications/gateinto.desktop");
        assert!(matches!(
            write(&scratch.0, &path, b"new", Mode::Exactly(0o600)),
            Err(FileError::ForeignDirectory { path: refused, .. }) if refused == foreign
        ));
        assert!(!level.exists());
    }

    #[test]
    fn a_symlinked_directory_owned_by_the_user_is_followed() {
        let scratch = Scratch::new();
        std::fs::create_dir(scratch.path("dotfiles")).unwrap();
        symlink(scratch.path("dotfiles"), scratch.path("config")).unwrap();
        let path = scratch.path("config/mimeapps.list");
        write(&scratch.0, &path, b"list", Mode::KeepOr(0o644)).unwrap();
        assert_eq!(
            std::fs::read(scratch.path("dotfiles/mimeapps.list")).unwrap(),
            b"list"
        );
        assert!(
            std::fs::symlink_metadata(scratch.path("config"))
                .unwrap()
                .is_symlink()
        );
        assert!(remove(&scratch.0, &path).unwrap());
        assert!(scratch.names("dotfiles").is_empty());
    }

    #[test]
    fn a_symlinked_directory_owned_by_another_user_is_refused() {
        let scratch = Scratch::new();
        let link = scratch.path("config");
        symlink(foreign_target(&scratch), &link).unwrap();
        let path = link.join(unique("mimeapps.list"));
        assert!(matches!(
            write(&scratch.0, &path, b"new", Mode::KeepOr(0o644)),
            Err(FileError::ForeignDirectory { path: refused, .. }) if refused == link
        ));
        assert!(!path.exists());
    }

    #[test]
    fn a_symlinked_target_is_refused_and_its_destination_kept() {
        let scratch = Scratch::new();
        let destination = scratch.path("elsewhere");
        std::fs::write(&destination, b"precious").unwrap();
        let path = scratch.path("mimeapps.list");
        symlink(&destination, &path).unwrap();
        assert!(matches!(
            write(&scratch.0, &path, b"new", Mode::KeepOr(0o644)),
            Err(FileError::Symlink(refused)) if refused == path
        ));
        assert_eq!(std::fs::read(&destination).unwrap(), b"precious");
        assert!(std::fs::symlink_metadata(&path).unwrap().is_symlink());
        assert_eq!(scratch.names(""), ["elsewhere", "mimeapps.list"]);
    }

    #[test]
    fn a_dangling_symlink_target_is_refused() {
        let scratch = Scratch::new();
        let path = scratch.path("gateinto.desktop");
        symlink(scratch.path("absent"), &path).unwrap();
        assert!(matches!(
            write(&scratch.0, &path, b"new", Mode::Exactly(0o600)),
            Err(FileError::Symlink(_))
        ));
        assert!(!scratch.path("absent").exists());
    }

    #[test]
    fn a_target_that_is_not_a_regular_file_is_refused() {
        let scratch = Scratch::new();
        let path = scratch.path("gateinto.desktop");
        std::fs::create_dir(&path).unwrap();
        assert!(matches!(
            write(&scratch.0, &path, b"new", Mode::Exactly(0o600)),
            Err(FileError::NotRegular(_))
        ));
        assert_eq!(scratch.names(""), ["gateinto.desktop"]);
    }

    #[test]
    fn a_level_that_is_not_a_directory_is_refused() {
        let scratch = Scratch::new();
        let file = scratch.path("file");
        std::fs::write(&file, b"").unwrap();
        let path = file.join("gateinto.desktop");
        assert!(matches!(
            write(&scratch.0, &path, b"new", Mode::Exactly(0o600)),
            Err(FileError::NotADirectory(refused)) if refused == file
        ));
        assert!(matches!(
            remove(&scratch.0, &path),
            Err(FileError::NotADirectory(refused)) if refused == file
        ));
        assert_eq!(scratch.names(""), ["file"]);
    }

    #[test]
    fn a_failed_publish_removes_the_temporary_file() {
        let scratch = Scratch::new();
        let path = scratch.path("mimeapps.list");
        std::fs::write(&path, b"old").unwrap();
        let failed = write_with(&scratch.0, &path, b"new", Mode::KeepOr(0o644), |_, _| {
            Err(io::Error::other("injected"))
        });
        assert!(matches!(failed, Err(FileError::Io(..))));
        assert_eq!(std::fs::read(&path).unwrap(), b"old");
        assert_eq!(scratch.names(""), ["mimeapps.list"]);
    }

    #[test]
    fn a_stale_temporary_name_is_skipped() {
        let scratch = Scratch::new();
        let path = scratch.path("gateinto.desktop");
        let names = [0, 1].map(|n| temp_name(&path, n));
        for name in &names {
            std::fs::write(name, b"stale").unwrap();
        }
        write(&scratch.0, &path, b"new", Mode::Exactly(0o600)).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        for name in &names {
            assert_eq!(std::fs::read(name).unwrap(), b"stale");
        }
    }

    #[test]
    fn removing_a_file_reports_whether_it_existed() {
        let scratch = Scratch::new();
        let path = scratch.path("gateinto.desktop");
        std::fs::write(&path, b"entry").unwrap();
        assert!(remove(&scratch.0, &path).unwrap());
        assert!(!path.exists());
        assert!(!remove(&scratch.0, &path).unwrap());
    }

    #[test]
    fn removing_never_creates_directories() {
        let scratch = Scratch::new();
        let path = scratch.path("config/applications/gateinto.desktop");
        assert!(!remove(&scratch.0, &path).unwrap());
        let anchor = scratch.path("home");
        assert!(!remove(&anchor, &anchor.join("gateinto.desktop")).unwrap());
        assert!(scratch.names("").is_empty());
    }

    #[test]
    fn removing_a_symlink_is_refused() {
        let scratch = Scratch::new();
        let destination = scratch.path("elsewhere");
        std::fs::write(&destination, b"precious").unwrap();
        let path = scratch.path("gateinto.desktop");
        symlink(&destination, &path).unwrap();
        assert!(matches!(
            remove(&scratch.0, &path),
            Err(FileError::Symlink(_))
        ));
        assert!(std::fs::symlink_metadata(&path).unwrap().is_symlink());
        assert_eq!(std::fs::read(&destination).unwrap(), b"precious");
    }

    #[test]
    fn removing_a_directory_is_refused() {
        let scratch = Scratch::new();
        let path = scratch.path("gateinto.desktop");
        std::fs::create_dir(&path).unwrap();
        assert!(matches!(
            remove(&scratch.0, &path),
            Err(FileError::NotRegular(_))
        ));
        assert!(path.is_dir());
    }

    #[test]
    fn removing_from_a_directory_owned_by_another_user_is_refused() {
        let scratch = Scratch::new();
        let dir = foreign_inside(&scratch);
        let path = dir.join(unique("gateinto.desktop"));
        if euid() == 0 {
            std::fs::write(&path, b"entry").unwrap();
        }
        assert!(matches!(
            remove(&scratch.0, &path),
            Err(FileError::ForeignDirectory { path: refused, .. }) if refused == dir
        ));
        assert_eq!(euid() == 0, path.exists());
    }

    #[test]
    fn removing_under_an_anchor_owned_by_another_user_is_refused() {
        let scratch = Scratch::new();
        let anchor = foreign_target(&scratch);
        let path = anchor.join(unique("gateinto.desktop"));
        assert!(matches!(
            remove(&anchor, &path),
            Err(FileError::ForeignDirectory { path: refused, .. }) if refused == anchor
        ));
    }

    #[test]
    fn reading_distinguishes_missing_text_and_refused_files() {
        let scratch = Scratch::new();
        let path = scratch.path("mimeapps.list");
        assert_eq!(read(&path, Links::Refuse).unwrap(), Contents::Missing);
        std::fs::write(&path, "[Default Applications]\n").unwrap();
        assert_eq!(
            read(&path, Links::Refuse).unwrap(),
            Contents::Text("[Default Applications]\n".to_owned())
        );
        std::fs::write(&path, b"\xff\xfe").unwrap();
        assert_eq!(
            read(&path, Links::Refuse).unwrap(),
            Contents::Refused(Refusal::NotUtf8)
        );
    }

    #[test]
    fn reading_refuses_files_over_the_size_limit() {
        let scratch = Scratch::new();
        let path = scratch.path("mimeapps.list");
        std::fs::write(&path, "#".repeat(MAX_FILE_SIZE as usize)).unwrap();
        assert!(matches!(
            read(&path, Links::Refuse).unwrap(),
            Contents::Text(_)
        ));
        std::fs::write(&path, "#".repeat(MAX_FILE_SIZE as usize + 1)).unwrap();
        assert_eq!(
            read(&path, Links::Refuse).unwrap(),
            Contents::Refused(Refusal::TooLarge)
        );
    }

    #[test]
    fn reading_refuses_symlinks_unless_asked_to_follow_them() {
        let scratch = Scratch::new();
        let destination = scratch.path("elsewhere");
        std::fs::write(&destination, "text").unwrap();
        let path = scratch.path("mimeapps.list");
        symlink(&destination, &path).unwrap();
        assert_eq!(
            read(&path, Links::Refuse).unwrap(),
            Contents::Refused(Refusal::Symlink)
        );
        assert_eq!(
            read(&path, Links::Follow).unwrap(),
            Contents::Text("text".to_owned())
        );
        let dangling = scratch.path("dangling");
        symlink(scratch.path("absent"), &dangling).unwrap();
        assert_eq!(
            read(&dangling, Links::Refuse).unwrap(),
            Contents::Refused(Refusal::Symlink)
        );
        assert_eq!(read(&dangling, Links::Follow).unwrap(), Contents::Missing);
    }

    #[test]
    fn reading_refuses_fifos_and_directories_without_blocking() {
        let scratch = Scratch::new();
        let fifo = scratch.path("fifo");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        assert_eq!(
            read(&fifo, Links::Refuse).unwrap(),
            Contents::Refused(Refusal::NotRegular)
        );
        assert_eq!(
            read(&scratch.0, Links::Refuse).unwrap(),
            Contents::Refused(Refusal::NotRegular)
        );
    }

    #[test]
    fn errors_name_the_path_but_never_the_contents() {
        let error = FileError::Symlink(PathBuf::from("/home/u/.config/mimeapps.list"));
        assert!(error.to_string().contains("/home/u/.config/mimeapps.list"));
        let error = FileError::ForeignDirectory {
            path: PathBuf::from("/home/u/.config"),
            uid: 0,
        };
        assert!(error.to_string().contains("/home/u/.config"));
        let error = FileError::OutsideAnchor {
            path: PathBuf::from("/etc/mimeapps.list"),
            anchor: PathBuf::from("/home/u"),
        };
        assert!(error.to_string().contains("/etc/mimeapps.list"));
        assert!(error.to_string().contains("/home/u"));
    }
}
