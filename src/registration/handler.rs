use super::files::{self, Contents, FileError, Links, Mode};
use super::xdg::Roots;
use super::{
    Overridden, RegistrationError, is_handler_command, keyfile, lookup, mimeapps, validate_scheme,
};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub(crate) struct Target {
    pub(crate) home: Option<PathBuf>,
    pub(crate) roots: Roots,
}

impl Target {
    pub(crate) fn from_env(env: impl Fn(&str) -> Option<OsString>) -> Self {
        Self {
            home: env("HOME")
                .map(PathBuf::from)
                .filter(|home| home.is_absolute()),
            roots: Roots::from_env(env),
        }
    }
}

struct Places {
    config_anchor: PathBuf,
    list: PathBuf,
    data_anchor: PathBuf,
    entry: PathBuf,
}

impl Places {
    fn new(target: &Target, scheme: &str) -> Result<Self, RegistrationError> {
        let required = |root: &Option<PathBuf>, kind: &str, variable: &str| {
            root.clone().ok_or_else(|| {
                RegistrationError::File(format!(
                    "cannot find the per-user {kind} directory: set HOME or {variable} to an \
                     absolute path"
                ))
            })
        };
        let config = required(&target.roots.config_home, "config", "XDG_CONFIG_HOME")?;
        let data = required(&target.roots.data_home, "data", "XDG_DATA_HOME")?;
        let anchor = |root: &Path| match &target.home {
            Some(home) if root.starts_with(home) => home.clone(),
            _ => root.to_owned(),
        };
        Ok(Self {
            config_anchor: anchor(&config),
            list: config.join("mimeapps.list"),
            data_anchor: anchor(&data),
            entry: data.join("applications").join(mimeapps::desktop_id(scheme)),
        })
    }
}

pub(crate) fn register(
    target: &Target,
    scheme: &str,
    command: &str,
) -> Result<Option<Overridden>, RegistrationError> {
    register_with(target, scheme, command, files::write)
}

fn register_with(
    target: &Target,
    scheme: &str,
    command: &str,
    write: impl Fn(&Path, &Path, &[u8], Mode) -> Result<(), FileError>,
) -> Result<Option<Overridden>, RegistrationError> {
    validate_scheme(scheme)?;
    if !is_handler_command(command) {
        return Err(RegistrationError::NotAHandlerCommand(command.to_owned()));
    }
    let places = Places::new(target, scheme)?;
    files::check_anchor(&places.data_anchor).map_err(file)?;
    files::check_anchor(&places.config_anchor).map_err(file)?;
    let existed = read_entry(&places.entry, scheme)?.is_some();
    read_list(&places.list, scheme)?;
    let entry = entry(scheme, command);
    let roll_back = || {
        if !existed {
            remove_if_unchanged(&places.data_anchor, &places.entry, &entry);
        }
    };
    if let Err(error) = write(
        &places.data_anchor,
        &places.entry,
        entry.as_bytes(),
        Mode::Exactly(0o600),
    ) {
        roll_back();
        return Err(file(error));
    }
    if let Err((error, published)) = set_default(&places, scheme, &write) {
        if !published {
            roll_back();
        }
        return Err(error);
    }
    Ok(overridden(target, &places, scheme))
}

fn set_default(
    places: &Places,
    scheme: &str,
    write: impl Fn(&Path, &Path, &[u8], Mode) -> Result<(), FileError>,
) -> Result<(), (RegistrationError, bool)> {
    let text = read_list(&places.list, scheme).map_err(|error| (error, false))?;
    let updated = mimeapps::with_handler(text.as_deref().unwrap_or_default(), scheme);
    if text.as_deref() == Some(updated.as_str()) {
        return Ok(());
    }
    write(
        &places.config_anchor,
        &places.list,
        updated.as_bytes(),
        Mode::KeepOr(0o644),
    )
    .map_err(|error| {
        let published = matches!(error, FileError::Unsynced(..));
        (file(error), published)
    })
}

pub(crate) fn unregister(target: &Target, scheme: &str) -> Result<bool, RegistrationError> {
    validate_scheme(scheme)?;
    let places = Places::new(target, scheme)?;
    let entry = read_entry(&places.entry, scheme)?;
    let list = read_list(&places.list, scheme)?;
    let mut removed = false;
    if let Some(text) = list
        && !mimeapps::listed_ids(&text, scheme).is_empty()
        && let Some(updated) = mimeapps::without_handler(&text, scheme)
    {
        files::write(
            &places.config_anchor,
            &places.list,
            updated.as_bytes(),
            Mode::KeepOr(0o644),
        )
        .map_err(file)?;
        removed = true;
    }
    if entry.is_some() {
        removed |= files::remove(&places.data_anchor, &places.entry).map_err(file)?;
    }
    Ok(removed)
}

fn entry(scheme: &str, command: &str) -> String {
    format!(
        "[Desktop Entry]\nType=Application\nName=Gateinto\nExec={command}\nNoDisplay=true\n\
         MimeType=x-scheme-handler/{scheme};\nX-Gateinto-Handler=1\n"
    )
}

fn is_ours(text: &str, scheme: &str) -> bool {
    let values = |name: &str| -> Vec<&str> {
        keyfile::values(text, "Desktop Entry", |key| key == name).collect()
    };
    values("X-Gateinto-Handler") == ["1"]
        && values("MimeType") == [format!("x-scheme-handler/{scheme};")]
        && matches!(values("Exec")[..], [exec] if is_handler_command(exec))
}

fn read_entry(path: &Path, scheme: &str) -> Result<Option<String>, RegistrationError> {
    match read(path)? {
        Some(text) if !is_ours(&text, scheme) => Err(RegistrationError::ForeignHandler {
            scheme: scheme.to_owned(),
            command: lookup::exec(&text).map(str::to_owned),
        }),
        text => Ok(text),
    }
}

fn read_list(path: &Path, scheme: &str) -> Result<Option<String>, RegistrationError> {
    let text = read(path)?;
    if let Some(text) = &text {
        let ours = mimeapps::desktop_id(scheme);
        let ids = mimeapps::listed_ids(text, scheme);
        if ids.iter().any(|id| *id != ours) {
            return Err(RegistrationError::ForeignDefault {
                scheme: scheme.to_owned(),
                list: path.to_owned(),
                ids: ids.into_iter().map(str::to_owned).collect(),
            });
        }
    }
    Ok(text)
}

fn read(path: &Path) -> Result<Option<String>, RegistrationError> {
    match files::read(path, Links::Refuse).map_err(file)? {
        Contents::Missing => Ok(None),
        Contents::Text(text) => Ok(Some(text)),
        Contents::Refused(refusal) => Err(file(refusal.error(path))),
    }
}

fn remove_if_unchanged(anchor: &Path, path: &Path, written: &str) {
    if let Ok(Contents::Text(text)) = files::read(path, Links::Refuse)
        && text == written
    {
        let _ = files::remove(anchor, path);
    }
}

fn overridden(target: &Target, places: &Places, scheme: &str) -> Option<Overridden> {
    match lookup::effective_default(&target.roots, scheme) {
        Some(found) if found.entry == places.entry && is_ours(&found.text, scheme) => None,
        found => Some(Overridden {
            scheme: scheme.to_owned(),
            by: found.map(|found| (found.id, found.list)),
        }),
    }
}

pub(crate) fn check_owner(target: &Target, scheme: &str) -> Result<(), RegistrationError> {
    let Ok(places) = Places::new(target, scheme) else {
        return Ok(());
    };
    for anchor in [&places.data_anchor, &places.config_anchor] {
        if let Err(error @ FileError::ForeignDirectory { .. }) = files::check_anchor(anchor) {
            return Err(RegistrationError::File(format!(
                "{error}; Gateinto registers its {scheme}:// handler only for the user who owns \
                 the per-user directories, so run it as that user, not through sudo or su"
            )));
        }
    }
    Ok(())
}

pub(crate) fn installed_override(target: &Target, scheme: &str) -> Option<Overridden> {
    let places = Places::new(target, scheme).ok()?;
    read_entry(&places.entry, scheme).ok()??;
    overridden(target, &places, scheme)
}

fn file(error: FileError) -> RegistrationError {
    RegistrationError::File(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registration::files::{MAX_FILE_SIZE, euid};
    use crate::registration::lookup;
    use crate::registration::testing::{foreign_dir, mkfifo};
    use std::io;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU32, Ordering};

    const SCHEME: &str = "gateinto";
    const COMMAND: &str = "\"/opt/gateinto/gateinto\" open -- %u";
    const MOVED: &str = "\"/usr/local/bin/gateinto\" open --config \"/home/me/g.toml\" -- %u";
    const ENTRY: &str = "\
[Desktop Entry]
Type=Application
Name=Gateinto
Exec=\"/opt/gateinto/gateinto\" open -- %u
NoDisplay=true
MimeType=x-scheme-handler/gateinto;
X-Gateinto-Handler=1
";
    const DEFAULT: &str = "[Default Applications]\nx-scheme-handler/gateinto=gateinto.desktop\n";

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            static RUNS: AtomicU32 = AtomicU32::new(0);
            let dir = std::env::temp_dir().join(format!(
                "gateinto-handler-{}-{}",
                std::process::id(),
                RUNS.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join("home")).unwrap();
            Self(dir)
        }

        fn home(&self) -> PathBuf {
            self.0.join("home")
        }

        fn target(&self, desktops: &[&str]) -> Target {
            let home = self.home();
            Target {
                roots: Roots {
                    config_home: Some(home.join(".config")),
                    config_dirs: vec![self.0.join("etc")],
                    data_home: Some(home.join(".local/share")),
                    data_dirs: vec![self.0.join("share")],
                    desktops: desktops.iter().map(|name| (*name).to_owned()).collect(),
                },
                home: Some(home),
            }
        }

        fn list(&self) -> PathBuf {
            self.home().join(".config/mimeapps.list")
        }

        fn entry(&self) -> PathBuf {
            self.applications().join("gateinto.desktop")
        }

        fn applications(&self) -> PathBuf {
            self.home().join(".local/share/applications")
        }

        fn snapshot(&self) -> Vec<String> {
            fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
                let mut entries: Vec<_> = std::fs::read_dir(dir)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .collect();
                entries.sort();
                for path in entries {
                    let name = path.strip_prefix(base).unwrap().display().to_string();
                    let metadata = std::fs::symlink_metadata(&path).unwrap();
                    let mode = metadata.mode() & 0o7777;
                    if metadata.is_symlink() {
                        let target = std::fs::read_link(&path).unwrap();
                        out.push(format!("{name} -> {}", target.display()));
                    } else if metadata.is_dir() {
                        out.push(format!("{name}/ {mode:o}"));
                        if metadata.uid() == euid() {
                            walk(&path, base, out);
                        }
                    } else if metadata.is_file() {
                        let bytes = std::fs::read(&path).unwrap();
                        out.push(format!(
                            "{name} {mode:o} {:?}",
                            String::from_utf8_lossy(&bytes)
                        ));
                    } else {
                        out.push(format!("{name} special"));
                    }
                }
            }
            let mut out = Vec::new();
            walk(&self.0, &self.0, &mut out);
            out
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn put(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn text(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap()
    }

    fn mode(path: &Path) -> u32 {
        std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
    }

    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn default_line(value: &str) -> String {
        format!("[Default Applications]\nx-scheme-handler/gateinto={value}\n")
    }

    fn file_error(text: String) -> Result<Option<Overridden>, RegistrationError> {
        Err(RegistrationError::File(text))
    }

    #[test]
    fn registering_writes_the_desktop_file_and_the_default() {
        let scratch = Scratch::new();
        let target = scratch.target(&[]);
        assert_eq!(register(&target, SCHEME, COMMAND), Ok(None));
        assert_eq!(text(&scratch.entry()), ENTRY);
        assert_eq!(mode(&scratch.entry()), 0o600);
        assert_eq!(text(&scratch.list()), DEFAULT);
        assert_eq!(mode(&scratch.list()), 0o644);
        assert_eq!(
            lookup::registered_command(&target.roots, SCHEME).as_deref(),
            Some(COMMAND)
        );
    }

    #[test]
    fn each_scheme_gets_its_own_desktop_file_and_line() {
        let scratch = Scratch::new();
        let target = scratch.target(&[]);
        register(&target, "gateinto-test-1", COMMAND).unwrap();
        register(&target, SCHEME, COMMAND).unwrap();
        assert_eq!(
            text(&scratch.applications().join("gateinto-test-1.desktop")),
            ENTRY.replace(
                "x-scheme-handler/gateinto;",
                "x-scheme-handler/gateinto-test-1;"
            )
        );
        assert_eq!(
            text(&scratch.list()),
            "[Default Applications]\n\
             x-scheme-handler/gateinto-test-1=gateinto-test-1.desktop\n\
             x-scheme-handler/gateinto=gateinto.desktop\n"
        );
        assert_eq!(unregister(&target, "gateinto-test-1"), Ok(true));
        assert_eq!(text(&scratch.list()), DEFAULT);
        assert_eq!(text(&scratch.entry()), ENTRY);
        assert!(
            !scratch
                .applications()
                .join("gateinto-test-1.desktop")
                .exists()
        );
    }

    #[test]
    fn registering_again_is_idempotent_and_updates_the_command() {
        let scratch = Scratch::new();
        let target = scratch.target(&[]);
        register(&target, SCHEME, COMMAND).unwrap();
        let first = scratch.snapshot();
        assert_eq!(register(&target, SCHEME, COMMAND), Ok(None));
        assert_eq!(scratch.snapshot(), first);
        assert_eq!(register(&target, SCHEME, MOVED), Ok(None));
        assert_eq!(text(&scratch.entry()), ENTRY.replace(COMMAND, MOVED));
        assert_eq!(text(&scratch.list()), DEFAULT);
        assert_eq!(
            lookup::registered_command(&target.roots, SCHEME).as_deref(),
            Some(MOVED)
        );
    }

    #[test]
    fn unregistering_removes_the_line_and_the_desktop_file_once() {
        let scratch = Scratch::new();
        let target = scratch.target(&[]);
        register(&target, SCHEME, COMMAND).unwrap();
        assert_eq!(unregister(&target, SCHEME), Ok(true));
        assert!(!scratch.entry().exists());
        assert_eq!(text(&scratch.list()), "[Default Applications]\n");
        let after = scratch.snapshot();
        assert_eq!(unregister(&target, SCHEME), Ok(false));
        assert_eq!(scratch.snapshot(), after);
        assert_eq!(lookup::registered_command(&target.roots, SCHEME), None);
    }

    #[test]
    fn unregistering_removes_whichever_half_is_left() {
        let scratch = Scratch::new();
        let target = scratch.target(&[]);
        register(&target, SCHEME, COMMAND).unwrap();
        std::fs::remove_file(scratch.entry()).unwrap();
        assert_eq!(unregister(&target, SCHEME), Ok(true));
        assert_eq!(text(&scratch.list()), "[Default Applications]\n");

        register(&target, SCHEME, COMMAND).unwrap();
        std::fs::write(scratch.list(), "").unwrap();
        assert_eq!(unregister(&target, SCHEME), Ok(true));
        assert!(!scratch.entry().exists());
        assert_eq!(text(&scratch.list()), "");
    }

    #[test]
    fn unregistering_without_a_handler_creates_nothing() {
        let scratch = Scratch::new();
        let before = scratch.snapshot();
        assert_eq!(unregister(&scratch.target(&[]), SCHEME), Ok(false));
        assert_eq!(scratch.snapshot(), before);
    }

    #[test]
    fn a_line_without_ids_is_replaced_but_not_removed() {
        let scratch = Scratch::new();
        let target = scratch.target(&[]);
        put(&scratch.list(), &default_line(""));
        assert_eq!(unregister(&target, SCHEME), Ok(false));
        assert_eq!(text(&scratch.list()), default_line(""));
        register(&target, SCHEME, COMMAND).unwrap();
        assert_eq!(text(&scratch.list()), DEFAULT);
    }

    #[test]
    fn a_foreign_desktop_file_is_neither_replaced_nor_removed() {
        let without = |line: &str| ENTRY.replace(&format!("{line}\n"), "");
        for (entry, command) in [
            (
                "[Desktop Entry]\nExec=other %u\nMimeType=x-scheme-handler/gateinto;\n\
                 X-Gateinto-Handler=1\n"
                    .to_owned(),
                Some("other %u"),
            ),
            (without("X-Gateinto-Handler=1"), Some(COMMAND)),
            (
                ENTRY.replace("X-Gateinto-Handler=1", "X-Gateinto-Handler=0"),
                Some(COMMAND),
            ),
            (
                ENTRY.replace("handler/gateinto;", "handler/gateinto-test;"),
                Some(COMMAND),
            ),
            (
                ENTRY.replace("handler/gateinto;", "handler/gateinto;text/html;"),
                Some(COMMAND),
            ),
            (format!("{ENTRY}X-Gateinto-Handler=1\n"), Some(COMMAND)),
            (format!("{ENTRY}Exec=other\n"), Some("other")),
            (
                format!(
                    "{}[Desktop Action x]\nX-Gateinto-Handler=1\n",
                    without("X-Gateinto-Handler=1")
                ),
                Some(COMMAND),
            ),
            (without(&format!("Exec={COMMAND}")), None),
        ] {
            let scratch = Scratch::new();
            let target = scratch.target(&[]);
            put(&scratch.entry(), &entry);
            put(&scratch.list(), DEFAULT);
            let before = scratch.snapshot();
            let foreign = Err(RegistrationError::ForeignHandler {
                scheme: SCHEME.to_owned(),
                command: command.map(str::to_owned),
            });
            assert_eq!(
                register(&target, SCHEME, COMMAND),
                foreign.clone(),
                "{entry}"
            );
            assert_eq!(
                unregister(&target, SCHEME),
                foreign.map(|_| false),
                "{entry}"
            );
            assert_eq!(scratch.snapshot(), before, "{entry}");
        }
    }

    #[test]
    fn a_foreign_default_is_neither_replaced_nor_removed() {
        for (list, ids) in [
            (default_line("other.desktop"), &["other.desktop"][..]),
            (
                default_line("other.desktop;gateinto.desktop;"),
                &["other.desktop", "gateinto.desktop"][..],
            ),
            (
                default_line("gateinto.desktop;other.desktop"),
                &["gateinto.desktop", "other.desktop"][..],
            ),
            (
                default_line("a\\;gateinto.desktop"),
                &["a\\;gateinto.desktop"][..],
            ),
            (
                default_line("gateinto\\s.desktop"),
                &["gateinto\\s.desktop"][..],
            ),
            (
                format!(
                    "{}x-scheme-handler/gateinto=gateinto.desktop\n",
                    default_line("other.desktop")
                ),
                &["other.desktop", "gateinto.desktop"][..],
            ),
        ] {
            for ours in [false, true] {
                let scratch = Scratch::new();
                let target = scratch.target(&[]);
                put(&scratch.list(), &list);
                if ours {
                    put(&scratch.entry(), ENTRY);
                }
                let before = scratch.snapshot();
                let foreign = Err(RegistrationError::ForeignDefault {
                    scheme: SCHEME.to_owned(),
                    list: scratch.list(),
                    ids: ids.iter().map(|id| (*id).to_owned()).collect(),
                });
                assert_eq!(
                    register(&target, SCHEME, COMMAND),
                    foreign.clone(),
                    "{list}"
                );
                assert_eq!(
                    unregister(&target, SCHEME),
                    foreign.map(|_| false),
                    "{list}"
                );
                assert_eq!(scratch.snapshot(), before, "{list}");
            }
        }
    }

    #[test]
    fn a_round_trip_keeps_unrelated_content_byte_for_byte() {
        let scratch = Scratch::new();
        let target = scratch.target(&[]);
        let original = "\u{feff}# kept as written\r\n\
                        [Added Associations]\r\n\
                        x-scheme-handler/gateinto=added.desktop;\r\n\
                        \r\n\
                        [Default Applications]\r\n\
                        text/html = firefox.desktop\r\n\
                        \x20 # indented comment\r\n\
                        x-scheme-handler/https=firefox.desktop;\r\n\
                        [Removed Associations]\r\n\
                        x-scheme-handler/gateinto=removed.desktop";
        put(&scratch.list(), original);
        chmod(&scratch.list(), 0o640);
        register(&target, SCHEME, COMMAND).unwrap();
        assert_eq!(
            text(&scratch.list()),
            original.replace(
                "x-scheme-handler/https=firefox.desktop;\r\n",
                "x-scheme-handler/https=firefox.desktop;\r\n\
                 x-scheme-handler/gateinto=gateinto.desktop\r\n"
            )
        );
        assert_eq!(mode(&scratch.list()), 0o640);
        assert_eq!(unregister(&target, SCHEME), Ok(true));
        assert_eq!(std::fs::read(scratch.list()).unwrap(), original.as_bytes());
        assert_eq!(mode(&scratch.list()), 0o640);
    }

    #[test]
    fn a_desktop_specific_default_is_reported_after_registering() {
        let scratch = Scratch::new();
        let kde = scratch.home().join(".config/kde-mimeapps.list");
        put(&kde, &default_line("other.desktop"));
        put(
            &scratch.applications().join("other.desktop"),
            "[Desktop Entry]\nExec=other %u\n",
        );
        let overridden = register(&scratch.target(&["kde"]), SCHEME, COMMAND).unwrap();
        assert_eq!(
            overridden,
            Some(Overridden {
                scheme: SCHEME.to_owned(),
                by: Some(("other.desktop".to_owned(), kde.clone())),
            })
        );
        assert_eq!(
            overridden.unwrap().to_string(),
            format!(
                "{} sets \"other.desktop\" as the default for x-scheme-handler/gateinto, so \
                 gateinto:// links may open that application instead of Gateinto",
                kde.display()
            )
        );
        assert_eq!(text(&scratch.entry()), ENTRY);
        assert_eq!(text(&scratch.list()), DEFAULT);
        assert_eq!(
            register(&scratch.target(&["gnome"]), SCHEME, COMMAND),
            Ok(None)
        );
    }

    #[test]
    fn an_overriding_default_is_reported_even_when_hidden_or_without_exec() {
        for entry in [
            "[Desktop Entry]\nHidden=true\nExec=other %u\n",
            "[Desktop Entry]\nDBusActivatable=true\n",
        ] {
            let scratch = Scratch::new();
            let kde = scratch.home().join(".config/kde-mimeapps.list");
            put(&kde, &default_line("other.desktop"));
            put(&scratch.applications().join("other.desktop"), entry);
            assert_eq!(
                register(&scratch.target(&["kde"]), SCHEME, COMMAND),
                Ok(Some(Overridden {
                    scheme: SCHEME.to_owned(),
                    by: Some(("other.desktop".to_owned(), kde)),
                })),
                "{entry}"
            );
        }
    }

    #[test]
    fn an_uninstalled_desktop_specific_default_is_not_reported() {
        let scratch = Scratch::new();
        put(
            &scratch.home().join(".config/kde-mimeapps.list"),
            &default_line("missing.desktop"),
        );
        assert_eq!(
            register(&scratch.target(&["kde"]), SCHEME, COMMAND),
            Ok(None)
        );
    }

    #[test]
    fn a_default_that_cannot_be_confirmed_is_reported() {
        let scratch = Scratch::new();
        let overridden = register_with(
            &scratch.target(&[]),
            SCHEME,
            COMMAND,
            |anchor, path, bytes, mode| {
                if path.ends_with("mimeapps.list") {
                    files::write(anchor, path, bytes, mode)
                } else {
                    Ok(())
                }
            },
        )
        .unwrap();
        assert_eq!(
            overridden,
            Some(Overridden {
                scheme: SCHEME.to_owned(),
                by: None,
            })
        );
        assert_eq!(
            overridden.unwrap().to_string(),
            "no installed default for x-scheme-handler/gateinto was found that is the Gateinto \
             desktop file, so gateinto:// links may open another application or none"
        );
    }

    #[test]
    fn a_symlinked_list_is_refused_and_its_destination_kept() {
        let scratch = Scratch::new();
        let target = scratch.target(&[]);
        let destination = scratch.0.join("dotfiles/mimeapps.list");
        put(&destination, DEFAULT);
        std::fs::create_dir_all(scratch.list().parent().unwrap()).unwrap();
        symlink(&destination, scratch.list()).unwrap();
        put(&scratch.entry(), ENTRY);
        let before = scratch.snapshot();
        let refused = format!(
            "{} is a symbolic link; refusing to follow it",
            scratch.list().display()
        );
        assert_eq!(
            register(&target, SCHEME, COMMAND),
            file_error(refused.clone())
        );
        assert_eq!(
            unregister(&target, SCHEME),
            Err(RegistrationError::File(refused))
        );
        assert_eq!(scratch.snapshot(), before);
    }

    #[test]
    fn files_that_cannot_be_read_safely_are_refused_and_kept() {
        type Make = fn(&Path, &Scratch);
        let cases: [(Make, &str); 5] = [
            (
                |path, scratch| {
                    put(&scratch.0.join("elsewhere"), ENTRY);
                    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                    symlink(scratch.0.join("elsewhere"), path).unwrap();
                },
                "is a symbolic link; refusing to follow it",
            ),
            (|path, _| mkfifo(path), "is not a regular file"),
            (
                |path, _| std::fs::create_dir_all(path).unwrap(),
                "is not a regular file",
            ),
            (
                |path, _| put(path, &"#".repeat(MAX_FILE_SIZE as usize + 1)),
                "is larger than 1 MiB",
            ),
            (
                |path, _| {
                    put(path, "");
                    std::fs::write(path, b"\xff\xfe").unwrap();
                },
                "is not valid UTF-8",
            ),
        ];
        for (make, reason) in cases {
            for list in [false, true] {
                let scratch = Scratch::new();
                let target = scratch.target(&[]);
                let path = if list {
                    scratch.list()
                } else {
                    scratch.entry()
                };
                make(&path, &scratch);
                let before = scratch.snapshot();
                let refused = format!("{} {reason}", path.display());
                assert_eq!(
                    register(&target, SCHEME, COMMAND),
                    file_error(refused.clone())
                );
                assert_eq!(
                    unregister(&target, SCHEME),
                    Err(RegistrationError::File(refused))
                );
                assert_eq!(scratch.snapshot(), before, "{reason}");
            }
        }
    }

    #[test]
    fn an_anchor_owned_by_another_user_is_refused_before_writing() {
        let scratch = Scratch::new();
        let home = foreign_dir(&scratch.0);
        let unique =
            |name: &str| home.join(format!("gateinto-handler-{}-{name}", std::process::id()));
        let target = Target {
            home: Some(home.clone()),
            roots: Roots {
                config_home: Some(unique("config")),
                data_home: Some(unique("data")),
                ..scratch.target(&[]).roots
            },
        };
        let uid = std::fs::metadata(&home).unwrap().uid();
        assert_eq!(
            register(&target, SCHEME, COMMAND),
            file_error(format!(
                "directory {} is owned by uid {uid}, not by the current user",
                home.display()
            ))
        );
        assert!(!unique("config").exists());
        assert!(!unique("data").exists());
    }

    #[test]
    fn only_an_anchor_of_another_user_fails_the_owner_check() {
        let scratch = Scratch::new();
        assert_eq!(check_owner(&scratch.target(&[]), SCHEME), Ok(()));
        let unset = Target {
            home: None,
            roots: Roots {
                config_home: None,
                data_home: None,
                ..scratch.target(&[]).roots
            },
        };
        assert_eq!(check_owner(&unset, SCHEME), Ok(()));
        let absent = scratch.0.join("absent");
        let missing = Target {
            home: Some(absent.clone()),
            roots: Roots {
                config_home: Some(absent.join(".config")),
                data_home: Some(absent.join(".local/share")),
                ..scratch.target(&[]).roots
            },
        };
        assert_eq!(check_owner(&missing, SCHEME), Ok(()));
        assert!(!absent.exists());

        let home = foreign_dir(&scratch.0);
        let uid = std::fs::metadata(&home).unwrap().uid();
        let refused = Err(RegistrationError::File(format!(
            "directory {} is owned by uid {uid}, not by the current user; Gateinto registers \
             its gateinto:// handler only for the user who owns the per-user directories, so \
             run it as that user, not through sudo or su",
            home.display()
        )));
        for (config, data) in [(true, false), (false, true)] {
            let root = |foreign: bool, name: &str| {
                if foreign {
                    home.clone()
                } else {
                    scratch.home().join(name)
                }
            };
            let target = Target {
                home: Some(scratch.home()),
                roots: Roots {
                    config_home: Some(root(config, ".config")),
                    data_home: Some(root(data, ".local/share")),
                    ..scratch.target(&[]).roots
                },
            };
            assert_eq!(check_owner(&target, SCHEME), refused, "{config} {data}");
        }
    }

    #[test]
    fn an_installed_handler_reports_a_default_that_overrides_it() {
        let scratch = Scratch::new();
        let target = scratch.target(&["kde"]);
        assert_eq!(installed_override(&target, SCHEME), None);
        assert_eq!(register(&target, SCHEME, COMMAND), Ok(None));
        assert_eq!(installed_override(&target, SCHEME), None);

        let kde = scratch.home().join(".config/kde-mimeapps.list");
        put(&kde, &default_line("other.desktop"));
        put(
            &scratch.applications().join("other.desktop"),
            "[Desktop Entry]\nExec=other %u\n",
        );
        assert_eq!(
            installed_override(&target, SCHEME),
            Some(Overridden {
                scheme: SCHEME.to_owned(),
                by: Some(("other.desktop".to_owned(), kde.clone())),
            })
        );

        std::fs::remove_file(&kde).unwrap();
        std::fs::remove_file(scratch.list()).unwrap();
        assert_eq!(
            installed_override(&target, SCHEME),
            Some(Overridden {
                scheme: SCHEME.to_owned(),
                by: None,
            })
        );

        put(&scratch.entry(), "[Desktop Entry]\nExec=other %u\n");
        assert_eq!(installed_override(&target, SCHEME), None);
    }

    #[test]
    fn a_failed_default_write_removes_a_desktop_file_it_created() {
        let scratch = Scratch::new();
        let link = scratch.home().join("cfg");
        symlink(foreign_dir(&scratch.0), &link).unwrap();
        let mut target = scratch.target(&[]);
        target.roots.config_home =
            Some(link.join(format!("gateinto-handler-{}-config", std::process::id())));
        let error = register(&target, SCHEME, COMMAND).unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with(&format!("directory {} is owned by", link.display())),
            "{error}"
        );
        assert!(!scratch.entry().exists());

        put(&scratch.entry(), &ENTRY.replace(COMMAND, MOVED));
        assert!(register(&target, SCHEME, COMMAND).is_err());
        assert!(scratch.entry().exists());
    }

    #[test]
    fn a_read_only_config_directory_rolls_back_the_desktop_file() {
        if euid() == 0 {
            return;
        }
        let scratch = Scratch::new();
        let config = scratch.home().join(".config");
        std::fs::create_dir(&config).unwrap();
        chmod(&config, 0o500);
        let result = register(&scratch.target(&[]), SCHEME, COMMAND);
        chmod(&config, 0o700);
        assert!(
            matches!(result, Err(RegistrationError::File(_))),
            "{result:?}"
        );
        assert!(!scratch.entry().exists());
        assert!(!scratch.list().exists());
    }

    fn unsynced(path: &Path) -> FileError {
        FileError::Unsynced(
            path.parent().unwrap().to_owned(),
            io::Error::other("injected"),
        )
    }

    #[test]
    fn a_failed_sync_after_the_default_was_published_keeps_both_files() {
        let scratch = Scratch::new();
        let result = register_with(
            &scratch.target(&[]),
            SCHEME,
            COMMAND,
            |anchor, path, bytes, mode| {
                files::write(anchor, path, bytes, mode)?;
                if path.ends_with("mimeapps.list") {
                    Err(unsynced(path))
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(result, file_error(unsynced(&scratch.list()).to_string()));
        assert_eq!(text(&scratch.entry()), ENTRY);
        assert_eq!(text(&scratch.list()), DEFAULT);
    }

    #[test]
    fn a_failed_desktop_file_write_writes_no_default_and_keeps_nothing() {
        for published in [false, true] {
            let scratch = Scratch::new();
            let result = register_with(
                &scratch.target(&[]),
                SCHEME,
                COMMAND,
                |anchor, path, bytes, mode| {
                    if published {
                        files::write(anchor, path, bytes, mode)?;
                    }
                    Err(unsynced(path))
                },
            );
            assert_eq!(result, file_error(unsynced(&scratch.entry()).to_string()));
            assert!(!scratch.entry().exists());
            assert!(!scratch.list().exists());
        }
    }

    #[test]
    fn the_list_is_read_again_just_before_it_is_written() {
        let scratch = Scratch::new();
        let list = scratch.list();
        let result = register_with(
            &scratch.target(&[]),
            SCHEME,
            COMMAND,
            |anchor, path, bytes, mode| {
                if !path.ends_with("mimeapps.list") {
                    put(&list, &default_line("other.desktop"));
                }
                files::write(anchor, path, bytes, mode)
            },
        );
        assert_eq!(
            result,
            Err(RegistrationError::ForeignDefault {
                scheme: SCHEME.to_owned(),
                list: scratch.list(),
                ids: vec!["other.desktop".to_owned()],
            })
        );
        assert!(!scratch.entry().exists());
        assert_eq!(text(&scratch.list()), default_line("other.desktop"));
    }

    fn from_env(vars: &[(&str, &Path)]) -> Target {
        Target::from_env(|name| {
            vars.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| OsString::from(value.as_os_str()))
        })
    }

    #[test]
    fn relative_xdg_values_are_ignored() {
        let scratch = Scratch::new();
        let home = scratch.home();
        let target = from_env(&[
            ("HOME", &home),
            ("XDG_CONFIG_HOME", Path::new("gateinto-relative-config")),
            ("XDG_DATA_HOME", Path::new("./gateinto-relative-data")),
        ]);
        assert_eq!(register(&target, SCHEME, COMMAND), Ok(None));
        assert_eq!(text(&scratch.entry()), ENTRY);
        assert_eq!(text(&scratch.list()), DEFAULT);
        assert!(!Path::new("gateinto-relative-config").exists());
        assert!(!Path::new("gateinto-relative-data").exists());
    }

    #[test]
    fn without_an_absolute_home_the_xdg_values_are_required() {
        for home in [None, Some(Path::new("home/me")), Some(Path::new(""))] {
            let mut vars = vec![("XDG_DATA_HOME", Path::new("/nonexistent/data"))];
            vars.extend(home.map(|home| ("HOME", home)));
            let target = from_env(&vars);
            let missing = "cannot find the per-user config directory: set HOME or \
                           XDG_CONFIG_HOME to an absolute path";
            assert_eq!(
                register(&target, SCHEME, COMMAND),
                file_error(missing.to_owned())
            );
            assert_eq!(
                unregister(&target, SCHEME),
                Err(RegistrationError::File(missing.to_owned()))
            );
        }
    }

    #[test]
    fn an_xdg_root_outside_home_is_its_own_anchor_and_must_exist() {
        let scratch = Scratch::new();
        let config = scratch.0.join("config");
        let data = scratch.0.join("data");
        std::fs::create_dir(&data).unwrap();
        let target = from_env(&[
            ("HOME", &scratch.home()),
            ("XDG_CONFIG_HOME", &config),
            ("XDG_DATA_HOME", &data),
        ]);
        let before = scratch.snapshot();
        assert_eq!(
            register(&target, SCHEME, COMMAND),
            file_error(format!("directory {} does not exist", config.display()))
        );
        assert_eq!(scratch.snapshot(), before);
        assert_eq!(unregister(&target, SCHEME), Ok(false));

        std::fs::create_dir(&config).unwrap();
        assert_eq!(register(&target, SCHEME, COMMAND), Ok(None));
        assert_eq!(text(&config.join("mimeapps.list")), DEFAULT);
        assert_eq!(text(&data.join("applications/gateinto.desktop")), ENTRY);
    }

    #[test]
    fn invalid_schemes_and_commands_are_refused_before_anything_is_written() {
        let scratch = Scratch::new();
        let target = scratch.target(&[]);
        let before = scratch.snapshot();
        let invalid = Err(RegistrationError::InvalidScheme("../x".to_owned()));
        assert_eq!(register(&target, "../x", COMMAND), invalid.clone());
        assert_eq!(unregister(&target, "../x"), invalid.map(|_| false));
        let other = "\"/opt/other/other\" open -- %u";
        assert_eq!(
            register(&target, SCHEME, other),
            Err(RegistrationError::NotAHandlerCommand(other.to_owned()))
        );
        assert_eq!(scratch.snapshot(), before);
    }
}
