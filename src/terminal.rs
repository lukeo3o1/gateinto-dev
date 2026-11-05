use std::ffi::{OsStr, OsString};
use std::fmt;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};

use crate::config::ConfigFile;

const EQUALS: u16 = b'=' as u16;

pub const NO_PROXY_HOSTS: &str = "localhost,127.0.0.1,::1";

pub type Variables = Vec<(OsString, OsString)>;

pub fn terminal_environment(
    inherited: Variables,
    listen: SocketAddr,
) -> (Variables, Vec<OsString>) {
    let url = format!("http://{listen}");
    let values = [
        ("HTTPS_PROXY", url.as_str()),
        ("HTTP_PROXY", &url),
        ("ALL_PROXY", &url),
        ("NO_PROXY", NO_PROXY_HOSTS),
    ];
    let replaces = |name: &OsStr| {
        values
            .iter()
            .any(|(proxy, _)| name.eq_ignore_ascii_case(proxy))
    };
    let (replaced, mut vars): (Variables, Variables) =
        inherited.into_iter().partition(|(name, _)| replaces(name));
    for (name, value) in values {
        for spelling in [name.to_owned(), name.to_ascii_lowercase()] {
            vars.push((spelling.into(), value.into()));
        }
    }
    (vars, replaced.into_iter().map(|(name, _)| name).collect())
}

pub fn without_hidden_entries(inherited: Variables) -> Variables {
    inherited
        .into_iter()
        .filter(|(name, _)| !name.as_encoded_bytes().starts_with(b"="))
        .collect()
}

pub fn environment_block(vars: &[(OsString, OsString)]) -> Result<Vec<u16>, EnvironmentError> {
    let mut entries = vars
        .iter()
        .map(|(name, value)| wide_entry(name, value))
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_cached_key(|(name, _)| {
        let folded: Vec<u16> = name.iter().map(|&unit| uppercase(unit)).collect();
        (folded, name.clone())
    });
    let mut block = Vec::new();
    for (name, value) in entries {
        block.extend(name);
        block.push(EQUALS);
        block.extend(value);
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

fn wide_entry(name: &OsStr, value: &OsStr) -> Result<(Vec<u16>, Vec<u16>), EnvironmentError> {
    let error = |kind| EnvironmentError {
        name: name.to_owned(),
        kind,
    };
    let wide_name = wide(name).ok_or_else(|| error(EnvironmentErrorKind::NotUnicode))?;
    let wide_value = wide(value).ok_or_else(|| error(EnvironmentErrorKind::NotUnicode))?;
    if wide_name.is_empty() {
        return Err(error(EnvironmentErrorKind::EmptyName));
    }
    if wide_name.contains(&0) || wide_value.contains(&0) {
        return Err(error(EnvironmentErrorKind::Nul));
    }
    if wide_name[1..].contains(&EQUALS) {
        return Err(error(EnvironmentErrorKind::Equals));
    }
    Ok((wide_name, wide_value))
}

#[cfg(windows)]
fn wide(text: &OsStr) -> Option<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;
    Some(text.encode_wide().collect())
}

#[cfg(not(windows))]
fn wide(text: &OsStr) -> Option<Vec<u16>> {
    text.to_str().map(|text| text.encode_utf16().collect())
}

fn uppercase(unit: u16) -> u16 {
    char::from_u32(unit.into())
        .and_then(|c| {
            let mut upper = c.to_uppercase();
            match (upper.next(), upper.next()) {
                (Some(upper), None) => u16::try_from(u32::from(upper)).ok(),
                _ => None,
            }
        })
        .unwrap_or(unit)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentError {
    name: OsString,
    kind: EnvironmentErrorKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnvironmentErrorKind {
    EmptyName,
    Nul,
    Equals,
    NotUnicode,
}

impl fmt::Display for EnvironmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.name.to_string_lossy();
        match self.kind {
            EnvironmentErrorKind::EmptyName => {
                f.write_str("an environment variable has an empty name")
            }
            EnvironmentErrorKind::Nul => {
                write!(f, "environment variable {name:?} contains a NUL character")
            }
            EnvironmentErrorKind::Equals => {
                write!(f, "environment variable name {name:?} contains '='")
            }
            EnvironmentErrorKind::NotUnicode => {
                write!(f, "environment variable {name:?} is not valid Unicode")
            }
        }
    }
}

impl std::error::Error for EnvironmentError {}

pub trait Lookup {
    fn var(&self, name: &str) -> Option<OsString>;
    fn is_file(&self, path: &Path) -> bool;
    fn login_shell(&self) -> Option<PathBuf>;
}

pub struct System;

impl Lookup for System {
    fn var(&self, name: &str) -> Option<OsString> {
        std::env::var_os(name)
    }

    fn is_file(&self, path: &Path) -> bool {
        path.is_file()
    }

    #[cfg(unix)]
    fn login_shell(&self) -> Option<PathBuf> {
        use std::ffi::CStr;
        use std::os::unix::ffi::OsStrExt;
        let mut buffer = vec![0; 1024];
        loop {
            let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
            let mut found = std::ptr::null_mut();
            // SAFETY: entry and buffer outlive the call, and buffer.len() is its size in bytes.
            let status = unsafe {
                libc::getpwuid_r(
                    libc::getuid(),
                    entry.as_mut_ptr(),
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &mut found,
                )
            };
            if status == libc::ERANGE && buffer.len() < 1 << 20 {
                buffer.resize(buffer.len() * 2, 0);
                continue;
            }
            if status != 0 || found.is_null() {
                return None;
            }
            // SAFETY: on success found points to entry, whose strings point into buffer.
            let shell = unsafe { (*found).pw_shell };
            if shell.is_null() {
                return None;
            }
            // SAFETY: pw_shell is a NUL-terminated string in buffer, which is still alive.
            let shell = unsafe { CStr::from_ptr(shell) }.to_bytes();
            return (!shell.is_empty()).then(|| PathBuf::from(OsStr::from_bytes(shell)));
        }
    }

    #[cfg(not(unix))]
    fn login_shell(&self) -> Option<PathBuf> {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shell {
    pub executable: PathBuf,
    pub args: Vec<OsString>,
}

pub fn configured_shell(file: &ConfigFile, lookup: &impl Lookup) -> Result<Shell, ShellError> {
    let Some(shell) = &file.terminal.shell else {
        return default_shell(lookup).map(|executable| Shell {
            executable,
            args: Vec::new(),
        });
    };
    Ok(Shell {
        executable: resolve_shell(shell, file.dir().as_deref(), lookup)?,
        args: file.terminal.args.iter().map(OsString::from).collect(),
    })
}

pub fn default_shell(lookup: &impl Lookup) -> Result<PathBuf, ShellError> {
    if cfg!(windows) {
        windows_default_shell(lookup)
    } else {
        Ok(unix_default_shell(lookup))
    }
}

fn windows_default_shell(lookup: &impl Lookup) -> Result<PathBuf, ShellError> {
    lookup
        .var("ComSpec")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute() && lookup.is_file(path))
        .ok_or(ShellError::NoDefault)
}

fn unix_default_shell(lookup: &impl Lookup) -> PathBuf {
    [lookup.var("SHELL").map(PathBuf::from), lookup.login_shell()]
        .into_iter()
        .flatten()
        .find(|path| path.is_absolute() && lookup.is_file(path))
        .unwrap_or_else(|| PathBuf::from("/bin/sh"))
}

pub fn resolve_shell(
    value: &Path,
    base: Option<&Path>,
    lookup: &impl Lookup,
) -> Result<PathBuf, ShellError> {
    let existing = |path: PathBuf| {
        if lookup.is_file(&path) {
            Ok(path)
        } else {
            Err(ShellError::NotFound(path))
        }
    };
    if value.is_absolute() {
        return existing(value.to_owned());
    }
    if matches!(value.components().next(), Some(Component::Prefix(_))) && !value.has_root() {
        return Err(ShellError::DriveRelative(value.to_owned()));
    }
    if value.has_root() {
        return Err(ShellError::RootRelative(value.to_owned()));
    }
    let separated = value
        .as_os_str()
        .as_encoded_bytes()
        .iter()
        .any(|&byte| std::path::is_separator(byte.into()));
    if separated {
        return match base {
            Some(base) => existing(base.join(value)),
            None => Err(ShellError::NotFound(value.to_owned())),
        };
    }
    let extensions = lookup.var("PATHEXT").filter(|_| cfg!(windows));
    search_path(
        value.as_os_str(),
        lookup.var("PATH").as_deref(),
        extensions.as_deref(),
        |path| lookup.is_file(path),
    )
    .ok_or_else(|| ShellError::NotOnPath(value.to_owned()))
}

fn search_path(
    name: &OsStr,
    path: Option<&OsStr>,
    extensions: Option<&OsStr>,
    is_file: impl Fn(&Path) -> bool,
) -> Option<PathBuf> {
    let extensions = extensions.map(OsStr::to_string_lossy).unwrap_or_default();
    let names: Vec<OsString> = std::iter::once(name.to_owned())
        .chain(
            extensions
                .split(';')
                .filter(|extension| !extension.is_empty())
                .map(|extension| {
                    let mut candidate = name.to_owned();
                    candidate.push(extension);
                    candidate
                }),
        )
        .collect();
    std::env::split_paths(path?)
        .filter(|dir| dir.is_absolute())
        .flat_map(|dir| names.iter().map(move |name| dir.join(name)))
        .find(|candidate| is_file(candidate))
}

#[derive(Debug)]
pub enum ShellError {
    NotFound(PathBuf),
    NotOnPath(PathBuf),
    DriveRelative(PathBuf),
    RootRelative(PathBuf),
    NoDefault,
}

impl fmt::Display for ShellError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(path) => write!(f, "shell {} not found", path.display()),
            Self::NotOnPath(name) => write!(
                f,
                "shell {} was not found in the directories of PATH",
                name.display()
            ),
            Self::DriveRelative(path) => write!(
                f,
                "shell {} names a drive without a root directory; use an absolute path or a \
                 path without a drive",
                path.display()
            ),
            Self::RootRelative(path) => write!(
                f,
                "shell {} names a root directory without a drive; use an absolute path or a \
                 path without a root directory",
                path.display()
            ),
            Self::NoDefault => f.write_str(
                "the default shell %ComSpec% does not name an existing file by its absolute path; \
                 set shell in the [terminal] section",
            ),
        }
    }
}

impl std::error::Error for ShellError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn pairs(entries: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        entries
            .iter()
            .map(|(name, value)| (OsString::from(name), OsString::from(value)))
            .collect()
    }

    fn listen() -> SocketAddr {
        "127.0.0.1:49152".parse().unwrap()
    }

    const PROXY: &str = "http://127.0.0.1:49152";
    const LOOPBACK: &str = "localhost,127.0.0.1,::1";

    #[test]
    fn the_proxy_variables_are_set_in_both_spellings_once_each() {
        let (vars, replaced) = terminal_environment(pairs(&[("PATH", "/usr/bin")]), listen());
        assert_eq!(
            vars,
            pairs(&[
                ("PATH", "/usr/bin"),
                ("HTTPS_PROXY", PROXY),
                ("https_proxy", PROXY),
                ("HTTP_PROXY", PROXY),
                ("http_proxy", PROXY),
                ("ALL_PROXY", PROXY),
                ("all_proxy", PROXY),
                ("NO_PROXY", LOOPBACK),
                ("no_proxy", LOOPBACK),
            ])
        );
        assert!(replaced.is_empty(), "{replaced:?}");
    }

    #[test]
    fn inherited_proxy_variables_of_any_case_are_replaced_and_named_without_values() {
        let inherited = pairs(&[
            ("Https_Proxy", "http://user:secret@corp.example:8080"),
            ("GATEINTO_INSTANCE", "work"),
            ("http_proxy", "http://corp.example:8080"),
            ("ALL_PROXY", "socks5://corp.example:1080"),
            ("no_PROXY", ".corp.example"),
            ("NO_PROXY_EXTRA", "kept"),
            ("HTTPS_PROXY_URL", "kept"),
        ]);
        let (vars, replaced) = terminal_environment(inherited, listen());
        assert_eq!(
            replaced,
            ["Https_Proxy", "http_proxy", "ALL_PROXY", "no_PROXY"].map(OsString::from)
        );
        assert_eq!(
            vars,
            pairs(&[
                ("GATEINTO_INSTANCE", "work"),
                ("NO_PROXY_EXTRA", "kept"),
                ("HTTPS_PROXY_URL", "kept"),
                ("HTTPS_PROXY", PROXY),
                ("https_proxy", PROXY),
                ("HTTP_PROXY", PROXY),
                ("http_proxy", PROXY),
                ("ALL_PROXY", PROXY),
                ("all_proxy", PROXY),
                ("NO_PROXY", LOOPBACK),
                ("no_proxy", LOOPBACK),
            ])
        );
    }

    #[test]
    fn the_proxy_url_carries_the_listen_address_and_no_credential() {
        let listen: SocketAddr = "127.0.0.1:8".parse().unwrap();
        let (vars, _) = terminal_environment(Vec::new(), listen);
        let https = vars.iter().find(|(name, _)| name == "HTTPS_PROXY").unwrap();
        assert_eq!(https.1, "http://127.0.0.1:8");
        assert!(
            vars.iter()
                .all(|(_, value)| !value.to_string_lossy().contains('@')),
            "{vars:?}"
        );
    }

    #[test]
    fn hidden_entries_are_kept_in_process_and_dropped_for_the_agent() {
        let inherited = pairs(&[
            ("=C:", r"C:\work"),
            ("=D:", r"D:\"),
            ("Path", r"C:\Windows"),
            ("=ExitCode", "00000000"),
            ("=ExitCodeAscii", ""),
        ]);
        let (in_process, _) = terminal_environment(inherited.clone(), listen());
        assert_eq!(in_process[..5], inherited[..]);

        let agent = without_hidden_entries(inherited);
        assert_eq!(agent, pairs(&[("Path", r"C:\Windows")]));
    }

    fn block(entries: &[(&str, &str)]) -> Result<String, EnvironmentError> {
        environment_block(&pairs(entries)).map(|block| String::from_utf16(&block).unwrap())
    }

    #[test]
    fn a_block_ends_each_entry_with_a_nul_and_the_block_with_another() {
        assert_eq!(
            block(&[("A", "1"), ("B", ""), ("C", "x=y")]).unwrap(),
            "A=1\0B=\0C=x=y\0\0"
        );
        assert_eq!(block(&[]).unwrap(), "\0\0");
        assert_eq!(
            environment_block(&pairs(&[("Z", "\u{e9}\u{1f600}")])).unwrap(),
            [
                &[u16::from(b'Z'), u16::from(b'=')][..],
                &"\u{e9}\u{1f600}".encode_utf16().collect::<Vec<_>>(),
                &[0, 0]
            ]
            .concat()
        );
    }

    #[test]
    fn a_block_is_sorted_case_insensitively_by_folding_to_uppercase() {
        assert_eq!(
            block(&[
                ("no_proxy", "l"),
                ("NO_PROXY", "L"),
                ("Path", "p"),
                ("NODE_ENV", "dev"),
                ("AB", "2"),
                ("A_B", "3"),
                ("a", "1"),
            ])
            .unwrap(),
            "a=1\0AB=2\0A_B=3\0NODE_ENV=dev\0NO_PROXY=L\0no_proxy=l\0Path=p\0\0"
        );
    }

    #[test]
    fn hidden_entries_pass_through_a_block_unchanged() {
        assert_eq!(
            block(&[
                ("Path", "p"),
                ("=ExitCode", "00000000"),
                ("=C:", r"C:\work")
            ])
            .unwrap(),
            "=C:=C:\\work\0=ExitCode=00000000\0Path=p\0\0"
        );
    }

    #[test]
    fn a_block_refuses_invalid_names_and_values_without_showing_values() {
        for (entries, expected) in [
            (
                &[("", "x")][..],
                "an environment variable has an empty name",
            ),
            (
                &[("A\0B", "x")],
                "environment variable \"A\\0B\" contains a NUL character",
            ),
            (
                &[("SECRET", "a\0b")],
                "environment variable \"SECRET\" contains a NUL character",
            ),
            (
                &[("A=B", "x")],
                "environment variable name \"A=B\" contains '='",
            ),
            (
                &[("==", "x")],
                "environment variable name \"==\" contains '='",
            ),
        ] {
            let error = block(entries).unwrap_err().to_string();
            assert_eq!(error, expected, "{entries:?}");
            assert!(!error.contains("a\\0b"), "{error}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_block_refuses_names_and_values_that_are_not_unicode() {
        use std::os::unix::ffi::OsStringExt;
        let invalid = OsString::from_vec(vec![0xff]);
        let error = environment_block(&[(OsString::from("NAME"), invalid.clone())]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "environment variable \"NAME\" is not valid Unicode"
        );
        assert!(environment_block(&[(invalid, OsString::new())]).is_err());
    }

    #[derive(Default)]
    struct Fake {
        vars: Vec<(&'static str, OsString)>,
        files: Vec<PathBuf>,
        login: Option<PathBuf>,
    }

    impl Fake {
        fn path(mut self, dirs: &[&Path]) -> Self {
            self.vars
                .push(("PATH", std::env::join_paths(dirs).unwrap()));
            self
        }

        fn env(mut self, name: &'static str, value: &str) -> Self {
            self.vars.push((name, value.into()));
            self
        }

        fn file(mut self, path: impl Into<PathBuf>) -> Self {
            self.files.push(path.into());
            self
        }
    }

    impl Lookup for Fake {
        fn var(&self, name: &str) -> Option<OsString> {
            self.vars
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.clone())
        }

        fn is_file(&self, path: &Path) -> bool {
            self.files.iter().any(|file| file == path)
        }

        fn login_shell(&self) -> Option<PathBuf> {
            self.login.clone()
        }
    }

    fn root(name: &str) -> PathBuf {
        let root = if cfg!(windows) { r"C:\" } else { "/" };
        Path::new(root).join(name)
    }

    #[test]
    fn an_absolute_shell_is_used_as_is_and_must_exist() {
        let shell = root("tools").join("sh");
        let lookup = Fake::default().file(&shell);
        assert_eq!(resolve_shell(&shell, None, &lookup).unwrap(), shell);
        let missing = root("missing").join("sh");
        assert_eq!(
            resolve_shell(&missing, Some(&root("cfg")), &lookup)
                .unwrap_err()
                .to_string(),
            format!("shell {} not found", missing.display())
        );
    }

    #[test]
    fn a_relative_shell_with_a_separator_is_resolved_against_the_base_only() {
        let base = root("cfg");
        let lookup = Fake::default()
            .file(base.join("tools/sh"))
            .file("other/sh")
            .path(&[&root("bin")])
            .file(root("bin").join("other/sh"));
        assert_eq!(
            resolve_shell(Path::new("tools/sh"), Some(&base), &lookup).unwrap(),
            base.join("tools/sh")
        );
        for base in [Some(base.as_path()), None] {
            let error = resolve_shell(Path::new("other/sh"), base, &lookup).unwrap_err();
            assert!(error.to_string().contains("not found"), "{error}");
        }
    }

    #[test]
    fn a_bare_shell_is_searched_on_path_and_never_in_the_base_or_current_directory() {
        let (first, second) = (root("first"), root("second"));
        let base = root("cfg");
        let lookup = Fake::default()
            .path(&[
                Path::new(""),
                Path::new("."),
                Path::new("rel"),
                &first,
                &second,
            ])
            .file("sh")
            .file("./sh")
            .file("rel/sh")
            .file(base.join("sh"))
            .file(second.join("sh"))
            .file(second.join("zsh"))
            .file(first.join("zsh"));
        assert_eq!(
            resolve_shell(Path::new("sh"), Some(&base), &lookup).unwrap(),
            second.join("sh")
        );
        assert_eq!(
            resolve_shell(Path::new("zsh"), Some(&base), &lookup).unwrap(),
            first.join("zsh")
        );
        assert_eq!(
            resolve_shell(Path::new("fish"), Some(&base), &lookup)
                .unwrap_err()
                .to_string(),
            "shell fish was not found in the directories of PATH"
        );
        let error = resolve_shell(Path::new("sh"), Some(&base), &Fake::default()).unwrap_err();
        assert!(error.to_string().contains("PATH"), "{error}");
    }

    #[test]
    fn a_path_search_tries_the_name_as_given_then_each_extension_per_directory() {
        let (first, second) = (root("first"), root("second"));
        let path = std::env::join_paths([&first, &second]).unwrap();
        let extensions = OsString::from(".COM;;.EXE");
        let search = |files: &[PathBuf]| {
            search_path(
                OsStr::new("pwsh"),
                Some(&path),
                Some(&extensions),
                |candidate| files.iter().any(|file| file == candidate),
            )
        };
        assert_eq!(
            search(&[first.join("pwsh.EXE"), first.join("pwsh")]),
            Some(first.join("pwsh"))
        );
        assert_eq!(
            search(&[first.join("pwsh.EXE"), first.join("pwsh.COM")]),
            Some(first.join("pwsh.COM"))
        );
        assert_eq!(
            search(&[second.join("pwsh"), first.join("pwsh.EXE")]),
            Some(first.join("pwsh.EXE"))
        );
        assert_eq!(search(&[first.join("pwsh.")]), None);
        assert_eq!(
            search_path(OsStr::new("pwsh"), None, Some(&extensions), |_| true),
            None
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_shells_use_pathext_backslashes_and_refuse_drive_relative_paths() {
        let base = root("cfg");
        let bin = root("bin");
        let lookup = Fake::default()
            .path(&[&bin])
            .env("PATHEXT", ".COM;.EXE")
            .file(bin.join("pwsh.EXE"))
            .file(base.join(r"tools\sh.exe"))
            .file(r"C:tools\sh.exe")
            .file(r"C:\tools\sh.exe");
        assert_eq!(
            resolve_shell(Path::new("pwsh"), Some(&base), &lookup).unwrap(),
            bin.join("pwsh.EXE")
        );
        assert_eq!(
            resolve_shell(Path::new(r"tools\sh.exe"), Some(&base), &lookup).unwrap(),
            base.join(r"tools\sh.exe")
        );
        for value in [r"C:tools\sh.exe", "C:sh.exe", "c:"] {
            let error = resolve_shell(Path::new(value), Some(&base), &lookup).unwrap_err();
            assert_eq!(
                error.to_string(),
                format!(
                    "shell {value} names a drive without a root directory; use an absolute path \
                     or a path without a drive"
                )
            );
        }
        for value in [r"\tools\sh.exe", "/tools/sh.exe", r"\sh.exe"] {
            let error = resolve_shell(Path::new(value), Some(&base), &lookup).unwrap_err();
            assert_eq!(
                error.to_string(),
                format!(
                    "shell {value} names a root directory without a drive; use an absolute path \
                     or a path without a root directory"
                )
            );
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn unix_shells_ignore_pathext() {
        let bin = root("bin");
        let lookup = Fake::default()
            .path(&[&bin])
            .env("PATHEXT", ".EXE")
            .file(bin.join("sh.EXE"));
        let error = resolve_shell(Path::new("sh"), None, &lookup).unwrap_err();
        assert!(error.to_string().contains("PATH"), "{error}");
    }

    fn config(dir: &Path, text: &str) -> ConfigFile {
        let path = dir.join("gateinto.toml");
        std::fs::write(&path, text).unwrap();
        ConfigFile::load(&path).unwrap()
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("gateinto-terminal-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_configured_shell_takes_its_arguments_and_resolves_against_the_file() {
        let dir = temp_dir("configured");
        let bin = root("bin");
        let lookup = Fake::default()
            .path(&[&bin])
            .file(bin.join("zsh"))
            .file(dir.join("tools").join("sh"));
        let file = config(
            &dir,
            "[terminal]\nshell = \"zsh\"\nargs = [\"-l\", \"two words\"]\n",
        );
        assert_eq!(
            configured_shell(&file, &lookup).unwrap(),
            Shell {
                executable: bin.join("zsh"),
                args: ["-l", "two words"].map(OsString::from).to_vec(),
            }
        );
        let file = config(&dir, "[terminal]\nshell = \"tools/sh\"\n");
        assert_eq!(
            configured_shell(&file, &lookup).unwrap(),
            Shell {
                executable: dir.join("tools").join("sh"),
                args: Vec::new(),
            }
        );
        let file = config(&dir, "[terminal]\nshell = \"missing/sh\"\n");
        let error = configured_shell(&file, &lookup).unwrap_err().to_string();
        assert_eq!(
            error,
            format!("shell {} not found", dir.join("missing/sh").display())
        );
    }

    #[test]
    fn without_a_configured_shell_the_platform_default_has_no_arguments() {
        let default = root("default").join("shell");
        let name = if cfg!(windows) { "ComSpec" } else { "SHELL" };
        let lookup = Fake::default()
            .env(name, default.to_str().unwrap())
            .file(&default);
        assert_eq!(
            configured_shell(&ConfigFile::default(), &lookup).unwrap(),
            Shell {
                executable: default,
                args: Vec::new(),
            }
        );
    }

    #[test]
    fn the_windows_default_is_comspec_naming_an_existing_absolute_file() {
        let cmd = root("Windows").join("cmd.exe");
        let lookup = Fake::default()
            .env("ComSpec", cmd.to_str().unwrap())
            .file(&cmd);
        assert_eq!(windows_default_shell(&lookup).unwrap(), cmd);
        for lookup in [
            Fake::default(),
            Fake::default().env("ComSpec", cmd.to_str().unwrap()),
            Fake::default().env("ComSpec", "cmd.exe").file("cmd.exe"),
        ] {
            assert_eq!(
                windows_default_shell(&lookup).unwrap_err().to_string(),
                "the default shell %ComSpec% does not name an existing file by its absolute \
                 path; set shell in the [terminal] section"
            );
        }
    }

    #[test]
    fn the_unix_default_is_shell_then_the_login_shell_then_bin_sh() {
        let (shell, login) = (root("usr/bin/fish"), root("bin/zsh"));
        let both = || {
            Fake {
                login: Some(login.clone()),
                ..Fake::default()
            }
            .env("SHELL", shell.to_str().unwrap())
        };
        assert_eq!(unix_default_shell(&both().file(&shell).file(&login)), shell);
        assert_eq!(unix_default_shell(&both().file(&login)), login);
        assert_eq!(
            unix_default_shell(&both().env("SHELL", "fish").file("fish").file(&login)),
            login
        );
        assert_eq!(unix_default_shell(&both()), PathBuf::from("/bin/sh"));
        assert_eq!(
            unix_default_shell(&Fake::default()),
            PathBuf::from("/bin/sh")
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_login_shell_is_the_users_database_entry() {
        let uid = std::fs::metadata("/proc/self").map(|meta| {
            use std::os::unix::fs::MetadataExt;
            meta.uid()
        });
        let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
        let entry = uid.ok().and_then(|uid| {
            passwd
                .lines()
                .map(|line| line.split(':').collect::<Vec<_>>())
                .find(|fields| fields.len() == 7 && fields[2] == uid.to_string())
        });
        match entry {
            Some(fields) if !fields[6].is_empty() => {
                assert_eq!(System.login_shell(), Some(PathBuf::from(fields[6])));
            }
            _ => {
                let _ = System.login_shell();
            }
        }
    }
}
