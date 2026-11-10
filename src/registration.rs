use std::fmt;
use std::path::Path;

pub const SCHEME: &str = "gateinto";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationError {
    UnsafePath(String),
    InvalidScheme(String),
    ForeignHandler {
        scheme: String,
        command: Option<String>,
    },
    Registry {
        operation: &'static str,
        code: u32,
    },
    Unsupported,
}

impl fmt::Display for RegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsafePath(path) => write!(
                f,
                "cannot use {path:?} in a URI handler command: it must be an absolute path \
                 without {REFUSED_DESCRIPTION} that does not end with a separator"
            ),
            Self::InvalidScheme(scheme) => write!(f, "invalid URI scheme name {scheme:?}"),
            Self::ForeignHandler {
                scheme,
                command: Some(command),
            } => write!(
                f,
                "HKCU\\Software\\Classes\\{scheme} runs {command:?}, which is not a Gateinto \
                 handler; leaving it unchanged"
            ),
            Self::ForeignHandler {
                scheme,
                command: None,
            } => write!(
                f,
                "HKCU\\Software\\Classes\\{scheme} exists without a Gateinto handler command; \
                 leaving it unchanged"
            ),
            Self::Registry { operation, code } => {
                write!(f, "{operation} failed with Windows error {code}")
            }
            Self::Unsupported => {
                f.write_str("URI handler registration is only supported on Windows")
            }
        }
    }
}

impl std::error::Error for RegistrationError {}

#[cfg(target_os = "linux")]
const URI_ARGUMENT: &str = " -- %u";
#[cfg(not(target_os = "linux"))]
const URI_ARGUMENT: &str = " -- \"%1\"";

#[cfg(target_os = "linux")]
const REFUSED: &[char] = &['"', '%', '`', '$', '\\'];
#[cfg(not(target_os = "linux"))]
const REFUSED: &[char] = &['"', '%'];
#[cfg(target_os = "linux")]
const REFUSED_DESCRIPTION: &str =
    "quotes, backticks, dollar signs, backslashes, percent signs or control characters";
#[cfg(not(target_os = "linux"))]
const REFUSED_DESCRIPTION: &str = "quotes, percent signs or control characters";

pub fn handler_command(
    executable: &Path,
    config: Option<&Path>,
) -> Result<String, RegistrationError> {
    let mut command = format!("\"{}\" open", quotable(executable)?);
    if let Some(config) = config {
        command.push_str(&format!(" --config \"{}\"", quotable(config)?));
    }
    command.push_str(URI_ARGUMENT);
    Ok(command)
}

fn quotable(path: &Path) -> Result<&str, RegistrationError> {
    let unsafe_path = || RegistrationError::UnsafePath(path.display().to_string());
    let text = path.to_str().ok_or_else(unsafe_path)?;
    let safe = path.is_absolute()
        && !text.ends_with(['\\', '/'])
        && !text.chars().any(|c| REFUSED.contains(&c) || c.is_control());
    if safe { Ok(text) } else { Err(unsafe_path()) }
}

pub fn is_handler_command(command: &str) -> bool {
    let Some((executable, arguments)) = command
        .strip_prefix('"')
        .and_then(|rest| rest.split_once('"'))
    else {
        return false;
    };
    let arguments = arguments
        .strip_prefix(" open")
        .and_then(|rest| rest.strip_suffix(URI_ARGUMENT));
    let config = match arguments {
        Some("") => None,
        Some(rest) => match rest
            .strip_prefix(" --config \"")
            .and_then(|rest| rest.strip_suffix('"'))
        {
            Some(config) if !config.is_empty() && !config.contains('"') => Some(config),
            _ => return false,
        },
        None => return false,
    };
    is_our_executable(executable, config)
}

#[cfg(target_os = "linux")]
fn is_our_executable(executable: &str, config: Option<&str>) -> bool {
    executable.rsplit('/').next() == Some("gateinto")
        && quotable(Path::new(executable)).is_ok()
        && config.is_none_or(|config| quotable(Path::new(config)).is_ok())
}

#[cfg(not(target_os = "linux"))]
fn is_our_executable(executable: &str, _config: Option<&str>) -> bool {
    let file_name = executable
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(file_name.as_str(), "gateinto.exe" | "gateinto")
}

pub fn validate_scheme(scheme: &str) -> Result<(), RegistrationError> {
    let valid = (1..=32).contains(&scheme.len())
        && scheme.starts_with(|c: char| c.is_ascii_lowercase())
        && scheme
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if valid {
        Ok(())
    } else {
        Err(RegistrationError::InvalidScheme(scheme.to_owned()))
    }
}

#[cfg(not(windows))]
pub fn register(_scheme: &str, _command: &str) -> Result<(), RegistrationError> {
    Err(RegistrationError::Unsupported)
}

#[cfg(not(windows))]
pub fn unregister(_scheme: &str) -> Result<bool, RegistrationError> {
    Err(RegistrationError::Unsupported)
}

#[cfg(not(windows))]
pub fn registered_command(_scheme: &str) -> Result<Option<String>, RegistrationError> {
    Err(RegistrationError::Unsupported)
}

#[cfg(windows)]
pub use windows::{register, registered_command, unregister};

#[cfg(windows)]
mod windows {
    use super::{RegistrationError, is_handler_command, validate_scheme};
    use crate::registry::{Key, delete_tree, key_exists, read_string};
    use windows_sys::Win32::System::Registry::HKEY_CURRENT_USER;

    fn key_path(scheme: &str) -> String {
        format!(r"Software\Classes\{scheme}")
    }

    pub fn registered_command(scheme: &str) -> Result<Option<String>, RegistrationError> {
        validate_scheme(scheme)?;
        read_string(
            HKEY_CURRENT_USER,
            &format!(r"{}\shell\open\command", key_path(scheme)),
            None,
        )
    }

    fn ensure_ours(scheme: &str) -> Result<bool, RegistrationError> {
        let foreign = |command| RegistrationError::ForeignHandler {
            scheme: scheme.to_owned(),
            command,
        };
        match registered_command(scheme)? {
            Some(command) if is_handler_command(&command) => Ok(true),
            Some(command) => Err(foreign(Some(command))),
            None if key_exists(HKEY_CURRENT_USER, &key_path(scheme))? => Err(foreign(None)),
            None => Ok(false),
        }
    }

    pub fn register(scheme: &str, command: &str) -> Result<(), RegistrationError> {
        if !is_handler_command(command) {
            return Err(RegistrationError::ForeignHandler {
                scheme: scheme.to_owned(),
                command: Some(command.to_owned()),
            });
        }
        let existed = ensure_ours(scheme)?;
        let path = key_path(scheme);
        let write = || {
            let key = Key::create(HKEY_CURRENT_USER, &path)?;
            key.set_string(None, "URL:Gateinto launch link")?;
            key.set_string(Some("URL Protocol"), "")?;
            Key::create(key.raw(), r"shell\open\command")?.set_string(None, command)
        };
        let result = write();
        if result.is_err() && !existed {
            let _ = delete_tree(HKEY_CURRENT_USER, &path);
        }
        result
    }

    pub fn unregister(scheme: &str) -> Result<bool, RegistrationError> {
        if !ensure_ours(scheme)? {
            return Ok(false);
        }
        delete_tree(HKEY_CURRENT_USER, &key_path(scheme))?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    const EXE: &str = r"C:\Program Files\Gateinto\gateinto.exe";
    #[cfg(not(windows))]
    const EXE: &str = "/opt/gate into/gateinto";
    #[cfg(windows)]
    const CONFIG: &str = r"C:\Users\me\gateinto.toml";
    #[cfg(not(windows))]
    const CONFIG: &str = "/home/me/gateinto.toml";
    #[cfg(target_os = "linux")]
    const URI: &str = "%u";
    #[cfg(not(target_os = "linux"))]
    const URI: &str = "\"%1\"";

    #[test]
    fn the_command_quotes_the_executable_and_the_uri_after_an_end_of_options_marker() {
        assert_eq!(
            handler_command(Path::new(EXE), None).unwrap(),
            format!("\"{EXE}\" open -- {URI}")
        );
    }

    #[test]
    fn the_command_passes_the_config_file_quoted() {
        assert_eq!(
            handler_command(Path::new(EXE), Some(Path::new(CONFIG))).unwrap(),
            format!("\"{EXE}\" open --config \"{CONFIG}\" -- {URI}")
        );
    }

    #[test]
    fn paths_that_could_break_the_quoting_or_expand_are_refused() {
        let base = Path::new(EXE)
            .parent()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let sep = std::path::MAIN_SEPARATOR;
        for path in [
            format!("{base}{sep}a\"b{sep}gateinto.exe"),
            format!("{base}{sep}100%{sep}gateinto.exe"),
            format!("{base}{sep}%1{sep}gateinto.exe"),
            format!("{base}{sep}a\nb{sep}gateinto.exe"),
            format!("{base}{sep}a\u{0}b{sep}gateinto.exe"),
            format!("{base}{sep}"),
            "gateinto.exe".to_owned(),
            format!("relative{sep}gateinto.exe"),
        ] {
            assert!(handler_command(Path::new(&path), None).is_err(), "{path:?}");
            assert!(
                handler_command(Path::new(EXE), Some(Path::new(&path))).is_err(),
                "{path:?}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn paths_that_a_desktop_entry_would_interpret_are_refused() {
        for path in [
            "/opt/a`b/gateinto",
            "/opt/$HOME/gateinto",
            "/opt/a\\b/gateinto",
            "/opt/a\u{7f}b/gateinto",
        ] {
            assert!(handler_command(Path::new(path), None).is_err(), "{path:?}");
            assert!(
                handler_command(Path::new(EXE), Some(Path::new(path))).is_err(),
                "{path:?}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_refusal_names_the_characters_refused_on_linux() {
        let error = handler_command(Path::new("/opt/$X/gateinto"), None).unwrap_err();
        assert_eq!(
            error.to_string(),
            "cannot use \"/opt/$X/gateinto\" in a URI handler command: it must be an absolute \
             path without quotes, backticks, dollar signs, backslashes, percent signs or control \
             characters that does not end with a separator"
        );
    }

    #[test]
    fn scheme_names_are_restricted() {
        for scheme in ["gateinto", "gateinto-test-123", "a"] {
            assert_eq!(validate_scheme(scheme), Ok(()), "{scheme}");
        }
        for scheme in [
            "",
            "Gateinto",
            "1gateinto",
            "-gateinto",
            "gate into",
            "gate\\into",
            "gate.into",
            "gateinto:",
            &"a".repeat(33),
        ] {
            assert!(validate_scheme(scheme).is_err(), "{scheme:?}");
        }
    }

    #[test]
    fn built_commands_are_recognised_as_gateinto_handlers() {
        for command in [
            handler_command(Path::new(EXE), None).unwrap(),
            handler_command(Path::new(EXE), Some(Path::new(CONFIG))).unwrap(),
        ] {
            assert!(is_handler_command(&command), "{command}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn the_windows_executable_name_is_matched_case_insensitively() {
        assert!(is_handler_command(
            r#""C:\dev\target\debug\GATEINTO.EXE" open -- "%1""#
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_commands_must_be_ones_handler_command_would_build() {
        for command in [
            r#""/opt/gateinto/gateinto" open -- "%1""#,
            r#""/opt/gateinto/gateinto" open -- %u %f"#,
            r#""/opt/gateinto/gateinto" open -- %U"#,
            r#""/opt/gateinto/gateinto" open %u"#,
            r#""/opt/gateinto/GATEINTO" open -- %u"#,
            r#""/opt/gateinto/gateinto.exe" open -- %u"#,
            r#""/opt/gateinto/other" open -- %u"#,
            r#""gateinto" open -- %u"#,
            r#""bin/gateinto" open -- %u"#,
            r#""/opt/$X/gateinto" open -- %u"#,
            r#""/opt/a`id`/gateinto" open -- %u"#,
            r#""/opt/a\"/gateinto" open -- %u"#,
            r#""/opt/100%/gateinto" open -- %u"#,
            r#""/opt/gateinto/gateinto" open --config "$HOME/g.toml" -- %u"#,
            r#""/opt/gateinto/gateinto" open --config "/a`id`.toml" -- %u"#,
            r#""/opt/gateinto/gateinto" open --config "/a\b.toml" -- %u"#,
            r#""/opt/gateinto/gateinto" open --config "/a%%.toml" -- %u"#,
            r#""/opt/gateinto/gateinto" open --config "g.toml" -- %u"#,
            r#""/opt/gateinto/gateinto" open --config "/etc/" -- %u"#,
            r#""/opt/gateinto/gateinto" open --config "" -- %u"#,
            "\"/opt/gateinto/gateinto\" open --config \"/a\tb.toml\" -- %u",
        ] {
            assert!(!is_handler_command(command), "{command}");
        }
    }

    #[test]
    fn other_commands_are_not_gateinto_handlers() {
        for command in [
            "",
            r#""C:\Program Files\Other\other.exe" "%1""#,
            r#""C:\Program Files\Other\other.exe" open -- "%1""#,
            r#""C:\Gateinto\gateinto.exe.evil.exe" open -- "%1""#,
            r#""C:\Gateinto\notgateinto.exe" open -- "%1""#,
            r#"C:\Gateinto\gateinto.exe open -- "%1""#,
            r#""C:\Gateinto\gateinto.exe" "%1""#,
            r#""C:\Gateinto\gateinto.exe" open "%1""#,
            r#""C:\Gateinto\gateinto.exe" open -- "%1" & calc"#,
            r#""C:\Gateinto\gateinto.exe" open -- "%1"; "C:\x.exe""#,
            r#""C:\Gateinto\gateinto.exe" open --config "a" "b" -- "%1""#,
            r#""C:\Gateinto\gateinto.exe"#,
        ] {
            assert!(!is_handler_command(command), "{command}");
        }
    }
}
