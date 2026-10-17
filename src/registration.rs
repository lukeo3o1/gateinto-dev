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
                 without quotes, percent signs or control characters that does not end with \
                 a separator"
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

const URI_ARGUMENT: &str = " -- \"%1\"";

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
        && !text.chars().any(|c| c == '"' || c == '%' || c.is_control());
    if safe { Ok(text) } else { Err(unsafe_path()) }
}

pub fn is_handler_command(command: &str) -> bool {
    let Some((executable, arguments)) = command
        .strip_prefix('"')
        .and_then(|rest| rest.split_once('"'))
    else {
        return false;
    };
    let file_name = executable
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let arguments = arguments
        .strip_prefix(" open")
        .and_then(|rest| rest.strip_suffix(URI_ARGUMENT));
    let arguments_valid = match arguments {
        Some("") => true,
        Some(rest) => rest
            .strip_prefix(" --config \"")
            .and_then(|rest| rest.strip_suffix('"'))
            .is_some_and(|config| !config.is_empty() && !config.contains('"')),
        None => false,
    };
    matches!(file_name.as_str(), "gateinto.exe" | "gateinto") && arguments_valid
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

    #[test]
    fn the_command_quotes_the_executable_and_the_uri_after_an_end_of_options_marker() {
        assert_eq!(
            handler_command(Path::new(EXE), None).unwrap(),
            format!("\"{EXE}\" open -- \"%1\"")
        );
    }

    #[test]
    fn the_command_passes_the_config_file_quoted() {
        assert_eq!(
            handler_command(Path::new(EXE), Some(Path::new(CONFIG))).unwrap(),
            format!("\"{EXE}\" open --config \"{CONFIG}\" -- \"%1\"")
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
            r#""C:\dev\target\debug\GATEINTO.EXE" open -- "%1""#.to_owned(),
        ] {
            assert!(is_handler_command(&command), "{command}");
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
