use std::ffi::{OsStr, OsString};
use std::fmt;
use std::net::SocketAddr;

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
