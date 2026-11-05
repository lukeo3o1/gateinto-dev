use std::ffi::{OsStr, OsString};
use std::net::SocketAddr;

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
}
