use std::io;
use std::net::Ipv6Addr;

use tokio::net::TcpListener;

#[cfg(target_os = "linux")]
const ADDRESS_FAMILY_NOT_SUPPORTED: Option<i32> = Some(97);
#[cfg(windows)]
const ADDRESS_FAMILY_NOT_SUPPORTED: Option<i32> = Some(10047);
#[cfg(not(any(target_os = "linux", windows)))]
const ADDRESS_FAMILY_NOT_SUPPORTED: Option<i32> = None;

pub(crate) fn ipv6_unavailable(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::AddrNotAvailable
        || error
            .raw_os_error()
            .is_some_and(|code| Some(code) == ADDRESS_FAMILY_NOT_SUPPORTED)
}

fn skip_without_ipv6(error: &io::Error, ci: bool) -> bool {
    !ci && ipv6_unavailable(error)
}

pub(crate) async fn bind_ipv6_loopback() -> Option<TcpListener> {
    match TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await {
        Ok(listener) => Some(listener),
        Err(error) if skip_without_ipv6(&error, std::env::var_os("CI").is_some()) => {
            eprintln!("skipping: IPv6 loopback is unavailable: {error}");
            None
        }
        Err(error) => panic!("binding [::1]:0 failed: {error}"),
    }
}

mod tests {
    use super::*;

    #[test]
    fn address_family_errors_mean_ipv6_is_unavailable() {
        assert!(ipv6_unavailable(&io::Error::from(
            io::ErrorKind::AddrNotAvailable
        )));
        #[cfg(target_os = "linux")]
        assert!(ipv6_unavailable(&io::Error::from_raw_os_error(97)));
        #[cfg(windows)]
        assert!(ipv6_unavailable(&io::Error::from_raw_os_error(10047)));
    }

    #[test]
    fn other_bind_errors_do_not_mean_ipv6_is_unavailable() {
        for error in [
            io::Error::from(io::ErrorKind::AddrInUse),
            io::Error::from(io::ErrorKind::PermissionDenied),
            io::Error::other("unexpected"),
        ] {
            assert!(!ipv6_unavailable(&error), "{error:?}");
        }
        #[cfg(target_os = "linux")]
        assert!(!ipv6_unavailable(&io::Error::from_raw_os_error(98)));
        #[cfg(windows)]
        assert!(!ipv6_unavailable(&io::Error::from_raw_os_error(10048)));
    }

    #[test]
    fn missing_ipv6_is_skipped_only_outside_ci() {
        let unavailable = io::Error::from(io::ErrorKind::AddrNotAvailable);
        assert!(skip_without_ipv6(&unavailable, false));
        assert!(!skip_without_ipv6(&unavailable, true));
        let in_use = io::Error::from(io::ErrorKind::AddrInUse);
        assert!(!skip_without_ipv6(&in_use, false));
        assert!(!skip_without_ipv6(&in_use, true));
    }
}
