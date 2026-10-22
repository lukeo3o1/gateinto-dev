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

pub(crate) async fn bind_ipv6_loopback() -> Option<TcpListener> {
    match TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await {
        Ok(listener) => Some(listener),
        Err(error) if ipv6_unavailable(&error) => {
            eprintln!("skipping: IPv6 loopback is unavailable: {error}");
            None
        }
        Err(error) => panic!("binding [::1]:0 failed: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_family_errors_mean_ipv6_is_unavailable() {
        let errors = [io::Error::from(io::ErrorKind::AddrNotAvailable)]
            .into_iter()
            .chain(ADDRESS_FAMILY_NOT_SUPPORTED.map(io::Error::from_raw_os_error));
        for error in errors {
            assert!(ipv6_unavailable(&error), "{error:?}");
        }
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
    }
}
