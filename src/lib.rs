pub mod agent;
pub mod browser;
pub mod check;
pub mod clock;
pub mod config;
mod dns;
pub mod http;
pub mod identity;
pub mod ipc;
pub mod job;
pub mod lifecycle;
pub mod link;
pub mod logbook;
pub mod process;
pub mod prompt;
pub mod proxy;
pub mod registration;
#[cfg(windows)]
mod registry;
pub mod session_table;
pub mod sessions;
pub mod terminal;
#[cfg(test)]
mod test_logs;
#[cfg(test)]
mod test_support;
pub mod tls;
#[cfg(windows)]
mod token;
pub mod uri;

pub const VERSION: &str = match option_env!("GATEINTO_BUILD_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

const _: () = assert!(
    http::is_token(VERSION.as_bytes()),
    "GATEINTO_BUILD_VERSION must be an HTTP token"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_a_token_and_a_bad_build_version_is_not() {
        assert!(http::is_token(VERSION.as_bytes()));
        assert_eq!(
            VERSION,
            option_env!("GATEINTO_BUILD_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
        );
        for bad in ["", "1.0 beta", "1.0/2", "1.0\"", "1.0\u{e9}"] {
            assert!(!http::is_token(bad.as_bytes()), "{bad:?}");
        }
    }
}
