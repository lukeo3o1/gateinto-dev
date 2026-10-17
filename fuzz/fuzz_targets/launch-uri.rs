#![no_main]

use gateinto::config::GatewayName;
use gateinto::ipc::Request;
use gateinto::uri::{LaunchRequest, MAX_LEN, UriError};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(uri) = std::str::from_utf8(data) else {
        return;
    };
    let request = match uri.parse::<LaunchRequest>() {
        Ok(request) => request,
        Err(error) => {
            if uri.len() > MAX_LEN {
                assert_eq!(error, UriError::TooLong);
            }
            return;
        }
    };
    assert!(uri.len() <= MAX_LEN);
    assert!(uri[..9].eq_ignore_ascii_case("gateinto:"));
    let profile = request.profile.as_str();
    assert!((1..=GatewayName::MAX_LEN).contains(&profile.len()));
    assert!(
        profile
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    );
    assert!(!profile.starts_with('-'));

    let canonical = format!(
        "gateinto://connect?profile={profile}&auth={}&v=1",
        request.auth
    );
    assert_eq!(canonical.parse::<LaunchRequest>().as_ref(), Ok(&request));

    let line = Request::Launch(request.clone()).to_string();
    assert_eq!(line.split(' ').count(), 3);
    assert_eq!(line.parse::<Request>(), Ok(Request::Launch(request)));
});
