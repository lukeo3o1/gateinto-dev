#![no_main]

use gateinto::config::{GatewayName, PortalUrl};
use gateinto::ipc::Request;
use gateinto::link::{self, Decision, Known, KnownGateway, Origin, Resolution, Source};
use gateinto::proxy::Route;
use gateinto::uri::{LaunchRequest, MAX_LEN, UriError};
use libfuzzer_sys::fuzz_target;

fn known() -> Known {
    let gateway = |name: &str, host: &str, portal: Option<&str>| KnownGateway {
        name: name.parse().unwrap(),
        host: Some(host.to_owned()),
        port: Some(443),
        portal_url: portal.map(|portal| portal.parse().unwrap()),
        source: Source::Config,
    };
    Known {
        gateways: vec![
            gateway("a", "proxy.example", Some("https://portal.example/start")),
            gateway("b", "10.0.0.1", None),
            gateway("c", "::1", Some("https://[::1]:8443/")),
        ],
        ..Known::default()
    }
}

fn origin(url: &PortalUrl) -> Origin {
    Origin::of(url).expect("parsed URLs have an origin")
}

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

    assert_eq!(request.gateway.is_some(), request.portal.is_some());
    if let Some(gateway) = &request.gateway {
        let host = gateway.host();
        assert!(!host.is_empty());
        let file = link::store::file_name(gateway);
        if let Ok(file) = &file {
            assert!(link::store::safe_file_name(file));
            assert_eq!(link::store::address_of_file(file).as_ref(), Some(gateway));
        }
        assert!(
            !host
                .chars()
                .any(|c| "@/\\?#[]".contains(c) || c.is_whitespace() || !c.is_ascii())
        );
        assert_ne!(gateway.port(), 0);
    }
    for url in [&request.url, &request.portal].into_iter().flatten() {
        assert!(url.as_str().bytes().all(|b| b.is_ascii_graphic()));
        origin(url);
    }
    if let (Some(url), Some(portal)) = (&request.url, &request.portal) {
        assert_eq!(origin(url), origin(portal));
    }

    let canonical = request.to_string();
    assert!(canonical.len() <= MAX_LEN);
    assert_eq!(canonical.parse::<LaunchRequest>().as_ref(), Ok(&request));

    let known = known();
    for decision in [Decision::Approve, Decision::Deny, Decision::Defer] {
        let mut confirm = decision;
        let Ok(resolution) = link::resolve(&request, &known, &mut confirm, 0) else {
            continue;
        };
        let Resolution::Launch(launch) = resolution else {
            assert_eq!(decision, Decision::Defer);
            continue;
        };
        assert_eq!(launch.route, request.route);
        let portal = known
            .gateways
            .iter()
            .find(|known| known.name == launch.profile)
            .map(|known| known.portal_url.clone())
            .unwrap_or_else(|| request.portal.clone());
        if launch.add.is_some() {
            assert_eq!(decision, Decision::Approve);
        }
        if let Some(start) = &launch.start_page {
            let portal = portal.expect("a start page needs a portal");
            assert_eq!(origin(start), origin(&portal));
        }
    }

    let line = Request::Launch(request.clone()).to_string();
    assert!(!line.contains(['\r', '\n']));
    let fields = [&request.url, &request.portal]
        .into_iter()
        .flatten()
        .count()
        + usize::from(request.gateway.is_some())
        + usize::from(request.route != Route::Gateway);
    assert_eq!(line.split(' ').count(), 3 + fields);
    assert_eq!(line.parse::<Request>(), Ok(Request::Launch(request)));
});
