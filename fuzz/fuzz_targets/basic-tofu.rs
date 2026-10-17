#![no_main]

use std::time::{Duration, Instant};

use gateinto::http::{DEFAULT_MAX_HEADER_BYTES, parse_connect_request};
use gateinto::proxy::FailureLimit;
use gateinto::proxy::fuzzing::{LocalAuthSession, Outcome, basic_credential};
use libfuzzer_sys::fuzz_target;

const WINDOW: Duration = Duration::from_secs(60);

fuzz_target!(|data: &[u8]| {
    let Some((&config, values)) = data.split_first() else {
        return;
    };
    check_credential_parser(values);
    let max_failures = if config & 0x80 == 0 {
        u32::from(config & 0x0f) + 1
    } else {
        u32::MAX
    };
    let session = LocalAuthSession::new(FailureLimit {
        max_failures,
        window: WINDOW,
    })
    .unwrap();
    let realm = session.realm().to_owned();
    let nonce = realm.strip_prefix("Gateinto session ").unwrap();
    assert!(nonce.len() == 16 && nonce.bytes().all(|b| b.is_ascii_hexdigit()));

    let now = Instant::now();
    let mut bound: Option<Vec<u8>> = None;
    let mut failures = 0u32;
    for value in values.split(|&b| b == 0) {
        let head = request(value);
        let outcome = session.respond(&head, DEFAULT_MAX_HEADER_BYTES, now);
        let parsed = match parse_connect_request(&head, DEFAULT_MAX_HEADER_BYTES) {
            Ok(Some(parsed)) => parsed.value,
            Ok(None) => unreachable!("the request is terminated"),
            Err(_) => {
                let status = rejected(&outcome, &realm);
                assert!(status == 400 || status == 431, "{status}");
                continue;
            }
        };
        if failures >= max_failures {
            assert_eq!(rejected(&outcome, &realm), 429);
            continue;
        }
        let Some(authorization) = parsed.proxy_authorization else {
            assert_eq!(rejected(&outcome, &realm), 407);
            continue;
        };
        match (basic_credential(&authorization), &bound) {
            (Some(credential), None) => {
                assert_eq!(outcome, Outcome::Tunnel { bound: true });
                bound = Some(credential);
            }
            (Some(credential), Some(first)) if credential == *first => {
                assert_eq!(outcome, Outcome::Tunnel { bound: false });
            }
            (Some(_), Some(_)) => {
                assert_eq!(rejected(&outcome, &realm), 407);
                failures += 1;
            }
            (None, _) => {
                let status = rejected(&outcome, &realm);
                assert!(status == 400 || status == 407, "{status}");
                failures += 1;
            }
        }
    }
});

fn request(value: &[u8]) -> Vec<u8> {
    let mut head = b"CONNECT a.test:443 HTTP/1.1\r\nHost: a.test:443\r\n".to_vec();
    if !value.is_empty() {
        head.extend_from_slice(b"Proxy-Authorization: ");
        head.extend_from_slice(value);
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(b"\r\n");
    head
}

fn rejected(outcome: &Outcome, realm: &str) -> u16 {
    let Outcome::Reject(response) = outcome else {
        panic!("expected a rejection, got {outcome:?}");
    };
    let (status, reason, extra) = match &response.as_bytes()[..12] {
        b"HTTP/1.1 400" => (400, "Bad Request", String::new()),
        b"HTTP/1.1 407" => (
            407,
            "Proxy Authentication Required",
            format!("Proxy-Authenticate: Basic realm=\"{realm}\", charset=\"UTF-8\"\r\n"),
        ),
        b"HTTP/1.1 429" => (
            429,
            "Too Many Requests",
            format!("Retry-After: {}\r\n", WINDOW.as_secs()),
        ),
        b"HTTP/1.1 431" => (431, "Request Header Fields Too Large", String::new()),
        _ => panic!("unexpected response {response:?}"),
    };
    assert_eq!(
        *response,
        format!(
            "HTTP/1.1 {status} {reason}\r\n{extra}Connection: close\r\nContent-Length: 0\r\n\r\n"
        ),
        "the response is not fixed by its status and the session realm"
    );
    status
}

fn check_credential_parser(value: &[u8]) {
    let Some(credential) = basic_credential(value) else {
        return;
    };
    assert!(value.len() >= 6 && value[..6].eq_ignore_ascii_case(b"basic "));
    assert!(credential.len() <= 768);
    let colon = credential.iter().position(|&b| b == b':').unwrap();
    assert!(colon + 1 < credential.len());
    assert!(!credential.iter().any(|&b| b < 0x20 || b == 0x7f));
}
