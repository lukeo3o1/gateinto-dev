#![no_main]

use gateinto::http::{
    Authority, ConnectRequest, DEFAULT_MAX_HEADER_BYTES, Host, ParseError, parse_connect_request,
    parse_response, parse_status_line,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (max, buf) = match data.split_first() {
        Some((&selector, rest)) if selector & 1 == 1 => (usize::from(selector >> 1), rest),
        Some((_, rest)) => (DEFAULT_MAX_HEADER_BYTES, rest),
        None => (DEFAULT_MAX_HEADER_BYTES, data),
    };
    check_request(buf, max);
    check_response(buf, max);
});

fn split_points(len: usize, head_len: Option<usize>) -> impl Iterator<Item = usize> {
    [0, len / 2, len.saturating_sub(1)]
        .into_iter()
        .chain(head_len.map(|head_len| head_len - 1))
}

fn check_head(buf: &[u8], max: usize, head_len: usize) {
    assert!(head_len >= 4 && head_len <= buf.len() && head_len <= max);
    let head = &buf[..head_len];
    assert!(head.ends_with(b"\r\n\r\n"));
    assert!(!head.contains(&0));
    for (i, &byte) in head.iter().enumerate() {
        match byte {
            b'\r' => assert_eq!(head[i + 1], b'\n'),
            b'\n' => assert_eq!(head[i - 1], b'\r'),
            _ => {}
        }
    }
}

fn check_request(buf: &[u8], max: usize) {
    let result = parse_connect_request(buf, max);
    match &result {
        Ok(None) => assert!(buf.len() < max),
        Ok(Some(parsed)) => {
            check_head(buf, max, parsed.head_len);
            assert!(buf.starts_with(b"CONNECT "));
            assert_eq!(
                parse_connect_request(&buf[..parsed.head_len], max),
                result,
                "bytes after the head changed the result"
            );
            check_target(&parsed.value.target);
            check_redaction(&parsed.value);
        }
        Err(ParseError::TooLarge) => assert!(buf.len() >= max),
        Err(ParseError::Malformed | ParseError::MethodNotAllowed) => {}
    }
    let head_len = result
        .as_ref()
        .ok()
        .and_then(Option::as_ref)
        .map(|parsed| parsed.head_len);
    for k in split_points(buf.len(), head_len) {
        let partial = parse_connect_request(&buf[..k], max);
        assert!(
            partial == Ok(None) || partial == result,
            "reading {k} of {} bytes gave {partial:?}, all of them {result:?}",
            buf.len()
        );
    }
}

fn check_target(target: &Authority) {
    assert_ne!(target.port, 0);
    if let Host::Name(name) = &target.host {
        assert!((1..=253).contains(&name.len()));
        assert!(
            name.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        );
        assert!(!name.starts_with(['-', '.']) && !name.ends_with(['-', '.']));
    }
    assert_eq!(target.to_string().parse::<Authority>().as_ref(), Ok(target));
}

fn check_redaction(request: &ConnectRequest) {
    let mut other = request.clone();
    other.proxy_authorization = request
        .proxy_authorization
        .as_ref()
        .map(|_| b"Basic b3RoZXI6c2VjcmV0".to_vec());
    assert_eq!(
        format!("{request:?}"),
        format!("{other:?}"),
        "the Debug output depends on the Proxy-Authorization value"
    );
    if let Some(value) = &request.proxy_authorization {
        assert!(!value.iter().any(|&b| b == b'\r' || b == b'\n' || b == 0));
        assert_eq!(value.trim_ascii(), value.as_slice());
    }
}

fn check_response(buf: &[u8], max: usize) {
    let result = parse_response(buf, max);
    match &result {
        Ok(None) => assert!(buf.len() < max),
        Ok(Some(parsed)) => {
            check_head(buf, max, parsed.head_len);
            assert!((100..=599).contains(&parsed.value));
            let line = parse_status_line(buf, max).unwrap().unwrap();
            assert_eq!(line.head_len, parsed.head_len);
            assert_eq!(line.value.0, parsed.value);
            assert!(
                line.value
                    .1
                    .starts_with(&format!("HTTP/1.1 {} ", parsed.value))
            );
        }
        Err(ParseError::TooLarge) => assert!(buf.len() >= max),
        Err(ParseError::Malformed) => {}
        Err(ParseError::MethodNotAllowed) => panic!("a response has no method"),
    }
    let head_len = result
        .as_ref()
        .ok()
        .and_then(Option::as_ref)
        .map(|parsed| parsed.head_len);
    for k in split_points(buf.len(), head_len) {
        let partial = parse_response(&buf[..k], max);
        assert!(partial == Ok(None) || partial == result);
    }
}
