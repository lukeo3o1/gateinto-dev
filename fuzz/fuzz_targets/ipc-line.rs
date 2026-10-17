#![no_main]

use gateinto::ipc::{MAX_REQUEST_BYTES, Request, Response};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    check_request(text);
    check_decoded_response(text);
    check_encoded_response(text);
});

fn check_request(line: &str) {
    let Ok(request) = line.parse::<Request>() else {
        return;
    };
    let encoded = request.to_string();
    assert!(!encoded.contains(['\r', '\n']));
    assert!(encoded.len() < MAX_REQUEST_BYTES);
    assert_eq!(encoded.parse::<Request>().as_ref(), Ok(&request));
    if !matches!(request, Request::Close(_)) {
        assert_eq!(encoded, line);
    }
}

fn check_decoded_response(text: &str) {
    let Ok(response) = Response::decode(text) else {
        return;
    };
    let encoded = response.encode();
    assert_eq!(
        Response::decode(&encoded).map(|again| again.encode()),
        Ok(encoded.clone())
    );
    if !text.contains('\r') {
        assert_eq!(encoded, text);
    }
}

fn check_encoded_response(text: &str) {
    let lines: Vec<String> = text.split('\0').map(str::to_owned).collect();
    let single = |line: &String| line.replace(['\r', '\n'], " ");
    let expected = lines.iter().map(single).collect();
    assert_eq!(
        Response::decode(&Response::Ok(lines).encode()),
        Ok(Response::Ok(expected))
    );
    if !text.is_empty() {
        assert_eq!(
            Response::decode(&Response::Error(text.to_owned()).encode()),
            Ok(Response::Error(single(&text.to_owned())))
        );
    }
}
