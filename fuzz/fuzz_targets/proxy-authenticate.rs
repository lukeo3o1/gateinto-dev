#![no_main]

use gateinto::proxy::fuzzing::{
    MAX_AUTH_URI_LEN, MAX_EXPIRES_IN, VerificationChallenge, VerificationOrigin,
    verification_challenge,
};
use libfuzzer_sys::fuzz_target;

const FINGERPRINT: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const EXCLUDED: &[u8] = b"\"\\ <>^`{|}#;";

fuzz_target!(|data: &[u8]| {
    let values: Vec<&[u8]> = data.split(|&b| b == b'\n').collect();
    for value in &values {
        check_origin(value);
    }
    let Some(challenge) = verification_challenge(&values, FINGERPRINT, None) else {
        return;
    };
    check_values(&challenge);
    let rendered = format!(
        "Gateinto auth_uri=\"{}\", user_code={}, expires_in={}",
        challenge.auth_uri, challenge.user_code, challenge.expires_in
    );
    assert_eq!(
        verification_challenge(&[rendered.as_bytes()], FINGERPRINT, None).as_ref(),
        Some(&challenge),
        "an accepted challenge does not re-validate"
    );
    let origin: VerificationOrigin = challenge
        .origin
        .parse()
        .expect("the origin of an accepted challenge is a valid verification origin");
    assert_eq!(origin.as_str(), challenge.origin);
    assert_eq!(
        verification_challenge(&values, FINGERPRINT, Some(&[origin])).as_ref(),
        Some(&challenge)
    );
    assert_eq!(
        verification_challenge(&values, FINGERPRINT, Some(&[])),
        None
    );
});

fn check_values(challenge: &VerificationChallenge) {
    for value in [&challenge.auth_uri, &challenge.origin, &challenge.user_code] {
        assert!(value.bytes().all(|b| b.is_ascii_graphic()), "{value:?}");
    }
    let url = &challenge.auth_uri;
    assert!(!url.bytes().any(|b| EXCLUDED.contains(&b)), "{url:?}");
    assert!(url.len() <= MAX_AUTH_URI_LEN);
    assert!(url[..8].eq_ignore_ascii_case("https://"), "{url:?}");
    assert!(url.contains(FINGERPRINT), "{url:?}");
    let code = challenge.user_code.as_bytes();
    assert!(code.len() == 9 && code[4] == b'-', "{code:?}");
    assert!(
        code.iter()
            .enumerate()
            .all(|(i, b)| i == 4 || b"BCDFGHJKLMNPQRSTVWXZ".contains(b))
    );
    assert!((1..=MAX_EXPIRES_IN).contains(&challenge.expires_in));
}

fn check_origin(value: &[u8]) {
    let Ok(text) = std::str::from_utf8(value) else {
        return;
    };
    let Ok(origin) = text.parse::<VerificationOrigin>() else {
        return;
    };
    let stored = origin.as_str();
    let authority = stored
        .strip_prefix("https://")
        .unwrap_or_else(|| panic!("{stored:?}"));
    assert!(
        authority
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b.is_ascii_uppercase() && !EXCLUDED.contains(&b)),
        "{stored:?}"
    );
    assert!(!authority.contains(['/', '?', '@', '%']), "{stored:?}");
    assert!(
        !authority.ends_with(":443") && !authority.ends_with('.'),
        "{stored:?}"
    );
    assert_eq!(
        stored
            .parse::<VerificationOrigin>()
            .map(|o| o.as_str().to_owned()),
        Ok(stored.to_owned())
    );
}
