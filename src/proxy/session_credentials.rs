use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::error::Unspecified;
use aws_lc_rs::hmac;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};

use crate::http::is_token;

const MAX_ENCODED_BYTES: usize = 1024;

const ALPHABET: &[u8; 31] = b"abcdefghjkmnpqrstuvwxyz23456789";
const GROUP_LEN: usize = 4;
const USERNAME: &str = "gateinto";
const PASSWORD_GROUPS: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailureLimit {
    pub max_failures: u32,
    pub window: Duration,
}

impl Default for FailureLimit {
    fn default() -> Self {
        Self {
            max_failures: 10,
            window: Duration::from_secs(60),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SessionCredentials {
    username: String,
    password: String,
}

impl fmt::Debug for SessionCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionCredentials { .. }")
    }
}

impl SessionCredentials {
    pub(crate) fn generate(random: &SystemRandom) -> Result<Self, Unspecified> {
        Ok(Self {
            username: USERNAME.to_owned(),
            password: grouped(random, PASSWORD_GROUPS)?,
        })
    }

    pub fn parse(username: &str, password: &str) -> Option<Self> {
        (username == USERNAME && is_grouped(password, PASSWORD_GROUPS)).then(|| Self {
            username: username.to_owned(),
            password: password.to_owned(),
        })
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &str {
        &self.password
    }
}

fn grouped(random: &SystemRandom, groups: usize) -> Result<String, Unspecified> {
    let mut text = String::with_capacity(groups * (GROUP_LEN + 1));
    let mut filled = 0;
    let mut bytes = [0; 32];
    while filled < groups * GROUP_LEN {
        random.fill(&mut bytes)?;
        for symbol in bytes.iter().filter_map(|&byte| symbol(byte)) {
            if filled == groups * GROUP_LEN {
                break;
            }
            if filled > 0 && filled.is_multiple_of(GROUP_LEN) {
                text.push('-');
            }
            text.push(char::from(symbol));
            filled += 1;
        }
    }
    Ok(text)
}

fn is_grouped(text: &str, groups: usize) -> bool {
    let parts: Vec<&str> = text.split('-').collect();
    parts.len() == groups
        && parts
            .iter()
            .all(|part| part.len() == GROUP_LEN && part.bytes().all(|b| ALPHABET.contains(&b)))
}

fn symbol(byte: u8) -> Option<u8> {
    let usable = 256 - 256 % ALPHABET.len();
    let byte = usize::from(byte);
    (byte < usable).then(|| ALPHABET[byte % ALPHABET.len()])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Accepted,
    Challenge,
    Rejected,
    Malformed,
    RateLimited { retry_after: Duration },
}

pub(crate) struct Verifier {
    realm: String,
    key: hmac::Key,
    expected: hmac::Tag,
    limit: FailureLimit,
    failures: Mutex<Failures>,
}

#[derive(Default)]
struct Failures {
    since: Option<Instant>,
    count: u32,
}

pub(super) enum Rejection {
    Scheme,
    Malformed,
}

impl Verifier {
    pub(crate) fn new(
        credentials: &SessionCredentials,
        limit: FailureLimit,
        random: &SystemRandom,
    ) -> Result<Self, Unspecified> {
        let mut nonce = [0; 8];
        random.fill(&mut nonce)?;
        let nonce: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
        let key = hmac::Key::generate(hmac::HMAC_SHA256, random)?;
        let issued = format!("{}:{}", credentials.username, credentials.password);
        Ok(Self {
            realm: format!("Gateinto session {nonce}"),
            expected: hmac::sign(&key, issued.as_bytes()),
            key,
            limit,
            failures: Mutex::new(Failures::default()),
        })
    }

    pub(crate) fn realm(&self) -> &str {
        &self.realm
    }

    pub(crate) fn check(&self, authorization: Option<&[u8]>, now: Instant) -> Verdict {
        let mut failures = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(since) = failures.since
            && now.saturating_duration_since(since) >= self.limit.window
        {
            *failures = Failures::default();
        }
        if let Some(since) = failures.since
            && failures.count >= self.limit.max_failures
        {
            return Verdict::RateLimited {
                retry_after: (since + self.limit.window).saturating_duration_since(now),
            };
        }
        let Some(authorization) = authorization else {
            return Verdict::Challenge;
        };
        let verdict = match parse_basic(authorization) {
            Ok(credential) => {
                let tag = hmac::sign(&self.key, &credential);
                if verify_slices_are_equal(self.expected.as_ref(), tag.as_ref()).is_ok() {
                    return Verdict::Accepted;
                }
                Verdict::Rejected
            }
            Err(Rejection::Scheme) => Verdict::Challenge,
            Err(Rejection::Malformed) => Verdict::Malformed,
        };
        failures.since.get_or_insert(now);
        failures.count = failures.count.saturating_add(1);
        verdict
    }
}

#[cfg(any(test, fuzzing))]
pub(super) fn encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub(super) fn parse_basic(value: &[u8]) -> Result<Vec<u8>, Rejection> {
    let (scheme, token) = match value.iter().position(|&b| b == b' ') {
        Some(space) => (&value[..space], value[space..].trim_ascii_start()),
        None => (value, &b""[..]),
    };
    if !is_token(scheme) {
        return Err(Rejection::Malformed);
    }
    if !scheme.eq_ignore_ascii_case(b"basic") {
        return Err(Rejection::Scheme);
    }
    if token.len() > MAX_ENCODED_BYTES {
        return Err(Rejection::Malformed);
    }
    let credential = decode_base64(token).ok_or(Rejection::Malformed)?;
    let colon = credential
        .iter()
        .position(|&b| b == b':')
        .ok_or(Rejection::Malformed)?;
    if colon + 1 == credential.len() || credential.iter().any(|&b| b < 0x20 || b == 0x7f) {
        return Err(Rejection::Malformed);
    }
    Ok(credential)
}

fn decode_base64(encoded: &[u8]) -> Option<Vec<u8>> {
    if encoded.is_empty() || !encoded.len().is_multiple_of(4) {
        return None;
    }
    let padding = encoded.iter().rev().take_while(|&&b| b == b'=').count();
    if padding > 2 {
        return None;
    }
    let mut decoded = Vec::with_capacity(encoded.len() / 4 * 3);
    let last = encoded.len() / 4 - 1;
    for (index, quad) in encoded.as_chunks::<4>().0.iter().enumerate() {
        let pad = if index == last { padding } else { 0 };
        let mut bits = 0u32;
        for &byte in &quad[..4 - pad] {
            bits = bits << 6 | u32::from(sextet(byte)?);
        }
        bits <<= 6 * pad;
        let bytes = bits.to_be_bytes();
        let used = 3 - pad;
        if bytes[1 + used..].iter().any(|&b| b != 0) {
            return None;
        }
        decoded.extend_from_slice(&bytes[1..1 + used]);
    }
    Some(decoded)
}

fn sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_DECODED_BYTES: usize = MAX_ENCODED_BYTES / 4 * 3;

    const LIMIT: FailureLimit = FailureLimit {
        max_failures: 3,
        window: Duration::from_secs(60),
    };

    const ROOMY: FailureLimit = FailureLimit {
        max_failures: 1000,
        window: Duration::from_secs(60),
    };

    fn basic(credential: &str) -> Vec<u8> {
        format!("Basic {}", encode(credential.as_bytes())).into_bytes()
    }

    fn issued() -> SessionCredentials {
        SessionCredentials::generate(&SystemRandom::new()).unwrap()
    }

    fn verifier(credentials: &SessionCredentials, limit: FailureLimit) -> Verifier {
        Verifier::new(credentials, limit, &SystemRandom::new()).unwrap()
    }

    fn right(credentials: &SessionCredentials) -> Vec<u8> {
        basic(&format!(
            "{}:{}",
            credentials.username(),
            credentials.password()
        ))
    }

    fn check(verifier: &Verifier, header: &[u8]) -> Verdict {
        verifier.check(Some(header), Instant::now())
    }

    fn assert_grouped(text: &str, groups: usize) {
        let parts: Vec<&str> = text.split('-').collect();
        assert_eq!(parts.len(), groups, "{text}");
        for part in parts {
            assert_eq!(part.len(), GROUP_LEN, "{text}");
            assert!(part.bytes().all(|b| ALPHABET.contains(&b)), "{text}");
        }
    }

    #[test]
    fn the_alphabet_is_lowercase_without_ambiguous_symbols() {
        let mut sorted = ALPHABET.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ALPHABET.len());
        for byte in ALPHABET {
            assert!(byte.is_ascii_lowercase() || byte.is_ascii_digit());
            assert!(!b"0o1li".contains(byte), "{}", char::from(*byte));
        }
    }

    #[test]
    fn the_password_carries_about_59_bits() {
        let symbols = GROUP_LEN * PASSWORD_GROUPS;
        let bits = symbols as f64 * (ALPHABET.len() as f64).log2();
        assert!((59.0..60.0).contains(&bits), "{bits}");
    }

    #[test]
    fn random_bytes_map_uniformly_onto_the_alphabet() {
        let mut counts = [0; 31];
        let mut rejected = 0;
        for byte in 0..=u8::MAX {
            match symbol(byte) {
                Some(symbol) => {
                    let index = ALPHABET.iter().position(|&b| b == symbol).unwrap();
                    counts[index] += 1;
                }
                None => rejected += 1,
            }
        }
        assert_eq!(counts, [8; 31]);
        assert_eq!(rejected, 256 % ALPHABET.len());
    }

    #[test]
    fn generated_credentials_have_the_fixed_username_and_a_fresh_grouped_password() {
        let first = issued();
        assert_eq!(first.username(), "gateinto");
        assert_grouped(first.password(), PASSWORD_GROUPS);
        let second = issued();
        assert_eq!(second.username(), "gateinto");
        assert_ne!(first.password(), second.password());
    }

    #[test]
    fn only_well_formed_credentials_are_parsed() {
        let credentials = issued();
        let (user, pass) = (credentials.username(), credentials.password());
        assert_eq!(
            SessionCredentials::parse(user, pass),
            Some(credentials.clone())
        );
        for (user, pass) in [
            (pass, user),
            (&user.to_uppercase()[..], pass),
            ("k7mp-2xqa", pass),
            (&format!("{user} ")[..], pass),
            (&format!("{user}x")[..], pass),
            (user, &pass.replace('-', "")[..]),
            (user, &format!("{pass}-abcd")[..]),
            (user, &format!("{pass} ")[..]),
            (
                user,
                &pass.replacen(|c: char| c.is_ascii_alphanumeric(), "l", 1)[..],
            ),
            ("", pass),
            (user, ""),
        ] {
            assert_eq!(SessionCredentials::parse(user, pass), None, "{user} {pass}");
        }
    }

    #[test]
    fn debug_output_redacts_the_credentials() {
        let credentials = issued();
        let debug = format!("{credentials:?}");
        assert!(!debug.contains(credentials.username()), "{debug}");
        assert!(!debug.contains(credentials.password()), "{debug}");
    }

    #[test]
    fn the_test_encoder_matches_rfc_4648_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(plain.as_bytes()), encoded);
        }
    }

    #[test]
    fn decodes_rfc_4648_vectors() {
        for (plain, encoded) in [
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(
                decode_base64(encoded.as_bytes()),
                Some(plain.as_bytes().to_vec())
            );
        }
    }

    #[test]
    fn rejects_non_canonical_base64() {
        for encoded in [
            "", "Zg", "Zg=", "Zh==", "Zm9=", "Z===", "Zg==Zg==", "Zm9v\n", "Zm 9v", "Zm9-", "Zm9_",
            "=Zm9", "Zm=v",
        ] {
            assert_eq!(decode_base64(encoded.as_bytes()), None, "{encoded:?}");
        }
    }

    #[test]
    fn missing_credentials_are_challenged() {
        let verifier = verifier(&issued(), LIMIT);
        assert_eq!(verifier.check(None, Instant::now()), Verdict::Challenge);
    }

    #[test]
    fn the_realm_names_gateinto_and_differs_per_session() {
        let credentials = issued();
        let first = verifier(&credentials, LIMIT);
        let second = verifier(&credentials, LIMIT);
        assert!(first.realm().starts_with("Gateinto "), "{}", first.realm());
        assert_ne!(first.realm(), second.realm());
        assert!(
            first
                .realm()
                .bytes()
                .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\' || b == b' '),
            "{}",
            first.realm()
        );
    }

    #[test]
    fn only_the_issued_credentials_are_accepted() {
        let credentials = issued();
        let verifier = verifier(&credentials, ROOMY);
        let (user, pass) = (credentials.username(), credentials.password());
        for wrong in [
            format!("{user}:{}", issued().password()),
            format!("k7mp-2xqa:{pass}"),
            format!("Gateinto:{pass}"),
            format!("{pass}:{user}"),
            format!("{}:{pass}", user.to_uppercase()),
            format!("{user}:{}", pass.replace('-', "")),
            format!("{user}:{pass} "),
            format!("{user}:{pass}:"),
            format!("{user}x:{pass}"),
        ] {
            assert_eq!(
                check(&verifier, &basic(&wrong)),
                Verdict::Rejected,
                "{wrong}"
            );
        }
        assert_eq!(check(&verifier, &right(&credentials)), Verdict::Accepted);
        assert_eq!(check(&verifier, &right(&credentials)), Verdict::Accepted);
    }

    #[test]
    fn an_unknown_first_credential_binds_nothing() {
        let credentials = issued();
        let verifier = verifier(&credentials, ROOMY);
        assert_eq!(check(&verifier, &basic("alice:first")), Verdict::Rejected);
        assert_eq!(check(&verifier, &basic("alice:first")), Verdict::Rejected);
        assert_eq!(check(&verifier, &right(&credentials)), Verdict::Accepted);
    }

    #[test]
    fn credentials_of_another_session_are_rejected() {
        let mine = issued();
        let theirs = issued();
        let verifier = verifier(&mine, ROOMY);
        assert_eq!(check(&verifier, &right(&theirs)), Verdict::Rejected);
        assert_eq!(check(&verifier, &right(&mine)), Verdict::Accepted);
    }

    #[test]
    fn the_scheme_is_case_insensitive() {
        let credentials = issued();
        let verifier = verifier(&credentials, LIMIT);
        let token =
            encode(format!("{}:{}", credentials.username(), credentials.password()).as_bytes());
        for header in [format!("bAsIc {token}"), format!("BASIC {token}")] {
            assert_eq!(check(&verifier, header.as_bytes()), Verdict::Accepted);
        }
    }

    #[test]
    fn other_schemes_are_challenged() {
        let verifier = verifier(&issued(), ROOMY);
        for header in [
            &b"Bearer abc"[..],
            b"Negotiate",
            b"Digest username=\"u\"",
            b"Basicx dTpw",
        ] {
            assert_eq!(check(&verifier, header), Verdict::Challenge);
        }
    }

    #[test]
    fn malformed_basic_credentials_are_rejected() {
        let verifier = verifier(&issued(), ROOMY);
        let long = format!("u:{}", "p".repeat(MAX_DECODED_BYTES));
        for header in [
            b"Basic".to_vec(),
            b"Basic ".to_vec(),
            b"Basic dTpw=".to_vec(),
            b"Basic dTpw extra".to_vec(),
            b"Basic\tdTpw".to_vec(),
            basic("no-colon"),
            basic("user:"),
            basic("u:p\x00"),
            basic("u:p\r\nX: y"),
            basic("u\x7f:p"),
            basic(&long),
        ] {
            assert_eq!(
                check(&verifier, &header),
                Verdict::Malformed,
                "{}",
                String::from_utf8_lossy(&header)
            );
        }
        assert_eq!(check(&verifier, &basic(":p")), Verdict::Rejected);
    }

    #[test]
    fn utf8_and_long_passwords_are_compared_not_refused() {
        let verifier = verifier(&issued(), ROOMY);
        assert_eq!(
            check(&verifier, &basic("j\u{f6}rg:p:a:ss \u{e9}")),
            Verdict::Rejected
        );
        let longest = format!("u:{}", "p".repeat(MAX_DECODED_BYTES - 2));
        assert_eq!(check(&verifier, &basic(&longest)), Verdict::Rejected);
    }

    #[test]
    fn failures_beyond_the_limit_are_rate_limited_until_the_window_ends() {
        let credentials = issued();
        let verifier = verifier(&credentials, LIMIT);
        let right = right(&credentials);
        let start = Instant::now();
        assert_eq!(verifier.check(Some(&right), start), Verdict::Accepted);
        assert_eq!(
            verifier.check(Some(&basic("u:wrong")), start),
            Verdict::Rejected
        );
        assert_eq!(verifier.check(Some(b"Basic !"), start), Verdict::Malformed);
        assert_eq!(
            verifier.check(None, start),
            Verdict::Challenge,
            "not a failure"
        );
        let third = start + Duration::from_secs(10);
        assert_eq!(verifier.check(Some(b"Bearer x"), third), Verdict::Challenge);

        let limited = start + Duration::from_secs(15);
        for header in [None, Some(&right[..]), Some(&basic("u:wrong")[..])] {
            assert_eq!(
                verifier.check(header, limited),
                Verdict::RateLimited {
                    retry_after: Duration::from_secs(45)
                }
            );
        }
        let last = start + LIMIT.window - Duration::from_millis(1);
        assert!(matches!(
            verifier.check(Some(&right), last),
            Verdict::RateLimited { .. }
        ));

        let reset = start + LIMIT.window;
        assert_eq!(verifier.check(Some(&right), reset), Verdict::Accepted);
        assert_eq!(
            verifier.check(Some(&basic("u:wrong")), reset),
            Verdict::Rejected
        );
        assert_eq!(verifier.check(Some(&right), reset), Verdict::Accepted);
    }

    #[test]
    fn rate_limiting_does_not_accept_the_issued_credentials_after_a_flood() {
        let credentials = issued();
        let verifier = verifier(&credentials, LIMIT);
        let now = Instant::now();
        for _ in 0..LIMIT.max_failures {
            verifier.check(Some(&basic("u:guess")), now);
        }
        assert!(matches!(
            verifier.check(Some(&right(&credentials)), now),
            Verdict::RateLimited { .. }
        ));
    }
}
