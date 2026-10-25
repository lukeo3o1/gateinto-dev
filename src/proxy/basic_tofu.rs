use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::error::Unspecified;
use aws_lc_rs::hmac;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};

use super::session_credentials::{FailureLimit, Rejection, parse_basic};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Bound,
    Accepted,
    Challenge,
    Rejected,
    Malformed,
    RateLimited { retry_after: std::time::Duration },
}

pub(crate) struct BasicTofu {
    realm: String,
    key: hmac::Key,
    bound: OnceLock<hmac::Tag>,
    limit: FailureLimit,
    failures: Mutex<Failures>,
}

#[derive(Default)]
struct Failures {
    since: Option<Instant>,
    count: u32,
}

impl BasicTofu {
    pub(crate) fn new(limit: FailureLimit) -> Result<Self, Unspecified> {
        let random = SystemRandom::new();
        let mut nonce = [0; 8];
        random.fill(&mut nonce)?;
        let nonce: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(Self {
            realm: format!("Gateinto session {nonce}"),
            key: hmac::Key::generate(hmac::HMAC_SHA256, &random)?,
            bound: OnceLock::new(),
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
                if self.bound.set(tag).is_ok() {
                    return Verdict::Bound;
                }
                let bound = self.bound.get().expect("set above if it was empty");
                if verify_slices_are_equal(bound.as_ref(), tag.as_ref()).is_ok() {
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    const MAX_DECODED_BYTES: usize = 768;

    const LIMIT: FailureLimit = FailureLimit {
        max_failures: 3,
        window: Duration::from_secs(60),
    };

    fn basic(credential: &str) -> Vec<u8> {
        format!("Basic {}", encode(credential.as_bytes())).into_bytes()
    }

    fn encode(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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

    fn check(tofu: &BasicTofu, header: &[u8]) -> Verdict {
        tofu.check(Some(header), Instant::now())
    }

    #[test]
    fn missing_credentials_are_challenged() {
        let tofu = BasicTofu::new(LIMIT).unwrap();
        assert_eq!(tofu.check(None, Instant::now()), Verdict::Challenge);
    }

    #[test]
    fn the_realm_names_gateinto_and_differs_per_session() {
        let first = BasicTofu::new(LIMIT).unwrap();
        let second = BasicTofu::new(LIMIT).unwrap();
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
    fn the_first_credential_binds_and_only_it_is_accepted_afterwards() {
        let tofu = BasicTofu::new(LIMIT).unwrap();
        assert_eq!(check(&tofu, &basic("alice:first")), Verdict::Bound);
        assert_eq!(check(&tofu, &basic("alice:first")), Verdict::Accepted);
        assert_eq!(check(&tofu, &basic("alice:other")), Verdict::Rejected);
        assert_eq!(check(&tofu, &basic("bob:first")), Verdict::Rejected);
        assert_eq!(check(&tofu, &basic("alice:first")), Verdict::Accepted);
    }

    #[test]
    fn the_scheme_is_case_insensitive() {
        let tofu = BasicTofu::new(LIMIT).unwrap();
        let token = encode(b"u:p");
        assert_eq!(
            check(&tofu, format!("bAsIc {token}").as_bytes()),
            Verdict::Bound
        );
        assert_eq!(
            check(&tofu, format!("BASIC {token}").as_bytes()),
            Verdict::Accepted
        );
    }

    #[test]
    fn other_schemes_are_challenged() {
        let tofu = BasicTofu::new(FailureLimit {
            max_failures: 100,
            window: Duration::from_secs(60),
        })
        .unwrap();
        for header in [
            &b"Bearer abc"[..],
            b"Negotiate",
            b"Digest username=\"u\"",
            b"Basicx dTpw",
        ] {
            assert_eq!(check(&tofu, header), Verdict::Challenge);
        }
        assert_eq!(
            check(&tofu, &basic("u:p")),
            Verdict::Bound,
            "nothing was bound"
        );
    }

    #[test]
    fn malformed_basic_credentials_are_rejected_without_binding() {
        let limit = FailureLimit {
            max_failures: 100,
            window: Duration::from_secs(60),
        };
        let tofu = BasicTofu::new(limit).unwrap();
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
                check(&tofu, &header),
                Verdict::Malformed,
                "{}",
                String::from_utf8_lossy(&header)
            );
        }
        assert_eq!(check(&tofu, &basic(":p")), Verdict::Bound);
    }

    #[test]
    fn accepts_utf8_and_colons_in_the_password() {
        let tofu = BasicTofu::new(LIMIT).unwrap();
        assert_eq!(
            check(&tofu, &basic("j\u{f6}rg:p:a:ss \u{e9}")),
            Verdict::Bound
        );
        let longest = format!("u:{}", "p".repeat(MAX_DECODED_BYTES - 2));
        let tofu = BasicTofu::new(LIMIT).unwrap();
        assert_eq!(check(&tofu, &basic(&longest)), Verdict::Bound);
    }

    #[test]
    fn concurrent_first_credentials_bind_exactly_one() {
        for _ in 0..20 {
            let tofu = BasicTofu::new(FailureLimit {
                max_failures: 1000,
                window: Duration::from_secs(60),
            })
            .unwrap();
            let barrier = std::sync::Barrier::new(16);
            let accepted: Vec<usize> = std::thread::scope(|scope| {
                let handles: Vec<_> = (0..16)
                    .map(|i| {
                        let (tofu, barrier) = (&tofu, &barrier);
                        scope.spawn(move || {
                            barrier.wait();
                            check(tofu, &basic(&format!("u:{i}")))
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .enumerate()
                    .filter_map(|(i, handle)| {
                        (handle.join().unwrap() == Verdict::Bound).then_some(i)
                    })
                    .collect()
            });
            assert_eq!(accepted.len(), 1, "{accepted:?}");
            let winner = accepted[0];
            for i in 0..16 {
                let expected = if i == winner {
                    Verdict::Accepted
                } else {
                    Verdict::Rejected
                };
                assert_eq!(check(&tofu, &basic(&format!("u:{i}"))), expected);
            }
        }
    }

    #[test]
    fn failures_beyond_the_limit_are_rate_limited_until_the_window_ends() {
        let tofu = BasicTofu::new(LIMIT).unwrap();
        let start = Instant::now();
        assert_eq!(tofu.check(Some(&basic("u:right")), start), Verdict::Bound);
        assert_eq!(
            tofu.check(Some(&basic("u:wrong")), start),
            Verdict::Rejected
        );
        assert_eq!(tofu.check(Some(b"Basic !"), start), Verdict::Malformed);
        assert_eq!(tofu.check(None, start), Verdict::Challenge, "not a failure");
        let third = start + Duration::from_secs(10);
        assert_eq!(tofu.check(Some(b"Bearer x"), third), Verdict::Challenge);

        let limited = start + Duration::from_secs(15);
        for header in [
            None,
            Some(&basic("u:right")[..]),
            Some(&basic("u:wrong")[..]),
        ] {
            assert_eq!(
                tofu.check(header, limited),
                Verdict::RateLimited {
                    retry_after: Duration::from_secs(45)
                }
            );
        }
        let last = start + LIMIT.window - Duration::from_millis(1);
        assert!(matches!(
            tofu.check(Some(&basic("u:right")), last),
            Verdict::RateLimited { .. }
        ));

        let reset = start + LIMIT.window;
        assert_eq!(
            tofu.check(Some(&basic("u:right")), reset),
            Verdict::Accepted
        );
        assert_eq!(
            tofu.check(Some(&basic("u:wrong")), reset),
            Verdict::Rejected
        );
        assert_eq!(
            tofu.check(Some(&basic("u:right")), reset),
            Verdict::Accepted
        );
    }

    #[test]
    fn rate_limiting_does_not_accept_the_bound_credential_after_a_flood() {
        let tofu = BasicTofu::new(LIMIT).unwrap();
        let now = Instant::now();
        assert_eq!(tofu.check(Some(&basic("u:right")), now), Verdict::Bound);
        for _ in 0..LIMIT.max_failures {
            tofu.check(Some(&basic("u:guess")), now);
        }
        assert!(matches!(
            tofu.check(Some(&basic("u:right")), now),
            Verdict::RateLimited { .. }
        ));
    }
}
