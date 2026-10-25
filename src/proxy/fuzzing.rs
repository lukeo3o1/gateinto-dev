use std::time::Instant;

use aws_lc_rs::error::Unspecified;
use aws_lc_rs::rand::SystemRandom;

use super::session_credentials::{Verifier, encode, parse_basic};
use super::{FailureLimit, HeadError, SessionCredentials, authenticate};
use crate::http::parse_connect_request;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Incomplete,
    Tunnel,
    Reject(String),
}

pub struct LocalAuthSession {
    credentials: SessionCredentials,
    verifier: Verifier,
}

impl LocalAuthSession {
    pub fn new(limit: FailureLimit) -> Result<Self, Unspecified> {
        let random = SystemRandom::new();
        let credentials = SessionCredentials::generate(&random)?;
        let verifier = Verifier::new(&credentials, limit, &random)?;
        Ok(Self {
            credentials,
            verifier,
        })
    }

    pub fn realm(&self) -> &str {
        self.verifier.realm()
    }

    pub fn issued_authorization(&self) -> String {
        let credentials = &self.credentials;
        let pair = format!("{}:{}", credentials.username(), credentials.password());
        format!("Basic {}", encode(pair.as_bytes()))
    }

    pub fn respond(&self, buf: &[u8], max_header_bytes: usize, now: Instant) -> Outcome {
        let request = match parse_connect_request(buf, max_header_bytes) {
            Ok(None) => return Outcome::Incomplete,
            Ok(Some(parsed)) => parsed.value,
            Err(error) => {
                return Outcome::Reject(HeadError::Parse(error).local_status().response());
            }
        };
        match authenticate(&self.verifier, request.proxy_authorization.as_deref(), now) {
            Ok(()) => Outcome::Tunnel,
            Err(status) => Outcome::Reject(status.response_in(self.realm())),
        }
    }
}

pub fn basic_credential(value: &[u8]) -> Option<Vec<u8>> {
    parse_basic(value).ok()
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::http::DEFAULT_MAX_HEADER_BYTES;

    const HEAD: &[u8] = b"CONNECT a.test:443 HTTP/1.1\r\nHost: a.test:443\r\n";

    fn request(authorization: Option<&str>) -> Vec<u8> {
        let mut head = HEAD.to_vec();
        if let Some(value) = authorization {
            head.extend_from_slice(format!("Proxy-Authorization: {value}\r\n").as_bytes());
        }
        head.extend_from_slice(b"\r\n");
        head
    }

    fn respond(session: &LocalAuthSession, buf: &[u8]) -> Outcome {
        session.respond(buf, DEFAULT_MAX_HEADER_BYTES, Instant::now())
    }

    fn rejected_status(outcome: Outcome) -> u16 {
        match outcome {
            Outcome::Reject(response) => response[9..12].parse().unwrap(),
            other => panic!("{other:?}"),
        }
    }

    fn session(max_failures: u32) -> LocalAuthSession {
        LocalAuthSession::new(FailureLimit {
            max_failures,
            window: Duration::from_secs(60),
        })
        .unwrap()
    }

    #[test]
    fn follows_the_proxy_answers_for_a_session_credentials_session() {
        let session = session(100);
        assert_eq!(respond(&session, &HEAD[..10]), Outcome::Incomplete);
        let challenge = respond(&session, &request(None));
        let Outcome::Reject(response) = &challenge else {
            panic!("{challenge:?}");
        };
        assert!(
            response.contains(&format!("realm=\"{}\"", session.realm())),
            "{response}"
        );
        assert_eq!(rejected_status(challenge), 407);
        assert_eq!(
            rejected_status(respond(&session, b"GET / HTTP/1.1\r\n\r\n")),
            405
        );
        assert_eq!(
            rejected_status(respond(&session, &request(Some("Basic !")))),
            400
        );
        assert_eq!(
            rejected_status(respond(&session, &request(Some("Basic dTpw")))),
            407
        );
        let issued = session.issued_authorization();
        let token = issued.strip_prefix("Basic ").unwrap();
        assert_eq!(basic_credential(issued.as_bytes()).unwrap().len(), 24);
        for header in [issued.clone(), format!("bAsIc {token}")] {
            assert_eq!(respond(&session, &request(Some(&header))), Outcome::Tunnel);
        }
        let oversized = session.respond(&request(None), 16, Instant::now());
        assert_eq!(rejected_status(oversized), 431);
    }

    #[test]
    fn reports_rate_limiting() {
        let session = session(1);
        assert_eq!(
            rejected_status(respond(&session, &request(Some("Basic !")))),
            400
        );
        let issued = session.issued_authorization();
        assert_eq!(
            rejected_status(respond(&session, &request(Some(&issued)))),
            429
        );
    }

    #[test]
    fn exposes_the_basic_credential_parser() {
        assert_eq!(basic_credential(b"Basic dTpw"), Some(b"u:p".to_vec()));
        assert_eq!(basic_credential(b"Basic dXNlcg=="), None);
        assert_eq!(basic_credential(b"Bearer dTpw"), None);
    }
}
