use std::time::Instant;

use aws_lc_rs::error::Unspecified;

use super::basic_tofu::{BasicTofu, parse_basic};
use super::{FailureLimit, HeadError, authorize};
use crate::http::parse_connect_request;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Incomplete,
    Tunnel { bound: bool },
    Reject(String),
}

pub struct LocalAuthSession(BasicTofu);

impl LocalAuthSession {
    pub fn new(limit: FailureLimit) -> Result<Self, Unspecified> {
        BasicTofu::new(limit).map(Self)
    }

    pub fn realm(&self) -> &str {
        self.0.realm()
    }

    pub fn respond(&self, buf: &[u8], max_header_bytes: usize, now: Instant) -> Outcome {
        let request = match parse_connect_request(buf, max_header_bytes) {
            Ok(None) => return Outcome::Incomplete,
            Ok(Some(parsed)) => parsed.value,
            Err(error) => {
                return Outcome::Reject(HeadError::Parse(error).local_status().response());
            }
        };
        match authorize(&self.0, request.proxy_authorization.as_deref(), now) {
            Ok(bound) => Outcome::Tunnel { bound },
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
    fn follows_the_proxy_answers_for_a_basic_tofu_session() {
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
            respond(&session, &request(Some("Basic dTpw"))),
            Outcome::Tunnel { bound: true }
        );
        assert_eq!(
            respond(&session, &request(Some("basic dTpw"))),
            Outcome::Tunnel { bound: false }
        );
        assert_eq!(
            rejected_status(respond(&session, &request(Some("Basic dTpx")))),
            407
        );
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
        assert_eq!(rejected_status(respond(&session, &request(None))), 429);
    }

    #[test]
    fn exposes_the_basic_credential_parser() {
        assert_eq!(basic_credential(b"Basic dTpw"), Some(b"u:p".to_vec()));
        assert_eq!(basic_credential(b"Basic dXNlcg=="), None);
        assert_eq!(basic_credential(b"Bearer dTpw"), None);
    }
}
