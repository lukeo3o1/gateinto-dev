use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use serde::de::{self, SeqAccess, Visitor};
use tracing::{debug, warn};

use super::os_user::{Denial, Owners};
use super::session_credentials::Verifier;
use super::{Status, authenticate};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalAuth {
    pub os_user: bool,
    pub session_credentials: bool,
}

impl LocalAuth {
    pub const NONE: Self = Self {
        os_user: false,
        session_credentials: false,
    };
    pub const SESSION_CREDENTIALS: Self = Self {
        os_user: false,
        session_credentials: true,
    };
    pub const OS_USER: Self = Self {
        os_user: true,
        session_credentials: false,
    };

    pub fn is_none(self) -> bool {
        self == Self::NONE
    }
}

impl Default for LocalAuth {
    fn default() -> Self {
        Self::SESSION_CREDENTIALS
    }
}

impl fmt::Display for LocalAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.os_user, self.session_credentials) {
            (false, false) => f.write_str("none"),
            (true, false) => f.write_str("os_user"),
            (false, true) => f.write_str("session_credentials"),
            (true, true) => f.write_str("os_user, session_credentials"),
        }
    }
}

const METHODS: &[&str] = if cfg!(windows) {
    &["none", "os_user", "session_credentials"]
} else {
    &["none", "session_credentials"]
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Method {
    None,
    OsUser,
    SessionCredentials,
}

impl Method {
    fn parse<E: de::Error>(name: &str) -> Result<Self, E> {
        match name {
            "none" => Ok(Self::None),
            "os_user" if cfg!(windows) => Ok(Self::OsUser),
            "os_user" => Err(E::custom("auth = \"os_user\" is only available on Windows")),
            "session_credentials" => Ok(Self::SessionCredentials),
            "basic_tofu" => Err(E::custom(
                "auth = \"basic_tofu\" was removed; use \"session_credentials\"",
            )),
            other => Err(E::unknown_variant(other, METHODS)),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::OsUser => "os_user",
            Self::SessionCredentials => "session_credentials",
        }
    }
}

struct MethodsVisitor;

impl<'de> Visitor<'de> for MethodsVisitor {
    type Value = LocalAuth;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a method name or a list of method names")
    }

    fn visit_str<E: de::Error>(self, name: &str) -> Result<LocalAuth, E> {
        Ok(match Method::parse(name)? {
            Method::None => LocalAuth::NONE,
            Method::OsUser => LocalAuth::OS_USER,
            Method::SessionCredentials => LocalAuth::SESSION_CREDENTIALS,
        })
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<LocalAuth, A::Error> {
        use de::Error as _;

        let mut methods = Vec::new();
        while let Some(name) = seq.next_element::<String>()? {
            let method = Method::parse(&name)?;
            if methods.contains(&method) {
                return Err(A::Error::custom(format!(
                    "auth lists \"{}\" more than once",
                    method.name()
                )));
            }
            methods.push(method);
        }
        if methods.is_empty() {
            return Err(A::Error::custom("auth must name at least one method"));
        }
        if methods.len() > 1 && methods.contains(&Method::None) {
            return Err(A::Error::custom(
                "auth = \"none\" cannot be combined with other methods",
            ));
        }
        Ok(LocalAuth {
            os_user: methods.contains(&Method::OsUser),
            session_credentials: methods.contains(&Method::SessionCredentials),
        })
    }
}

impl<'de> serde::Deserialize<'de> for LocalAuth {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(MethodsVisitor)
    }
}

pub(super) struct Authenticator {
    verifier: Option<Verifier>,
    owners: Option<Arc<dyn Owners>>,
    warned: AtomicBool,
}

impl Authenticator {
    pub(super) fn new(verifier: Option<Verifier>, owners: Option<Arc<dyn Owners>>) -> Self {
        Self {
            verifier,
            owners,
            warned: AtomicBool::new(false),
        }
    }

    #[cfg(test)]
    pub(super) fn with_owners(self, owners: Arc<dyn Owners>) -> Self {
        Self {
            owners: Some(owners),
            ..self
        }
    }

    pub(super) fn realm(&self) -> Option<&str> {
        self.verifier.as_ref().map(Verifier::realm)
    }

    pub(super) async fn os_user(
        &self,
        peer: io::Result<SocketAddr>,
        local: io::Result<SocketAddr>,
        deadline: tokio::time::Instant,
    ) -> Option<bool> {
        let Some(owners) = &self.owners else {
            return Some(false);
        };
        let checked = match (peer, local) {
            (Ok(peer), Ok(local)) => {
                let owners = owners.clone();
                let lookup = tokio::task::spawn_blocking(move || owners.check(peer, local));
                match tokio::time::timeout_at(deadline, lookup).await {
                    Ok(joined) => joined.unwrap_or_else(|_| {
                        Err(Denial::Lookup("the lookup task failed".to_owned()))
                    }),
                    Err(_) => {
                        self.report(&Denial::TimedOut);
                        return None;
                    }
                }
            }
            (Err(error), _) | (_, Err(error)) => Err(Denial::Lookup(error.to_string())),
        };
        match checked {
            Ok(()) => {
                debug!("os_user accepted the connection");
                Some(true)
            }
            Err(denial) => {
                self.report(&denial);
                Some(false)
            }
        }
    }

    fn report(&self, denial: &Denial) {
        if self.warned.swap(true, Ordering::Relaxed) {
            debug!("os_user denied the connection: {denial}");
        } else {
            warn!(
                "os_user denied the connection: {denial}; {}; later denials in this session are \
                 logged at debug level",
                self.fallback()
            );
        }
    }

    pub(super) fn check(
        &self,
        os_user: bool,
        authorization: Option<&[u8]>,
        now: Instant,
    ) -> Result<(), String> {
        if os_user {
            return Ok(());
        }
        match &self.verifier {
            Some(verifier) => authenticate(verifier, authorization, now)
                .map_err(|status| status.response_in(verifier.realm())),
            None if self.owners.is_some() => Err(Status::Forbidden.response()),
            None => Ok(()),
        }
    }

    fn fallback(&self) -> &'static str {
        if self.verifier.is_some() {
            "the session credentials still work: run `gateinto session credentials <session>`"
        } else {
            "add \"session_credentials\" to auth for a fallback"
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use aws_lc_rs::rand::SystemRandom;

    use super::super::FailureLimit;
    use super::super::os_user::tests::{Fake, fake};
    use super::super::session_credentials::{SessionCredentials, encode};
    use super::*;

    const LIMIT: FailureLimit = FailureLimit {
        max_failures: 2,
        window: Duration::from_secs(60),
    };

    const BOTH: LocalAuth = LocalAuth {
        os_user: true,
        session_credentials: true,
    };

    struct Setup {
        auth: Authenticator,
        fake: Arc<Fake>,
        basic: Option<String>,
    }

    fn setup(local: LocalAuth, verdict: Result<(), Denial>) -> Setup {
        let random = SystemRandom::new();
        let credentials = SessionCredentials::generate(&random).unwrap();
        let verifier = local
            .session_credentials
            .then(|| Verifier::new(&credentials, LIMIT, &random).unwrap());
        let fake = fake(verdict);
        let owners = local.os_user.then(|| fake.clone() as Arc<dyn Owners>);
        let pair = format!("{}:{}", credentials.username(), credentials.password());
        Setup {
            auth: Authenticator::new(verifier, owners),
            fake,
            basic: local
                .session_credentials
                .then(|| format!("Basic {}", encode(pair.as_bytes()))),
        }
    }

    fn addrs() -> (SocketAddr, SocketAddr) {
        (
            "127.0.0.1:50000".parse().unwrap(),
            "127.0.0.1:8080".parse().unwrap(),
        )
    }

    fn far() -> tokio::time::Instant {
        tokio::time::Instant::now() + Duration::from_secs(60)
    }

    async fn os_user(setup: &Setup) -> bool {
        let (peer, local) = addrs();
        setup
            .auth
            .os_user(Ok(peer), Ok(local), far())
            .await
            .expect("the lookup finished")
    }

    #[derive(Clone, Default)]
    struct Logs(Arc<std::sync::Mutex<Vec<u8>>>);

    impl io::Write for Logs {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Logs {
        fn capture(&self) -> tracing::subscriber::DefaultGuard {
            let logs = self.clone();
            tracing::subscriber::set_default(
                tracing_subscriber::fmt()
                    .with_max_level(tracing::Level::DEBUG)
                    .with_writer(move || logs.clone())
                    .finish(),
            )
        }

        fn lines(&self, level: &str) -> Vec<String> {
            String::from_utf8(self.0.lock().unwrap().clone())
                .unwrap()
                .lines()
                .filter(|line| line.contains(level))
                .map(str::to_owned)
                .collect()
        }
    }

    fn status(response: &str) -> u16 {
        response[9..12].parse().unwrap()
    }

    fn denials() -> [Denial; 4] {
        [
            Denial::NotFound,
            Denial::OtherUser,
            Denial::NotInJob,
            Denial::Lookup("access denied".to_owned()),
        ]
    }

    #[tokio::test]
    async fn the_same_user_passes_without_credentials() {
        for local in [LocalAuth::OS_USER, BOTH] {
            let setup = setup(local, Ok(()));
            assert!(os_user(&setup).await);
            assert_eq!(setup.auth.check(true, None, Instant::now()), Ok(()));
        }
    }

    #[tokio::test]
    async fn the_lookup_sees_the_peer_and_the_listener() {
        let setup = setup(LocalAuth::OS_USER, Ok(()));
        os_user(&setup).await;
        assert_eq!(*setup.fake.seen.lock().unwrap(), [addrs()]);
    }

    #[tokio::test]
    async fn an_unknown_address_is_a_denial_without_a_lookup() {
        let setup = setup(LocalAuth::OS_USER, Ok(()));
        let (peer, _) = addrs();
        let missing = || Err(io::Error::from(io::ErrorKind::NotConnected));
        assert_eq!(
            setup.auth.os_user(Ok(peer), missing(), far()).await,
            Some(false)
        );
        assert_eq!(
            setup.auth.os_user(missing(), Ok(peer), far()).await,
            Some(false)
        );
        assert!(setup.fake.seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn only_the_first_denial_of_a_session_is_a_warning() {
        let logs = Logs::default();
        let _guard = logs.capture();
        let setup = setup(BOTH, Err(Denial::OtherUser));
        for _ in 0..3 {
            assert!(!os_user(&setup).await);
        }
        let warnings = logs.lines(" WARN ");
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("another OS user"), "{warnings:?}");
        assert!(
            warnings[0].contains("gateinto session credentials"),
            "{warnings:?}"
        );
        let denied: Vec<_> = logs
            .lines(" DEBUG ")
            .into_iter()
            .filter(|line| line.contains("os_user denied"))
            .collect();
        assert_eq!(denied.len(), 2, "{denied:?}");
    }

    #[tokio::test]
    async fn a_lookup_past_the_deadline_is_a_logged_denial() {
        let logs = Logs::default();
        let _guard = logs.capture();
        let fake = super::super::os_user::tests::slow(Ok(()), Duration::from_secs(1));
        let auth = Authenticator::new(None, Some(fake as Arc<dyn Owners>));
        let (peer, local) = addrs();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(20);
        assert_eq!(auth.os_user(Ok(peer), Ok(local), deadline).await, None);
        let warnings = logs.lines(" WARN ");
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].contains("did not finish within the handshake timeout"),
            "{warnings:?}"
        );
        assert!(
            warnings[0].contains("add \"session_credentials\" to auth"),
            "{warnings:?}"
        );
    }

    #[tokio::test]
    async fn every_denial_falls_back_to_the_basic_challenge() {
        for denial in denials() {
            let setup = setup(BOTH, Err(denial));
            assert!(!os_user(&setup).await);
            let realm = setup.auth.realm().unwrap().to_owned();
            let response = setup.auth.check(false, None, Instant::now()).unwrap_err();
            assert_eq!(
                response,
                format!(
                    "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic \
                     realm=\"{realm}\", charset=\"UTF-8\"\r\nConnection: close\r\n\
                     Content-Length: 0\r\n\r\n"
                )
            );
            let basic = setup.basic.clone().unwrap();
            let checked = setup
                .auth
                .check(false, Some(basic.as_bytes()), Instant::now());
            assert_eq!(checked, Ok(()));
        }
    }

    #[tokio::test]
    async fn os_user_alone_forbids_every_denial_and_never_rate_limits() {
        for denial in denials() {
            let setup = setup(LocalAuth::OS_USER, Err(denial));
            for _ in 0..LIMIT.max_failures * 3 {
                assert!(!os_user(&setup).await);
                for authorization in [None, Some(&b"Basic dTpw"[..])] {
                    let response = setup
                        .auth
                        .check(false, authorization, Instant::now())
                        .unwrap_err();
                    assert_eq!(status(&response), 403, "{response}");
                    assert!(response.contains("Connection: close\r\n"), "{response}");
                }
            }
        }
    }

    #[tokio::test]
    async fn os_user_denials_do_not_count_toward_the_failure_limit() {
        let setup = setup(BOTH, Err(Denial::OtherUser));
        for _ in 0..LIMIT.max_failures * 3 {
            assert!(!os_user(&setup).await);
            let response = setup.auth.check(false, None, Instant::now()).unwrap_err();
            assert_eq!(status(&response), 407, "{response}");
        }
        let basic = setup.basic.clone().unwrap();
        let checked = setup
            .auth
            .check(false, Some(basic.as_bytes()), Instant::now());
        assert_eq!(checked, Ok(()));
    }

    #[tokio::test]
    async fn wrong_session_credentials_still_count_after_an_os_user_denial() {
        let setup = setup(BOTH, Err(Denial::NotFound));
        for _ in 0..LIMIT.max_failures {
            let response = setup
                .auth
                .check(false, Some(b"Basic dTpw"), Instant::now())
                .unwrap_err();
            assert_eq!(status(&response), 407, "{response}");
        }
        let basic = setup.basic.clone().unwrap();
        let response = setup
            .auth
            .check(false, Some(basic.as_bytes()), Instant::now())
            .unwrap_err();
        assert_eq!(status(&response), 429, "{response}");
    }

    #[tokio::test]
    async fn without_os_user_nothing_is_looked_up() {
        for local in [LocalAuth::SESSION_CREDENTIALS, LocalAuth::NONE] {
            let setup = setup(local, Ok(()));
            assert!(!os_user(&setup).await);
            assert!(setup.fake.seen.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn none_accepts_everything() {
        let setup = setup(LocalAuth::NONE, Ok(()));
        assert_eq!(setup.auth.check(false, None, Instant::now()), Ok(()));
        assert_eq!(
            setup.auth.check(false, Some(b"Basic !"), Instant::now()),
            Ok(())
        );
    }
}
