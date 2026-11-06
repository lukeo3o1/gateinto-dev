use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use tokio::task::AbortHandle;
use tokio::time::{Instant, sleep_until};
use zeroize::Zeroizing;

use super::challenge::Challenge;
use crate::http::Authority;
use crate::identity::client_cert::ClientCertificate;
use crate::identity::encoding::sha256_fingerprint;

pub(crate) const MAX_TARGETS: usize = 8;
pub(crate) const MAX_PENDING: usize = 16;

#[derive(Debug, Clone, Default)]
pub struct PendingVerifications(Arc<AtomicUsize>);

impl PendingVerifications {
    pub fn count(&self) -> usize {
        self.0.load(Ordering::Acquire)
    }

    fn reserve(&self) -> Option<AgentSlot> {
        let mut count = self.0.load(Ordering::Acquire);
        while count < MAX_PENDING {
            match self.0.compare_exchange_weak(
                count,
                count + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(AgentSlot(self.0.clone())),
                Err(actual) => count = actual,
            }
        }
        None
    }
}

struct AgentSlot(Arc<AtomicUsize>);

impl Drop for AgentSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(crate) struct Refusal {
    pub(crate) fingerprint: String,
    pub(crate) challenge: Challenge,
}

impl fmt::Debug for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Refusal(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Offer {
    Pending,
    Added,
    Counted,
    Stale,
    Suppressed,
    AgentLimit,
}

pub struct Verification {
    pub serial: u64,
    pub origin: Zeroizing<String>,
    pub auth_uri: Zeroizing<String>,
    pub user_code: Zeroizing<String>,
    pub expires_in: u64,
    pub targets: Vec<String>,
    pub more_targets: u64,
    pub suppressed: u64,
}

impl fmt::Debug for Verification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verification")
            .field("serial", &self.serial)
            .field("expires_in", &self.expires_in)
            .field("targets", &self.targets.len())
            .field("more_targets", &self.more_targets)
            .field("suppressed", &self.suppressed)
            .finish_non_exhaustive()
    }
}

struct Entry {
    serial: u64,
    fingerprint: String,
    challenge: Challenge,
    deadline: Instant,
    targets: Vec<String>,
    more_targets: u64,
    suppressed: u64,
    timer: AbortHandle,
    _slot: AgentSlot,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.timer.abort();
    }
}

#[derive(Default)]
struct State {
    next_serial: u64,
    pending: Option<Entry>,
    suppressed: u64,
}

struct Inner {
    certificate: Option<ClientCertificate>,
    agent: PendingVerifications,
    state: Mutex<State>,
}

impl Inner {
    fn current_fingerprint(&self) -> Option<String> {
        let leaf = match self.certificate.as_ref()? {
            ClientCertificate::Fixed(key) => key.cert.first()?.clone(),
            ClientCertificate::SelfSigned { certificates, .. } => {
                certificates.current().cert.first()?.clone()
            }
        };
        Some(sha256_fingerprint(&leaf))
    }

    fn lock(&self, now: Instant) -> (MutexGuard<'_, State>, Option<String>) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let current = self.current_fingerprint();
        let stale = state.pending.as_ref().is_some_and(|entry| {
            now >= entry.deadline || current.as_deref() != Some(entry.fingerprint.as_str())
        });
        if stale {
            state.pending = None;
        }
        (state, current)
    }
}

#[derive(Clone)]
pub struct Verifications(Arc<Inner>);

impl fmt::Debug for Verifications {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Verifications(<redacted>)")
    }
}

impl Verifications {
    pub(crate) fn new(certificate: Option<ClientCertificate>, agent: PendingVerifications) -> Self {
        Self(Arc::new(Inner {
            certificate,
            agent,
            state: Mutex::default(),
        }))
    }

    pub(crate) fn offer(&self, refusal: Refusal, target: &Authority) -> Offer {
        self.offer_at(refusal, target, Instant::now())
    }

    fn offer_at(&self, refusal: Refusal, target: &Authority, now: Instant) -> Offer {
        let (mut state, current) = self.0.lock(now);
        if current.as_deref() != Some(refusal.fingerprint.as_str()) {
            return Offer::Stale;
        }
        let target = target.to_string();
        if let Some(entry) = state.pending.as_mut() {
            let identical = entry.challenge.auth_uri() == refusal.challenge.auth_uri()
                && entry.challenge.user_code() == refusal.challenge.user_code();
            if !identical {
                entry.suppressed += 1;
                return Offer::Suppressed;
            }
            if entry.targets.contains(&target) {
                return Offer::Added;
            }
            if entry.targets.len() < MAX_TARGETS {
                entry.targets.push(target);
                return Offer::Added;
            }
            entry.more_targets += 1;
            return Offer::Counted;
        }
        let Some(slot) = self.0.agent.reserve() else {
            state.suppressed += 1;
            return Offer::AgentLimit;
        };
        state.next_serial += 1;
        let serial = state.next_serial;
        let deadline = now + Duration::from_secs(refusal.challenge.expires_in());
        let suppressed = std::mem::take(&mut state.suppressed);
        let inner = Arc::downgrade(&self.0);
        let timer = tokio::spawn(expire(inner, serial, deadline)).abort_handle();
        state.pending = Some(Entry {
            serial,
            fingerprint: refusal.fingerprint,
            challenge: refusal.challenge,
            deadline,
            targets: vec![target],
            more_targets: 0,
            suppressed,
            timer,
            _slot: slot,
        });
        Offer::Pending
    }

    pub fn pending(&self) -> bool {
        self.0.lock(Instant::now()).0.pending.is_some()
    }

    pub fn get(&self) -> Option<Verification> {
        self.get_at(Instant::now())
    }

    fn get_at(&self, now: Instant) -> Option<Verification> {
        let (state, _) = self.0.lock(now);
        let entry = state.pending.as_ref()?;
        let remaining = entry.deadline - now;
        Some(Verification {
            serial: entry.serial,
            origin: Zeroizing::new(entry.challenge.origin().to_owned()),
            auth_uri: Zeroizing::new(entry.challenge.auth_uri().to_owned()),
            user_code: Zeroizing::new(entry.challenge.user_code().to_owned()),
            expires_in: remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0),
            targets: entry.targets.clone(),
            more_targets: entry.more_targets,
            suppressed: entry.suppressed,
        })
    }

    pub fn dismiss(&self, serial: u64) -> bool {
        let (mut state, _) = self.0.lock(Instant::now());
        let matches = state
            .pending
            .as_ref()
            .is_some_and(|entry| entry.serial == serial);
        if matches {
            state.pending = None;
        }
        matches
    }

    pub fn clear(&self) {
        let mut state = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
        state.pending = None;
        state.suppressed = 0;
    }
}

async fn expire(inner: Weak<Inner>, serial: u64, deadline: Instant) {
    sleep_until(deadline).await;
    let Some(inner) = inner.upgrade() else {
        return;
    };
    let mut state = inner.state.lock().unwrap_or_else(|e| e.into_inner());
    if state
        .pending
        .as_ref()
        .is_some_and(|entry| entry.serial == serial)
    {
        state.pending = None;
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
    use rustls::pki_types::{PrivatePkcs8KeyDer, UnixTime};

    use super::*;
    use crate::identity::certificates::{DeviceSigner, RENEW_AFTER, SelfSignedCertificates};
    use crate::identity::encoding::sha256_fingerprint;
    use crate::proxy::challenge;

    fn self_signed() -> (ClientCertificate, Arc<SelfSignedCertificates>) {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .unwrap();
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref()).unwrap();
        let point = pair.public_key().as_ref().try_into().unwrap();
        let der = PrivatePkcs8KeyDer::from(pkcs8.as_ref().to_vec()).into();
        let key = rustls::crypto::aws_lc_rs::sign::any_ecdsa_type(&der).unwrap();
        let certificates = Arc::new(
            SelfSignedCertificates::new(DeviceSigner::new(point, key), UnixTime::now()).unwrap(),
        );
        let certificate = ClientCertificate::SelfSigned {
            certificates: certificates.clone(),
            required: true,
        };
        (certificate, certificates)
    }

    fn fingerprint(certificates: &SelfSignedCertificates) -> String {
        sha256_fingerprint(&certificates.current().cert[0])
    }

    fn renew(certificates: &SelfSignedCertificates) {
        let later = UnixTime::now().as_secs() + RENEW_AFTER.as_secs() + 1;
        certificates
            .certified_key_at(UnixTime::since_unix_epoch(Duration::from_secs(later)))
            .unwrap();
    }

    fn refusal(fingerprint: &str, code: &str, expires_in: u64) -> Refusal {
        let value = format!(
            "Gateinto auth_uri=\"https://verify.test/device?cert_sha256={fingerprint}\", \
             user_code={code}, expires_in={expires_in}"
        );
        let challenge = challenge::parse(&[value.as_bytes()], fingerprint, None).unwrap();
        Refusal {
            fingerprint: fingerprint.to_owned(),
            challenge,
        }
    }

    fn target(port: u16) -> Authority {
        format!("example.test:{port}").parse().unwrap()
    }

    fn store() -> (
        Verifications,
        Arc<SelfSignedCertificates>,
        PendingVerifications,
    ) {
        let (certificate, certificates) = self_signed();
        let agent = PendingVerifications::default();
        (
            Verifications::new(Some(certificate), agent.clone()),
            certificates,
            agent,
        )
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_challenge_becomes_pending_with_its_values() {
        let (store, certificates, agent) = store();
        assert!(!store.pending());
        assert!(store.get().is_none());
        let fp = fingerprint(&certificates);
        assert_eq!(
            store.offer(refusal(&fp, "WDJB-MJHT", 300), &target(1)),
            Offer::Pending
        );
        assert!(store.pending());
        assert_eq!(agent.count(), 1);
        let pending = store.get().unwrap();
        assert_eq!(pending.serial, 1);
        assert_eq!(*pending.origin, "https://verify.test");
        assert_eq!(
            *pending.auth_uri,
            format!("https://verify.test/device?cert_sha256={fp}")
        );
        assert_eq!(*pending.user_code, "WDJB-MJHT");
        assert_eq!(pending.expires_in, 300);
        assert_eq!(pending.targets, ["example.test:1"]);
        assert_eq!((pending.more_targets, pending.suppressed), (0, 0));
        let debug = format!("{pending:?}");
        assert!(
            !debug.contains("WDJB") && !debug.contains("verify.test"),
            "{debug}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn identical_repeats_add_targets_and_keep_deadline_code_and_serial() {
        let (store, certificates, _) = store();
        let fp = fingerprint(&certificates);
        store.offer(refusal(&fp, "WDJB-MJHT", 300), &target(1));
        tokio::time::advance(Duration::from_secs(100)).await;
        assert_eq!(
            store.offer(refusal(&fp, "WDJB-MJHT", 600), &target(1)),
            Offer::Added
        );
        for port in 2..=MAX_TARGETS as u16 {
            assert_eq!(
                store.offer(refusal(&fp, "WDJB-MJHT", 600), &target(port)),
                Offer::Added
            );
        }
        for port in [100, 101, 100] {
            assert_eq!(
                store.offer(refusal(&fp, "WDJB-MJHT", 600), &target(port)),
                Offer::Counted
            );
        }
        let pending = store.get().unwrap();
        assert_eq!(pending.serial, 1);
        assert_eq!(pending.expires_in, 200);
        assert_eq!(pending.targets.len(), MAX_TARGETS);
        assert_eq!(pending.targets[0], "example.test:1");
        assert_eq!(pending.more_targets, 3);
        assert_eq!(pending.suppressed, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_different_challenge_is_suppressed_while_one_is_pending() {
        let (store, certificates, agent) = store();
        let fp = fingerprint(&certificates);
        store.offer(refusal(&fp, "WDJB-MJHT", 300), &target(1));
        assert_eq!(
            store.offer(refusal(&fp, "BCDF-GHJK", 300), &target(2)),
            Offer::Suppressed
        );
        let pending = store.get().unwrap();
        assert_eq!(*pending.user_code, "WDJB-MJHT");
        assert_eq!(pending.targets, ["example.test:1"]);
        assert_eq!(pending.suppressed, 1);
        assert_eq!(agent.count(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_challenge_for_another_certificate_is_dropped() {
        let (store, _, agent) = store();
        let (_, other) = self_signed();
        assert_eq!(
            store.offer(refusal(&fingerprint(&other), "WDJB-MJHT", 300), &target(1)),
            Offer::Stale
        );
        assert!(!store.pending());
        assert_eq!(agent.count(), 0);
        let anonymous = Verifications::new(None, agent.clone());
        assert_eq!(
            anonymous.offer(refusal(&fingerprint(&other), "WDJB-MJHT", 300), &target(1)),
            Offer::Stale
        );
        assert!(!anonymous.pending());
    }

    #[tokio::test(start_paused = true)]
    async fn a_renewal_replaces_the_entry_with_a_new_serial() {
        let (store, certificates, agent) = store();
        let old = fingerprint(&certificates);
        store.offer(refusal(&old, "WDJB-MJHT", 300), &target(1));
        renew(&certificates);
        let new = fingerprint(&certificates);
        assert_ne!(old, new);
        assert!(!store.pending());
        assert_eq!(agent.count(), 0);
        assert_eq!(
            store.offer(refusal(&old, "WDJB-MJHT", 300), &target(1)),
            Offer::Stale
        );
        assert_eq!(
            store.offer(refusal(&new, "BCDF-GHJK", 300), &target(2)),
            Offer::Pending
        );
        let pending = store.get().unwrap();
        assert_eq!(pending.serial, 2);
        assert_eq!(*pending.user_code, "BCDF-GHJK");
    }

    #[tokio::test(start_paused = true)]
    async fn the_agent_holds_at_most_sixteen_pending_challenges() {
        let agent = PendingVerifications::default();
        let mut stores = Vec::new();
        for _ in 0..MAX_PENDING {
            let (certificate, certificates) = self_signed();
            let store = Verifications::new(Some(certificate), agent.clone());
            let fp = fingerprint(&certificates);
            assert_eq!(
                store.offer(refusal(&fp, "WDJB-MJHT", 300), &target(1)),
                Offer::Pending
            );
            stores.push((store, fp));
        }
        let (certificate, certificates) = self_signed();
        let late = Verifications::new(Some(certificate), agent.clone());
        let fp = fingerprint(&certificates);
        for _ in 0..2 {
            assert_eq!(
                late.offer(refusal(&fp, "WDJB-MJHT", 300), &target(1)),
                Offer::AgentLimit
            );
        }
        assert!(!late.pending());
        assert_eq!(agent.count(), MAX_PENDING);
        let (first, _) = &stores[0];
        assert!(first.dismiss(first.get().unwrap().serial));
        assert_eq!(agent.count(), MAX_PENDING - 1);
        assert_eq!(
            late.offer(refusal(&fp, "WDJB-MJHT", 300), &target(1)),
            Offer::Pending
        );
        let pending = late.get().unwrap();
        assert_eq!(pending.suppressed, 2);
        assert_eq!(pending.serial, 1);
        assert_eq!(agent.count(), MAX_PENDING);
    }

    #[tokio::test(start_paused = true)]
    async fn the_timer_removes_an_expired_entry() {
        let (store, certificates, agent) = store();
        let fp = fingerprint(&certificates);
        store.offer(refusal(&fp, "WDJB-MJHT", 2), &target(1));
        tokio::time::advance(Duration::from_millis(1500)).await;
        assert_eq!(store.get().unwrap().expires_in, 1);
        tokio::time::sleep(Duration::from_millis(600)).await;
        tokio::task::yield_now().await;
        assert_eq!(agent.count(), 0);
        assert!(!store.pending());
    }

    #[tokio::test(start_paused = true)]
    async fn a_read_never_returns_an_expired_entry() {
        let (store, certificates, agent) = store();
        let fp = fingerprint(&certificates);
        store.offer(refusal(&fp, "WDJB-MJHT", 2), &target(1));
        let deadline = Instant::now() + Duration::from_secs(2);
        assert!(store.get_at(deadline - Duration::from_millis(1)).is_some());
        assert!(store.get_at(deadline).is_none());
        assert_eq!(agent.count(), 0);
        assert_eq!(
            store.offer_at(refusal(&fp, "WDJB-MJHT", 2), &target(1), deadline),
            Offer::Pending
        );
        assert_eq!(store.get_at(deadline).unwrap().serial, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn dismissal_needs_the_current_serial() {
        let (store, certificates, agent) = store();
        let fp = fingerprint(&certificates);
        store.offer(refusal(&fp, "WDJB-MJHT", 300), &target(1));
        assert!(!store.dismiss(2));
        assert!(!store.dismiss(0));
        assert!(store.pending());
        assert!(store.dismiss(1));
        assert!(!store.pending());
        assert!(!store.dismiss(1));
        assert_eq!(agent.count(), 0);
        store.offer(refusal(&fp, "WDJB-MJHT", 300), &target(1));
        assert_eq!(store.get().unwrap().serial, 2);
        store.clear();
        assert!(!store.pending());
        assert_eq!(agent.count(), 0);
    }
}
