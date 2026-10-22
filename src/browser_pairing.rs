//! Fail-closed browser HTTP/2 connection pairing policy.
//!
//! This is a transport-independent policy primitive, NOT a listener or a complete
//! browser authentication system. The control plane must authenticate the approval
//! request separately, and the HTTPS/h2 ingress must supply connection identifiers
//! that cannot be selected by the peer. Never log or persist pairing secrets.

use std::time::{Duration, Instant};

use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};

/// A locally assigned identifier for a single *accepted TLS connection*.
/// It must not be a value provided by the HTTP client or the CONNECT request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub u64);

/// The maximum time between human-approved challenge creation and pairing.
pub const PAIRING_TTL: Duration = Duration::from_secs(60);

const CHALLENGE_SIZE: usize = 32;

/// A short-lived bearer secret. Deliver only through an independently
/// authorized control channel; a browser page is not an OS process identity.
#[derive(Clone)]
pub struct PairingChallenge([u8; CHALLENGE_SIZE]);

impl PairingChallenge {
    /// Do not put this value in logs, external DNS, telemetry or browser history.
    pub fn as_bytes(&self) -> &[u8; CHALLENGE_SIZE] {
        &self.0
    }
}

impl std::fmt::Debug for PairingChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairingChallenge([REDACTED])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingError {
    NotApproved,
    Expired,
    InvalidProof,
    AlreadyBound,
    RandomFailure,
}

struct Pending {
    secret: [u8; CHALLENGE_SIZE],
    until: Instant,
}

/// One BrowserSession owns one gate. Serialize all access to avoid two TLS
/// connections winning the slot concurrently.
///
/// WARNING: an untrusted localhost caller must NOT be allowed to call
/// 'approve'. This gate does not authenticate the user or the browser process.
#[derive(Default)]
pub struct BrowserPairingGate {
    pending: Option<Pending>,
    active: Option<ConnectionId>,
}

impl BrowserPairingGate {
    pub fn new() -> Self {
        Self::default()
    }

    /// Called only after a separately authenticated human approval.
    /// A new approval invalidates the previous pending challenge.
    pub fn approve(&mut self, now: Instant) -> Result<PairingChallenge, PairingError> {
        if self.active.is_some() {
            return Err(PairingError::AlreadyBound);
        }
        let mut nonce = [0_u8; CHALLENGE_SIZE];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| PairingError::RandomFailure)?;
        self.pending = Some(Pending {
            secret: nonce,
            until: now + PAIRING_TTL,
        });
        Ok(PairingChallenge(nonce))
    }

    /// Pair the specific local TLS connection which received the pairing
    /// CONNECT stream. This is not a per-stream authorization.
    pub fn pair(
        &mut self,
        connection: ConnectionId,
        proof: &[u8],
        now: Instant,
    ) -> Result<(), PairingError> {
        if self.active.is_some() {
            return Err(PairingError::AlreadyBound);
        }
        let Some(pending) = self.pending.as_ref() else {
            return Err(PairingError::NotApproved);
        };
        if now >= pending.until {
            self.pending = None;
            return Err(PairingError::Expired);
        }
        if proof.len() != CHALLENGE_SIZE
            || verify_slices_are_equal(&pending.secret, proof).is_err()
        {
            return Err(PairingError::InvalidProof);
        }
        self.pending = None;
        self.active = Some(connection);
        Ok(())
    }

    /// Check BEFORE upstream/DIRECT access or Device Key signing.
    pub fn may_open_tunnel(&self, connection: ConnectionId) -> bool {
        self.active == Some(connection)
    }

    /// A stale/foreign disconnect must never revoke a newer TLS connection.
    pub fn disconnected(&mut self, connection: ConnectionId) -> bool {
        if self.active != Some(connection) {
            return false;
        }
        self.active = None;
        self.pending = None;
        true
    }

    /// BrowserSession close, revocation or administrative reset.
    pub fn revoke(&mut self) {
        self.pending = None;
        self.active = None;
    }

    pub fn active_connection(&self) -> Option<ConnectionId> {
        self.active
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_closed_until_approved_and_paired() {
        let now = Instant::now();
        let mut gate = BrowserPairingGate::new();
        assert_eq!(gate.pair(ConnectionId(1), &[0; 32], now), Err(PairingError::NotApproved));
        assert!(!gate.may_open_tunnel(ConnectionId(1)));
        let challenge = gate.approve(now).unwrap();
        assert!(!gate.may_open_tunnel(ConnectionId(1)));
        gate.pair(ConnectionId(1), challenge.as_bytes(), now).unwrap();
        assert!(gate.may_open_tunnel(ConnectionId(1)));
        assert!(!gate.may_open_tunnel(ConnectionId(2)));
    }

    #[test]
    fn second_connection_cannot_pair_while_first_is_active() {
        let now = Instant::now();
        let mut gate = BrowserPairingGate::new();
        let challenge = gate.approve(now).unwrap();
        gate.pair(ConnectionId(10), challenge.as_bytes(), now).unwrap();
        assert!(matches!(gate.approve(now), Err(PairingError::AlreadyBound)));
        assert_eq!(
            gate.pair(ConnectionId(11), challenge.as_bytes(), now),
            Err(PairingError::AlreadyBound)
        );
        assert!(gate.may_open_tunnel(ConnectionId(10)));
    }

    #[test]
    fn short_incorrect_and_replayed_proofs_fail() {
        let now = Instant::now();
        let mut gate = BrowserPairingGate::new();
        let challenge = gate.approve(now).unwrap();
        assert_eq!(gate.pair(ConnectionId(1), &[1], now), Err(PairingError::InvalidProof));
        let mut wrong = *challenge.as_bytes();
        wrong[0] ^= 1;
        assert_eq!(gate.pair(ConnectionId(1), &wrong, now), Err(PairingError::InvalidProof));
        gate.pair(ConnectionId(1), challenge.as_bytes(), now).unwrap();
        gate.disconnected(ConnectionId(1));
        assert_eq!(
            gate.pair(ConnectionId(2), challenge.as_bytes(), now),
            Err(PairingError::NotApproved)
        );
    }

    #[test]
    fn expiry_and_new_approval_invalidate_old_nonce() {
        let now = Instant::now();
        let mut gate = BrowserPairingGate::new();
        let old = gate.approve(now).unwrap();
        assert_eq!(
            gate.pair(ConnectionId(1), old.as_bytes(), now + PAIRING_TTL),
            Err(PairingError::Expired)
        );
        let new = gate.approve(now + PAIRING_TTL).unwrap();
        assert_eq!(
            gate.pair(ConnectionId(1), old.as_bytes(), now + PAIRING_TTL),
            Err(PairingError::InvalidProof)
        );
        gate.pair(ConnectionId(1), new.as_bytes(), now + PAIRING_TTL).unwrap();
    }

    #[test]
    fn disconnect_and_revoke_require_new_approval() {
        let now = Instant::now();
        let mut gate = BrowserPairingGate::new();
        let old = gate.approve(now).unwrap();
        gate.pair(ConnectionId(10), old.as_bytes(), now).unwrap();
        assert!(!gate.disconnected(ConnectionId(11)));
        assert!(gate.may_open_tunnel(ConnectionId(10)));
        assert!(gate.disconnected(ConnectionId(10)));
        assert!(!gate.may_open_tunnel(ConnectionId(10)));
        assert_eq!(gate.pair(ConnectionId(11), old.as_bytes(), now), Err(PairingError::NotApproved));
        let fresh = gate.approve(now).unwrap();
        gate.revoke();
        assert_eq!(gate.pair(ConnectionId(11), fresh.as_bytes(), now), Err(PairingError::NotApproved));
    }

    #[test]
    fn debug_output_redacts_nonce() {
        let challenge = BrowserPairingGate::new().approve(Instant::now()).unwrap();
        assert_eq!(format!("{challenge:?}"), "PairingChallenge([REDACTED])");
    }
}
