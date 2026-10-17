use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use rustls::SignatureScheme;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::sign::{CertifiedKey, SigningKey};
use tracing::{info, warn};

use crate::identity::encoding::{P256Point, p256_spki_der, sha256_fingerprint};
use crate::identity::x509::{encode_time, format_utc};

pub const SUBJECT_COMMON_NAME: &str = "Gateinto device";
pub const VALIDITY: Duration = Duration::from_secs(60 * 60);
pub const BACKDATE: Duration = Duration::from_secs(5 * 60);
pub const RENEW_AFTER: Duration = Duration::from_secs(VALIDITY.as_secs() / 2);
pub const RENEW_RETRY_AFTER: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssueError {
    Random,
    NoScheme,
    Sign(String),
    Verify,
}

impl fmt::Display for IssueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Random => f.write_str("generating a certificate serial number failed"),
            Self::NoScheme => f.write_str("the device key cannot sign with ECDSA P-256 SHA-256"),
            Self::Sign(error) => write!(
                f,
                "the device key failed to sign the self-signed client certificate: {error}"
            ),
            Self::Verify => f.write_str(
                "the self-signed client certificate signature does not verify with the device \
                 public key",
            ),
        }
    }
}

impl std::error::Error for IssueError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredCertificate {
    pub not_after: i64,
    pub renewal: IssueError,
}

impl fmt::Display for ExpiredCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the self-signed client certificate expired at {} and renewing it failed: {}",
            format_utc(self.not_after),
            self.renewal
        )
    }
}

impl std::error::Error for ExpiredCertificate {}

#[derive(Debug, Clone)]
pub struct DeviceSigner {
    point: P256Point,
    key: Arc<dyn SigningKey>,
}

impl DeviceSigner {
    pub fn new(point: P256Point, key: Arc<dyn SigningKey>) -> Self {
        Self { point, key }
    }

    pub fn spki(&self) -> Vec<u8> {
        p256_spki_der(&self.point)
    }

    pub fn key(&self) -> Arc<dyn SigningKey> {
        self.key.clone()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, IssueError> {
        self.key
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
            .ok_or(IssueError::NoScheme)?
            .sign(message)
            .map_err(|error| IssueError::Sign(error.to_string()))
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), IssueError> {
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &self.point)
            .verify(message, signature)
            .map_err(|_| IssueError::Verify)
    }
}

const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const INTEGER: u8 = 0x02;
const BOOLEAN: u8 = 0x01;
const BIT_STRING: u8 = 0x03;
const OCTET_STRING: u8 = 0x04;
const OID: u8 = 0x06;
const UTF8_STRING: u8 = 0x0c;
const VERSION: u8 = 0xa0;
const EXTENSIONS: u8 = 0xa3;

const ECDSA_WITH_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
const EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
const CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
const SERIAL_LEN: usize = 16;

fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let len = contents.len();
    let mut out = vec![tag];
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let significant = &bytes[bytes.iter().take_while(|&&byte| byte == 0).count()..];
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(contents);
    out
}

fn sequence(parts: &[&[u8]]) -> Vec<u8> {
    tlv(SEQUENCE, &parts.concat())
}

fn extension(id: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let critical = if critical {
        tlv(BOOLEAN, &[0xff])
    } else {
        Vec::new()
    };
    sequence(&[&tlv(OID, id), &critical, &tlv(OCTET_STRING, value)])
}

fn serial_number() -> Result<[u8; SERIAL_LEN], IssueError> {
    let mut serial = [0; SERIAL_LEN];
    SystemRandom::new()
        .fill(&mut serial)
        .map_err(|_| IssueError::Random)?;
    serial[0] = serial[0] & 0x3f | 0x40;
    Ok(serial)
}

pub fn issue(signer: &DeviceSigner, now: UnixTime) -> Result<CertificateDer<'static>, IssueError> {
    let now = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
    let algorithm = sequence(&[&tlv(OID, ECDSA_WITH_SHA256)]);
    let name = sequence(&[&tlv(
        SET,
        &sequence(&[
            &tlv(OID, COMMON_NAME),
            &tlv(UTF8_STRING, SUBJECT_COMMON_NAME.as_bytes()),
        ]),
    )]);
    let validity = sequence(&[
        &encode_time(now - BACKDATE.as_secs() as i64),
        &encode_time(now + VALIDITY.as_secs() as i64),
    ]);
    let extensions = tlv(
        EXTENSIONS,
        &sequence(&[
            &extension(BASIC_CONSTRAINTS, true, &sequence(&[])),
            &extension(KEY_USAGE, true, &tlv(BIT_STRING, &[0x07, 0x80])),
            &extension(
                EXTENDED_KEY_USAGE,
                false,
                &sequence(&[&tlv(OID, CLIENT_AUTH)]),
            ),
        ]),
    );
    let tbs = sequence(&[
        &tlv(VERSION, &tlv(INTEGER, &[2])),
        &tlv(INTEGER, &serial_number()?),
        &algorithm,
        &name,
        &validity,
        &name,
        &signer.spki(),
        &extensions,
    ]);
    let signature = signer.sign(&tbs)?;
    signer.verify(&tbs, &signature)?;
    let certificate = sequence(&[
        &tbs,
        &algorithm,
        &tlv(BIT_STRING, &[&[0][..], &signature].concat()),
    ]);
    Ok(CertificateDer::from(certificate))
}

#[derive(Debug)]
pub struct SelfSignedCertificates {
    signer: DeviceSigner,
    current: Mutex<Current>,
}

#[derive(Debug)]
struct Current {
    certified_key: Arc<CertifiedKey>,
    issued_at: u64,
    not_after: u64,
    failed_renewal: Option<(u64, IssueError)>,
}

impl SelfSignedCertificates {
    pub fn new(signer: DeviceSigner, now: UnixTime) -> Result<Self, IssueError> {
        let current = Self::issue(&signer, now)?;
        Ok(Self {
            signer,
            current: Mutex::new(current),
        })
    }

    fn issue(signer: &DeviceSigner, now: UnixTime) -> Result<Current, IssueError> {
        let der = issue(signer, now)?;
        Ok(Current {
            certified_key: Arc::new(CertifiedKey::new(vec![der], signer.key())),
            issued_at: now.as_secs(),
            not_after: now.as_secs().saturating_add(VALIDITY.as_secs()),
            failed_renewal: None,
        })
    }

    pub fn spki(&self) -> Vec<u8> {
        self.signer.spki()
    }

    pub fn current(&self) -> Arc<CertifiedKey> {
        self.lock().certified_key.clone()
    }

    pub fn certified_key_at(&self, now: UnixTime) -> Result<Arc<CertifiedKey>, ExpiredCertificate> {
        let mut current = self.lock();
        let now_secs = now.as_secs();
        let retry_due = current
            .failed_renewal
            .as_ref()
            .is_none_or(|(failed_at, _)| {
                now_secs.saturating_sub(*failed_at) >= RENEW_RETRY_AFTER.as_secs()
            });
        if retry_due && now_secs.saturating_sub(current.issued_at) >= RENEW_AFTER.as_secs() {
            match Self::issue(&self.signer, now) {
                Ok(renewed) => {
                    *current = renewed;
                    info!(
                        sha256 = %sha256_fingerprint(&current.certified_key.cert[0]),
                        "renewed the self-signed client certificate"
                    );
                }
                Err(error) => {
                    if now_secs < current.not_after {
                        warn!(
                            "renewing the self-signed client certificate failed: {error}; \
                             sending the previous one, valid until {}",
                            format_utc(i64::try_from(current.not_after).unwrap_or(i64::MAX))
                        );
                    }
                    current.failed_renewal = Some((now_secs, error));
                }
            }
        }
        match &current.failed_renewal {
            Some((_, renewal)) if now_secs >= current.not_after => Err(ExpiredCertificate {
                not_after: i64::try_from(current.not_after).unwrap_or(i64::MAX),
                renewal: renewal.clone(),
            }),
            _ => Ok(current.certified_key.clone()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Current> {
        self.current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{
        ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair,
    };
    use rustls::RootCertStore;
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use rustls::server::WebPkiClientVerifier;

    use std::sync::atomic::{AtomicBool, Ordering};

    use rustls::SignatureAlgorithm;
    use rustls::sign::Signer;

    use super::*;
    use crate::identity::encoding::sha256_fingerprint;
    use crate::identity::x509::{ExtendedKeyUsage, parse_certificate};

    const NOW: u64 = 1_830_297_600;

    fn at(secs: u64) -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(secs))
    }

    fn software_signer() -> DeviceSigner {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .unwrap();
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref()).unwrap();
        let point = pair.public_key().as_ref().try_into().unwrap();
        let der = PrivatePkcs8KeyDer::from(pkcs8.as_ref().to_vec()).into();
        let key = rustls::crypto::aws_lc_rs::sign::any_ecdsa_type(&der).unwrap();
        DeviceSigner::new(point, key)
    }

    fn webpki_accepts_as_its_own_anchor(der: &CertificateDer<'static>, now: UnixTime) -> bool {
        let mut roots = RootCertStore::empty();
        roots.add(der.clone()).unwrap();
        WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        )
        .build()
        .unwrap()
        .verify_client_cert(der, &[], now)
        .is_ok()
    }

    #[test]
    fn tlv_encodes_lengths_in_the_shortest_der_form() {
        let header = |len: usize| {
            let encoded = tlv(OCTET_STRING, &vec![0; len]);
            encoded[..encoded.len() - len].to_vec()
        };

        assert_eq!(header(0), [0x04, 0x00]);
        assert_eq!(header(0x7f), [0x04, 0x7f]);
        assert_eq!(header(0x80), [0x04, 0x81, 0x80]);
        assert_eq!(header(0xff), [0x04, 0x81, 0xff]);
        assert_eq!(header(0x100), [0x04, 0x82, 0x01, 0x00]);
        assert_eq!(header(0xffff), [0x04, 0x82, 0xff, 0xff]);
        assert_eq!(header(0x1_0000), [0x04, 0x83, 0x01, 0x00, 0x00]);
        assert_eq!(header(0x0123_4567), [0x04, 0x84, 0x01, 0x23, 0x45, 0x67]);
    }

    #[test]
    fn issued_certificate_carries_the_documented_fields() {
        let signer = software_signer();

        let der = issue(&signer, at(NOW)).unwrap();

        let parsed = parse_certificate(&der).unwrap();
        assert_eq!(parsed.subject, "CN=Gateinto device");
        assert_eq!(parsed.spki, signer.spki());
        assert_eq!(
            parsed.extended_key_usage,
            ExtendedKeyUsage::Present { client_auth: true }
        );
        assert_eq!(parsed.not_before, NOW as i64 - 300);
        assert_eq!(parsed.not_after, NOW as i64 + 3600);
        assert_eq!(parsed.serial.len(), 16);
        assert_eq!(parsed.serial[0] & 0xc0, 0x40);
    }

    #[test]
    fn issued_certificate_is_a_critical_non_ca_digital_signature_certificate() {
        let der = issue(&software_signer(), at(NOW)).unwrap();
        let contains = |pattern: &[u8]| der.windows(pattern.len()).any(|w| w == pattern);

        assert!(contains(&[
            0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00
        ]));
        assert!(contains(&[
            0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02,
            0x07, 0x80
        ]));
    }

    #[test]
    fn certificates_from_one_key_share_the_spki_and_differ_otherwise() {
        let signer = software_signer();

        let first = issue(&signer, at(NOW)).unwrap();
        let second = issue(&signer, at(NOW)).unwrap();

        let (a, b) = (
            parse_certificate(&first).unwrap(),
            parse_certificate(&second).unwrap(),
        );
        assert_eq!(a.spki, b.spki);
        assert_ne!(first, second);
        assert_ne!(sha256_fingerprint(&first), sha256_fingerprint(&second));
        assert_ne!(a.serial, b.serial);
    }

    #[test]
    fn webpki_verifies_the_self_signature_validity_and_client_auth() {
        let der = issue(&software_signer(), at(NOW)).unwrap();

        assert!(webpki_accepts_as_its_own_anchor(&der, at(NOW)));
        assert!(webpki_accepts_as_its_own_anchor(&der, at(NOW - 300)));
        assert!(!webpki_accepts_as_its_own_anchor(&der, at(NOW - 301)));
        assert!(!webpki_accepts_as_its_own_anchor(&der, at(NOW + 3601)));
    }

    #[test]
    fn signer_signs_messages_with_der_ecdsa_p256_sha256() {
        let signer = software_signer();

        let signature = signer.sign(b"message").unwrap();

        aws_lc_rs::signature::UnparsedPublicKey::new(
            &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1,
            &signer.point,
        )
        .verify(b"message", &signature)
        .unwrap();
    }

    #[test]
    fn a_key_that_does_not_match_the_public_key_is_refused() {
        let signer = software_signer();
        let mismatched = DeviceSigner::new(software_signer().point, signer.key());

        assert_eq!(issue(&mismatched, at(NOW)), Err(IssueError::Verify));
    }

    #[test]
    fn a_key_without_ecdsa_p256_sha256_is_refused() {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let der = PrivatePkcs8KeyDer::from(pkcs8.as_ref().to_vec());
        let key = rustls::crypto::aws_lc_rs::sign::any_eddsa_type(&der).unwrap();
        let signer = DeviceSigner::new(software_signer().point, key);

        assert_eq!(issue(&signer, at(NOW)), Err(IssueError::NoScheme));
    }

    #[test]
    fn errors_explain_the_problem() {
        assert_eq!(
            IssueError::NoScheme.to_string(),
            "the device key cannot sign with ECDSA P-256 SHA-256"
        );
        assert_eq!(
            IssueError::Sign("denied".to_owned()).to_string(),
            "the device key failed to sign the self-signed client certificate: denied"
        );
        assert_eq!(
            IssueError::Verify.to_string(),
            "the self-signed client certificate signature does not verify with the device \
             public key"
        );
        assert_eq!(
            IssueError::Random.to_string(),
            "generating a certificate serial number failed"
        );
    }

    #[test]
    fn certificates_are_renewed_once_half_their_validity_has_passed() {
        let certificates = SelfSignedCertificates::new(software_signer(), at(NOW)).unwrap();
        let first = certificates.current();

        let early = certificates.certified_key_at(at(NOW + 1799)).unwrap();
        let renewed = certificates.certified_key_at(at(NOW + 1800)).unwrap();

        assert!(Arc::ptr_eq(&first, &early));
        assert_ne!(renewed.cert, first.cert);
        assert!(Arc::ptr_eq(&renewed, &certificates.current()));
        let parsed = parse_certificate(&renewed.cert[0]).unwrap();
        assert_eq!(parsed.not_before, (NOW + 1800 - 300) as i64);
        assert_eq!(parsed.spki, certificates.spki());
        renewed.keys_match().unwrap();
        assert!(Arc::ptr_eq(
            &certificates.certified_key_at(at(NOW + 1801)).unwrap(),
            &renewed
        ));
    }

    #[derive(Debug)]
    struct SwitchableKey {
        inner: Arc<dyn SigningKey>,
        failing: Arc<AtomicBool>,
    }

    impl SigningKey for SwitchableKey {
        fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
            if self.failing.load(Ordering::Relaxed) {
                return None;
            }
            self.inner.choose_scheme(offered)
        }

        fn algorithm(&self) -> SignatureAlgorithm {
            self.inner.algorithm()
        }
    }

    fn switchable_signer() -> (DeviceSigner, Arc<AtomicBool>) {
        let signer = software_signer();
        let failing = Arc::new(AtomicBool::new(false));
        let key = SwitchableKey {
            inner: signer.key(),
            failing: failing.clone(),
        };
        (DeviceSigner::new(signer.point, Arc::new(key)), failing)
    }

    #[test]
    fn a_failed_renewal_is_retried_no_sooner_than_a_minute_later() {
        let (signer, failing) = switchable_signer();
        let certificates = SelfSignedCertificates::new(signer, at(NOW)).unwrap();
        let first = certificates.current();
        failing.store(true, Ordering::Relaxed);
        certificates.certified_key_at(at(NOW + 1800)).unwrap();
        failing.store(false, Ordering::Relaxed);

        let within_a_minute = certificates.certified_key_at(at(NOW + 1859)).unwrap();
        let after_a_minute = certificates.certified_key_at(at(NOW + 1860)).unwrap();

        assert!(Arc::ptr_eq(&within_a_minute, &first));
        assert_ne!(after_a_minute.cert, first.cert);
    }

    #[test]
    fn an_expired_certificate_reports_the_last_renewal_error_until_the_retry() {
        let (signer, failing) = switchable_signer();
        let certificates = SelfSignedCertificates::new(signer, at(NOW)).unwrap();
        failing.store(true, Ordering::Relaxed);
        certificates.certified_key_at(at(NOW + 3600)).unwrap_err();
        failing.store(false, Ordering::Relaxed);

        let within_a_minute = certificates.certified_key_at(at(NOW + 3659)).unwrap_err();
        let after_a_minute = certificates.certified_key_at(at(NOW + 3660)).unwrap();

        assert_eq!(within_a_minute.renewal, IssueError::NoScheme);
        assert!(Arc::ptr_eq(&after_a_minute, &certificates.current()));
    }

    #[test]
    fn a_failed_renewal_keeps_the_previous_certificate_only_until_it_expires() {
        let (signer, failing) = switchable_signer();
        let certificates = SelfSignedCertificates::new(signer, at(NOW)).unwrap();
        let first = certificates.current();
        failing.store(true, Ordering::Relaxed);

        let after_failed_renewal = certificates.certified_key_at(at(NOW + 1800)).unwrap();
        let last_valid_second = certificates.certified_key_at(at(NOW + 3599)).unwrap();
        let expired = certificates.certified_key_at(at(NOW + 3600)).unwrap_err();

        assert!(Arc::ptr_eq(&after_failed_renewal, &first));
        assert!(Arc::ptr_eq(&last_valid_second, &first));
        assert_eq!(
            expired,
            ExpiredCertificate {
                not_after: (NOW + 3600) as i64,
                renewal: IssueError::NoScheme,
            }
        );
        assert_eq!(
            expired.to_string(),
            "the self-signed client certificate expired at 2028-01-01T01:00:00Z and \
             renewing it failed: the device key cannot sign with ECDSA P-256 SHA-256"
        );
        failing.store(false, Ordering::Relaxed);
        let renewed = certificates.certified_key_at(at(NOW + 3700)).unwrap();
        assert_ne!(renewed.cert, first.cert);
        assert!(Arc::ptr_eq(&renewed, &certificates.current()));
    }
}
