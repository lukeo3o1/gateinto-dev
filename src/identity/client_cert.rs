use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::pki_types::pem::{self, PemObject};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::sign::{CertifiedKey, SigningKey};
use tracing::{info, warn};

use crate::identity::UnsupportedPlatform;
use crate::identity::certificates::{
    DeviceSigner, ExpiredCertificate, IssueError, SelfSignedCertificates,
};
use crate::identity::device_key::{
    self, Backend, DeviceKey, KeyError, KeyName, KeyStore, StoreError,
};
use crate::identity::encoding::sha256_fingerprint;
use crate::identity::x509::{Certificate, X509Error, format_utc, parse_certificate};

pub const CERTIFICATE_STORE: &str = "CurrentUser\\My";

pub trait ClientIdentityStore: KeyStore {
    fn signing_key(&self, key: Self::Key) -> Result<Arc<dyn SigningKey>, StoreError>;
    fn client_certificates(&self) -> Result<Vec<CertificateDer<'static>>, StoreError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientCertificateMode {
    Off,
    #[default]
    Optional,
    Required,
}

#[derive(Debug)]
pub enum ClientAuth<T> {
    Off,
    Enabled(T),
    Unauthenticated(ClientAuthError),
}

impl ClientCertificateMode {
    pub fn resolve<T>(
        self,
        load: impl FnOnce() -> Result<T, ClientAuthError>,
    ) -> Result<ClientAuth<T>, ClientAuthError> {
        match self {
            Self::Off => Ok(ClientAuth::Off),
            Self::Required => load().map(ClientAuth::Enabled),
            Self::Optional => Ok(match load() {
                Ok(identity) => ClientAuth::Enabled(identity),
                Err(error) => ClientAuth::Unauthenticated(error),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateSource {
    File(PathBuf),
    Store,
    SelfSigned,
}

impl fmt::Display for CertificateSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(path) => write!(f, "file {}", path.display()),
            Self::Store => f.write_str(CERTIFICATE_STORE),
            Self::SelfSigned => f.write_str("self-signed"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CertificateFile {
    pub path: PathBuf,
    pub chain: Vec<CertificateDer<'static>>,
    pub leaf: Certificate,
}

#[derive(Debug)]
pub struct CertificateFileError {
    path: PathBuf,
    kind: CertificateFileErrorKind,
}

#[derive(Debug)]
enum CertificateFileErrorKind {
    Pem(pem::Error),
    Empty,
    Leaf(X509Error),
}

impl fmt::Display for CertificateFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let path = self.path.display();
        match &self.kind {
            CertificateFileErrorKind::Pem(error) => {
                write!(f, "cannot read client certificate file {path}: {error}")
            }
            CertificateFileErrorKind::Empty => {
                write!(f, "client certificate file {path} contains no certificates")
            }
            CertificateFileErrorKind::Leaf(error) => {
                write!(f, "invalid client certificate in {path}: {error}")
            }
        }
    }
}

impl std::error::Error for CertificateFileError {}

pub fn load_certificate_file(path: &Path) -> Result<CertificateFile, CertificateFileError> {
    let error = |kind| CertificateFileError {
        path: path.to_owned(),
        kind,
    };
    let chain = CertificateDer::pem_file_iter(path)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .map_err(|e| error(CertificateFileErrorKind::Pem(e)))?;
    let leaf = chain
        .first()
        .ok_or_else(|| error(CertificateFileErrorKind::Empty))?;
    let leaf = parse_certificate(leaf).map_err(|e| error(CertificateFileErrorKind::Leaf(e)))?;
    Ok(CertificateFile {
        path: path.to_owned(),
        chain,
        leaf,
    })
}

#[derive(Debug, Clone)]
pub struct Selection {
    pub chosen: Option<(CertificateDer<'static>, Certificate)>,
    pub matches: usize,
}

pub fn select_store_certificate(
    candidates: Vec<CertificateDer<'static>>,
    spki: &[u8],
    now: UnixTime,
) -> Selection {
    let now = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
    let usable: Vec<_> = candidates
        .into_iter()
        .filter_map(|der| parse_certificate(&der).ok().map(|parsed| (der, parsed)))
        .filter(|(_, parsed)| {
            parsed.spki == spki
                && parsed.extended_key_usage.allows_client_auth()
                && (parsed.not_before..=parsed.not_after).contains(&now)
        })
        .collect();
    Selection {
        matches: usable.len(),
        chosen: usable
            .into_iter()
            .max_by_key(|(_, parsed)| parsed.not_after),
    }
}

#[derive(Debug, Clone)]
pub struct Binding {
    pub chain: Vec<CertificateDer<'static>>,
    pub leaf: Certificate,
    pub source: CertificateSource,
}

impl Binding {
    pub fn summary(&self) -> String {
        format!(
            "client-certificate: {}\nclient-certificate-sha1: {}\nclient-certificate-not-after: {}\n\
             client-certificate-source: {}\n",
            self.leaf.subject,
            self.leaf.sha1_thumbprint,
            format_utc(self.leaf.not_after),
            self.source
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientAuthError {
    Unsupported,
    Key(KeyError),
    Store(StoreError),
    NoCertificate {
        name: KeyName,
        key_fingerprint: String,
    },
    Mismatch {
        subject: String,
        source: CertificateSource,
        certificate_fingerprint: String,
        key_fingerprint: String,
    },
    Signer(StoreError),
    File(String),
    Issue(IssueError),
}

impl From<UnsupportedPlatform> for ClientAuthError {
    fn from(_: UnsupportedPlatform) -> Self {
        Self::Unsupported
    }
}

impl fmt::Display for ClientAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(f, "{UnsupportedPlatform}"),
            Self::Key(error) => write!(f, "{error}"),
            Self::Store(error) => {
                write!(
                    f,
                    "reading the {CERTIFICATE_STORE} certificate store failed: {error}"
                )
            }
            Self::NoCertificate {
                name,
                key_fingerprint,
            } => write!(
                f,
                "no client certificate for device key \"{name}\" (spki-sha256: \
                 {key_fingerprint}): none was given with --client-cert-file and \
                 {CERTIFICATE_STORE} has no currently valid certificate for this key that allows \
                 client authentication"
            ),
            Self::Mismatch {
                subject,
                source,
                certificate_fingerprint,
                key_fingerprint,
            } => write!(
                f,
                "client certificate \"{subject}\" from {source} does not belong to the device \
                 key: its public key (spki-sha256: {certificate_fingerprint}) differs from the \
                 device key (spki-sha256: {key_fingerprint}); a certificate whose private key is \
                 not held is never sent"
            ),
            Self::Signer(error) => {
                write!(f, "the device key cannot be used for TLS signing: {error}")
            }
            Self::File(error) => f.write_str(error),
            Self::Issue(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ClientAuthError {}

impl ClientAuthError {
    pub fn unauthenticated_warning(&self) -> String {
        format!(
            "{self}; mTLS is not configured and upstream connections do not authenticate this \
             device"
        )
    }
}

pub fn bind_certificate<S: ClientIdentityStore>(
    store: &S,
    spki: &[u8],
    file: Option<CertificateFile>,
    now: UnixTime,
) -> Result<Option<Binding>, ClientAuthError> {
    let binding = match file {
        Some(file) => Binding {
            chain: file.chain,
            leaf: file.leaf,
            source: CertificateSource::File(file.path),
        },
        None => {
            let candidates = store
                .client_certificates()
                .map_err(ClientAuthError::Store)?;
            let selection = select_store_certificate(candidates, spki, now);
            let Some((der, leaf)) = selection.chosen else {
                return Ok(None);
            };
            if selection.matches > 1 {
                info!(
                    matches = selection.matches,
                    thumbprint = %leaf.sha1_thumbprint,
                    "several client certificates match the device key; using the one that expires last"
                );
            }
            Binding {
                chain: vec![der],
                leaf,
                source: CertificateSource::Store,
            }
        }
    };
    if binding.leaf.spki != spki {
        return Err(ClientAuthError::Mismatch {
            subject: binding.leaf.subject,
            source: binding.source,
            certificate_fingerprint: sha256_fingerprint(&binding.leaf.spki),
            key_fingerprint: sha256_fingerprint(spki),
        });
    }
    Ok(Some(binding))
}

pub struct ClientIdentity {
    pub backend: Backend,
    pub binding: Binding,
    pub certified_key: Arc<CertifiedKey>,
    self_signed: Option<ClientCertificate>,
}

#[derive(Debug, Clone)]
pub enum ClientCertificate {
    Fixed(Arc<CertifiedKey>),
    SelfSigned {
        certificates: Arc<SelfSignedCertificates>,
        required: bool,
    },
}

impl From<Arc<CertifiedKey>> for ClientCertificate {
    fn from(certified_key: Arc<CertifiedKey>) -> Self {
        Self::Fixed(certified_key)
    }
}

impl ClientCertificate {
    pub fn certified_key(&self, now: UnixTime) -> Result<Arc<CertifiedKey>, ExpiredCertificate> {
        match self {
            Self::Fixed(certified_key) => Ok(certified_key.clone()),
            Self::SelfSigned { certificates, .. } => certificates.certified_key_at(now),
        }
    }

    pub fn check_required(&self, now: UnixTime) -> Result<(), ExpiredCertificate> {
        match self {
            Self::SelfSigned { required: true, .. } => self.certified_key(now).map(drop),
            _ => Ok(()),
        }
    }
}

impl fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientIdentity")
            .field("backend", &self.backend)
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}

fn open_device_key<S: ClientIdentityStore>(
    store: &S,
    name: &KeyName,
) -> Result<DeviceKey<S::Key>, ClientAuthError> {
    let (key, duplicate) = device_key::info(store, name).map_err(ClientAuthError::Key)?;
    if let Some(duplicate) = duplicate {
        warn!("{duplicate}; using the tpm key");
    }
    Ok(key)
}

pub fn load_self_signed_identity<S: ClientIdentityStore>(
    store: &S,
    name: &KeyName,
    mode: ClientCertificateMode,
    now: UnixTime,
) -> Result<ClientIdentity, ClientAuthError> {
    let key = open_device_key(store, name)?;
    let backend = key.backend;
    let signer = store
        .signing_key(key.key)
        .map_err(ClientAuthError::Signer)?;
    let certificates = SelfSignedCertificates::new(DeviceSigner::new(key.point, signer), now)
        .map_err(ClientAuthError::Issue)?;
    let certified_key = certificates.current();
    let leaf = parse_certificate(&certified_key.cert[0])
        .expect("issued self-signed certificates are well-formed");
    Ok(ClientIdentity {
        backend,
        binding: Binding {
            chain: certified_key.cert.clone(),
            leaf,
            source: CertificateSource::SelfSigned,
        },
        certified_key,
        self_signed: Some(ClientCertificate::SelfSigned {
            certificates: Arc::new(certificates),
            required: mode == ClientCertificateMode::Required,
        }),
    })
}

pub fn load_client_identity<S: ClientIdentityStore>(
    store: &S,
    name: &KeyName,
    file: Option<CertificateFile>,
    now: UnixTime,
) -> Result<ClientIdentity, ClientAuthError> {
    let key = open_device_key(store, name)?;
    let spki = key.spki_der();
    let binding = bind_certificate(store, &spki, file, now)?.ok_or_else(|| {
        ClientAuthError::NoCertificate {
            name: name.clone(),
            key_fingerprint: sha256_fingerprint(&spki),
        }
    })?;
    let signer = store
        .signing_key(key.key)
        .map_err(ClientAuthError::Signer)?;
    let certified_key = Arc::new(CertifiedKey::new(binding.chain.clone(), signer));
    Ok(ClientIdentity {
        backend: key.backend,
        binding,
        certified_key,
        self_signed: None,
    })
}

impl ClientAuth<ClientIdentity> {
    pub fn into_client_certificate(self) -> Option<ClientCertificate> {
        match self {
            Self::Off => {
                info!("client certificate authentication is off");
                None
            }
            Self::Enabled(identity) => {
                let leaf = &identity.binding.leaf;
                info!(
                    subject = %leaf.subject,
                    thumbprint = %leaf.sha1_thumbprint,
                    not_after = %format_utc(leaf.not_after),
                    source = %identity.binding.source,
                    backend = %identity.backend,
                    "client certificate authentication enabled"
                );
                Some(
                    identity
                        .self_signed
                        .unwrap_or(ClientCertificate::Fixed(identity.certified_key)),
                )
            }
            Self::Unauthenticated(error) => {
                warn!("{}", error.unauthenticated_warning());
                None
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCertificateOptions {
    pub mode: ClientCertificateMode,
    pub key_name: KeyName,
    pub source: CertificateSource,
}

fn load_file(path: Option<&Path>) -> Result<Option<CertificateFile>, ClientAuthError> {
    path.map(load_certificate_file)
        .transpose()
        .map_err(|error| ClientAuthError::File(error.to_string()))
}

pub fn configure<S: ClientIdentityStore>(
    options: &ClientCertificateOptions,
    store: Result<&S, UnsupportedPlatform>,
    now: UnixTime,
) -> Result<ClientAuth<ClientIdentity>, ClientAuthError> {
    options.mode.resolve(|| {
        let store = store?;
        let file = match &options.source {
            CertificateSource::SelfSigned => {
                return load_self_signed_identity(store, &options.key_name, options.mode, now);
            }
            CertificateSource::File(path) => Some(path.as_path()),
            CertificateSource::Store => None,
        };
        load_client_identity(store, &options.key_name, load_file(file)?, now)
    })
}

pub fn describe_binding<S: ClientIdentityStore>(
    store: &S,
    spki: &[u8],
    file: Option<&Path>,
    now: UnixTime,
) -> Result<String, ClientAuthError> {
    let binding = bind_certificate(store, spki, load_file(file)?, now)?;
    Ok(binding.map_or_else(|| "client-certificate: none\n".to_owned(), |b| b.summary()))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    use rcgen::{
        CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, PublicKeyData, date_time_ymd,
    };
    use rustls::pki_types::PrivatePkcs8KeyDer;

    use super::*;
    use crate::identity::certificates::IssueError;
    use crate::identity::encoding::P256Point;

    fn now() -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(1_830_297_600))
    }

    type Date = (i32, u8, u8);

    struct Issued {
        der: CertificateDer<'static>,
        pem: String,
    }

    fn issue(
        key: &KeyPair,
        valid: (Date, Date),
        configure: impl FnOnce(&mut CertificateParams),
    ) -> Issued {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "gateinto-client");
        let ((y1, m1, d1), (y2, m2, d2)) = valid;
        params.not_before = date_time_ymd(y1, m1, d1);
        params.not_after = date_time_ymd(y2, m2, d2);
        configure(&mut params);
        let certificate = params.self_signed(key).unwrap();
        Issued {
            der: certificate.der().clone(),
            pem: certificate.pem(),
        }
    }

    const VALID: (Date, Date) = ((2026, 1, 1), (2030, 1, 1));

    fn client(key: &KeyPair) -> Issued {
        issue(key, VALID, |params| {
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth]
        })
    }

    fn write_temp(name: &str, contents: &[u8]) -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("gateinto-{}-{n}-{name}", std::process::id()));
        std::fs::write(&path, contents).unwrap();
        path
    }

    fn chosen_not_after(selection: &Selection) -> Option<String> {
        selection
            .chosen
            .as_ref()
            .map(|(_, certificate)| format_utc(certificate.not_after))
    }

    #[test]
    fn store_selection_requires_the_device_spki() {
        let key = KeyPair::generate().unwrap();
        let other = KeyPair::generate().unwrap();
        let candidates = vec![client(&other).der, client(&key).der];

        let selection =
            select_store_certificate(candidates.clone(), &key.subject_public_key_info(), now());

        assert_eq!(selection.matches, 1);
        assert_eq!(selection.chosen.unwrap().0, candidates[1]);
        let none = select_store_certificate(
            vec![client(&other).der],
            &key.subject_public_key_info(),
            now(),
        );
        assert_eq!(none.matches, 0);
        assert!(none.chosen.is_none());
    }

    #[test]
    fn store_selection_accepts_client_auth_or_no_extended_key_usage() {
        let key = KeyPair::generate().unwrap();
        let spki = key.subject_public_key_info();
        let server_only = issue(&key, VALID, |params| {
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth]
        });
        let unrestricted = issue(&key, VALID, |_| {});

        assert!(
            select_store_certificate(vec![server_only.der], &spki, now())
                .chosen
                .is_none()
        );
        assert!(
            select_store_certificate(vec![unrestricted.der], &spki, now())
                .chosen
                .is_some()
        );
        assert!(
            select_store_certificate(vec![client(&key).der], &spki, now())
                .chosen
                .is_some()
        );
    }

    #[test]
    fn store_selection_requires_validity_at_the_given_time() {
        let key = KeyPair::generate().unwrap();
        let spki = key.subject_public_key_info();
        let expired = issue(&key, ((2020, 1, 1), (2027, 12, 31)), |_| {});
        let not_yet_valid = issue(&key, ((2028, 1, 2), (2030, 1, 1)), |_| {});
        let starts_now = issue(&key, ((2028, 1, 1), (2030, 1, 1)), |_| {});
        let ends_now = issue(&key, ((2020, 1, 1), (2028, 1, 1)), |_| {});

        let selection =
            select_store_certificate(vec![expired.der, not_yet_valid.der], &spki, now());
        assert!(selection.chosen.is_none());
        assert_eq!(selection.matches, 0);
        assert!(
            select_store_certificate(vec![starts_now.der], &spki, now())
                .chosen
                .is_some()
        );
        assert!(
            select_store_certificate(vec![ends_now.der], &spki, now())
                .chosen
                .is_some()
        );
    }

    #[test]
    fn store_selection_picks_the_latest_not_after() {
        let key = KeyPair::generate().unwrap();
        let spki = key.subject_public_key_info();
        let early = issue(&key, ((2026, 1, 1), (2029, 1, 1)), |_| {});
        let late = issue(&key, ((2027, 1, 1), (2031, 1, 1)), |_| {});
        let middle = issue(&key, ((2025, 1, 1), (2030, 1, 1)), |_| {});

        let selection =
            select_store_certificate(vec![early.der, late.der, middle.der], &spki, now());

        assert_eq!(selection.matches, 3);
        assert_eq!(
            chosen_not_after(&selection).as_deref(),
            Some("2031-01-01T00:00:00Z")
        );
    }

    #[test]
    fn store_selection_skips_unparsable_certificates() {
        let key = KeyPair::generate().unwrap();
        let candidates = vec![CertificateDer::from(b"garbage".to_vec()), client(&key).der];

        let selection = select_store_certificate(candidates, &key.subject_public_key_info(), now());

        assert_eq!(selection.matches, 1);
    }

    #[test]
    fn certificate_file_holds_the_leaf_and_intermediates_in_order() {
        let key = KeyPair::generate().unwrap();
        let leaf = client(&key);
        let intermediate = issue(&KeyPair::generate().unwrap(), VALID, |_| {});
        let path = write_temp(
            "chain.pem",
            format!("{}{}", leaf.pem, intermediate.pem).as_bytes(),
        );

        let file = load_certificate_file(&path).unwrap();

        assert_eq!(file.path, path);
        assert_eq!(file.chain, vec![leaf.der, intermediate.der]);
        assert_eq!(file.leaf.spki, key.subject_public_key_info());
    }

    #[test]
    fn certificate_file_errors_name_the_file() {
        let missing = Path::new("/nonexistent/gateinto-client.pem");
        let error = load_certificate_file(missing).unwrap_err().to_string();
        assert!(
            error.starts_with(
                "cannot read client certificate file /nonexistent/gateinto-client.pem: "
            ),
            "{error}"
        );

        let empty = write_temp("empty.pem", b"no certificates here\n");
        assert_eq!(
            load_certificate_file(&empty).unwrap_err().to_string(),
            format!(
                "client certificate file {} contains no certificates",
                empty.display()
            )
        );

        let bad_leaf = write_temp(
            "bad.pem",
            b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        );
        assert_eq!(
            load_certificate_file(&bad_leaf).unwrap_err().to_string(),
            format!(
                "invalid client certificate in {}: malformed X.509 certificate: unexpected tag",
                bad_leaf.display()
            )
        );
    }

    fn failure() -> ClientAuthError {
        ClientAuthError::Key(KeyError::NotFound(KeyName::default()))
    }

    #[test]
    fn off_never_loads_an_identity() {
        let auth = ClientCertificateMode::Off
            .resolve::<()>(|| panic!("must not load"))
            .unwrap();

        assert!(matches!(auth, ClientAuth::Off));
    }

    #[test]
    fn required_uses_the_identity_or_fails() {
        let mode = ClientCertificateMode::Required;

        assert!(matches!(mode.resolve(|| Ok(7)), Ok(ClientAuth::Enabled(7))));
        assert_eq!(
            mode.resolve::<()>(|| Err(failure())).unwrap_err(),
            failure()
        );
    }

    #[test]
    fn optional_uses_the_identity_or_continues_unauthenticated() {
        let mode = ClientCertificateMode::Optional;

        assert!(matches!(mode.resolve(|| Ok(7)), Ok(ClientAuth::Enabled(7))));
        assert!(matches!(
            mode.resolve::<()>(|| Err(failure())),
            Ok(ClientAuth::Unauthenticated(error)) if error == failure()
        ));
    }

    #[test]
    fn optional_is_the_default() {
        assert_eq!(
            ClientCertificateMode::default(),
            ClientCertificateMode::Optional
        );
    }

    #[test]
    fn unauthenticated_warning_says_the_device_is_not_authenticated() {
        assert_eq!(
            ClientAuthError::Unsupported.unauthenticated_warning(),
            "device keys are only supported on Windows; mTLS is not configured and upstream \
             connections do not authenticate this device"
        );
    }

    struct FakeStore {
        name: KeyName,
        key: KeyPair,
        missing: bool,
        certificates: Result<Vec<CertificateDer<'static>>, StoreError>,
        calls: RefCell<Vec<String>>,
    }

    impl FakeStore {
        fn new() -> Self {
            Self {
                name: KeyName::default(),
                key: KeyPair::generate().unwrap(),
                missing: false,
                certificates: Ok(Vec::new()),
                calls: RefCell::new(Vec::new()),
            }
        }

        fn spki(&self) -> Vec<u8> {
            self.key.subject_public_key_info()
        }

        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }

    impl KeyStore for FakeStore {
        type Key = ();

        fn open(&self, backend: Backend, name: &KeyName) -> Result<(), StoreError> {
            self.calls.borrow_mut().push(format!("open {backend}"));
            if backend == Backend::Software && *name == self.name && !self.missing {
                Ok(())
            } else {
                Err(StoreError::NotFound)
            }
        }

        fn create(&self, backend: Backend, _: &KeyName) -> Result<(), StoreError> {
            self.calls.borrow_mut().push(format!("create {backend}"));
            Err(StoreError::Failed("must not create".to_owned()))
        }

        fn delete(&self, _: ()) -> Result<(), StoreError> {
            self.calls.borrow_mut().push("delete".to_owned());
            Ok(())
        }

        fn public_point(&self, _: &()) -> Result<P256Point, StoreError> {
            Ok(self.key.public_key_raw().try_into().unwrap())
        }

        fn sign_digest(&self, _: &(), _: &[u8]) -> Result<Vec<u8>, StoreError> {
            Err(StoreError::Failed("not used".to_owned()))
        }
    }

    impl ClientIdentityStore for FakeStore {
        fn signing_key(&self, _: ()) -> Result<Arc<dyn SigningKey>, StoreError> {
            self.calls.borrow_mut().push("signing key".to_owned());
            let der = PrivatePkcs8KeyDer::from(self.key.serialize_der()).into();
            rustls::crypto::aws_lc_rs::sign::any_ecdsa_type(&der)
                .map_err(|error| StoreError::Failed(error.to_string()))
        }

        fn client_certificates(&self) -> Result<Vec<CertificateDer<'static>>, StoreError> {
            self.calls.borrow_mut().push("certificates".to_owned());
            self.certificates.clone()
        }
    }

    fn file_for(key: &KeyPair) -> CertificateFile {
        let issued = client(key);
        load_certificate_file(&write_temp("client.pem", issued.pem.as_bytes())).unwrap()
    }

    #[test]
    fn identity_from_a_matching_file_signs_with_the_device_key() {
        let store = FakeStore::new();
        let file = file_for(&store.key);
        let path = file.path.clone();

        let identity =
            load_client_identity(&store, &KeyName::default(), Some(file), now()).unwrap();

        assert_eq!(identity.backend, Backend::Software);
        assert_eq!(identity.binding.source, CertificateSource::File(path));
        identity.certified_key.keys_match().unwrap();
        assert!(!store.calls().contains(&"certificates".to_owned()));
        assert!(!store.calls().iter().any(|call| call.starts_with("create")));
    }

    #[test]
    fn identity_from_a_file_for_another_key_is_refused_before_signing() {
        let store = FakeStore::new();
        let other = KeyPair::generate().unwrap();
        let file = file_for(&other);
        let path = file.path.clone();

        let error =
            load_client_identity(&store, &KeyName::default(), Some(file), now()).unwrap_err();

        assert_eq!(
            error,
            ClientAuthError::Mismatch {
                subject: "CN=gateinto-client".to_owned(),
                source: CertificateSource::File(path),
                certificate_fingerprint: sha256_fingerprint(&other.subject_public_key_info()),
                key_fingerprint: sha256_fingerprint(&store.spki()),
            }
        );
        assert!(!store.calls().contains(&"signing key".to_owned()));
    }

    #[test]
    fn identity_without_a_file_comes_from_the_store() {
        let mut store = FakeStore::new();
        let issued = client(&store.key);
        store.certificates = Ok(vec![issued.der.clone()]);

        let identity = load_client_identity(&store, &KeyName::default(), None, now()).unwrap();

        assert_eq!(identity.binding.source, CertificateSource::Store);
        assert_eq!(identity.certified_key.cert, vec![issued.der]);
        identity.certified_key.keys_match().unwrap();
    }

    #[test]
    fn identity_without_any_certificate_is_an_error() {
        let store = FakeStore::new();

        let error = load_client_identity(&store, &KeyName::default(), None, now()).unwrap_err();

        assert_eq!(
            error,
            ClientAuthError::NoCertificate {
                name: KeyName::default(),
                key_fingerprint: sha256_fingerprint(&store.spki()),
            }
        );
    }

    #[test]
    fn identity_needs_an_existing_key_and_never_creates_one() {
        let store = FakeStore {
            missing: true,
            ..FakeStore::new()
        };
        let file = file_for(&store.key);

        let error =
            load_client_identity(&store, &KeyName::default(), Some(file), now()).unwrap_err();

        assert_eq!(error, failure());
        assert_eq!(store.calls(), vec!["open tpm", "open software"]);
    }

    #[test]
    fn store_failures_are_reported() {
        let mut store = FakeStore::new();
        let failure = StoreError::Failed("access denied".to_owned());
        store.certificates = Err(failure.clone());

        assert_eq!(
            load_client_identity(&store, &KeyName::default(), None, now()).unwrap_err(),
            ClientAuthError::Store(failure)
        );
    }

    fn options(mode: ClientCertificateMode, file: Option<PathBuf>) -> ClientCertificateOptions {
        ClientCertificateOptions {
            mode,
            key_name: KeyName::default(),
            source: file.map_or(CertificateSource::Store, CertificateSource::File),
        }
    }

    fn self_signed(mode: ClientCertificateMode) -> ClientCertificateOptions {
        ClientCertificateOptions {
            source: CertificateSource::SelfSigned,
            ..options(mode, None)
        }
    }

    fn enabled(auth: ClientAuth<ClientIdentity>) -> ClientIdentity {
        match auth {
            ClientAuth::Enabled(identity) => identity,
            other => panic!("client auth was not enabled: {other:?}"),
        }
    }

    #[test]
    fn configure_self_signed_issues_a_certificate_for_the_device_key() {
        let store = FakeStore::new();

        let identity = enabled(
            configure(
                &self_signed(ClientCertificateMode::Required),
                Ok(&store),
                now(),
            )
            .unwrap(),
        );

        assert_eq!(identity.backend, Backend::Software);
        assert_eq!(identity.binding.source, CertificateSource::SelfSigned);
        let leaf = &identity.binding.leaf;
        assert_eq!(leaf.subject, "CN=Gateinto device");
        assert_eq!(leaf.spki, store.spki());
        assert_eq!(leaf.not_after, now().as_secs() as i64 + 3600);
        assert_eq!(identity.certified_key.cert, identity.binding.chain);
        identity.certified_key.keys_match().unwrap();
        assert!(!store.calls().contains(&"certificates".to_owned()));
        assert!(!store.calls().iter().any(|call| call.starts_with("create")));
        let Some(ClientCertificate::SelfSigned {
            certificates,
            required: true,
        }) = ClientAuth::Enabled(identity).into_client_certificate()
        else {
            panic!("self-signed identity did not renew its certificates");
        };
        assert_eq!(certificates.spki(), store.spki());
    }

    #[test]
    fn each_self_signed_identity_gets_its_own_certificate_for_the_same_key() {
        let store = FakeStore::new();
        let issue = || {
            enabled(
                configure(
                    &self_signed(ClientCertificateMode::Required),
                    Ok(&store),
                    now(),
                )
                .unwrap(),
            )
            .binding
            .leaf
        };

        let (first, second) = (issue(), issue());

        assert_eq!(first.spki, second.spki);
        assert_ne!(first.serial, second.serial);
        assert_ne!(first.sha1_thumbprint, second.sha1_thumbprint);
    }

    #[test]
    fn configure_self_signed_needs_an_existing_key() {
        let store = FakeStore {
            missing: true,
            ..FakeStore::new()
        };

        let error = configure(
            &self_signed(ClientCertificateMode::Required),
            Ok(&store),
            now(),
        )
        .unwrap_err();
        let auth = configure(
            &self_signed(ClientCertificateMode::Optional),
            Ok(&store),
            now(),
        )
        .unwrap();

        assert_eq!(error, failure());
        assert!(matches!(auth, ClientAuth::Unauthenticated(error) if error == failure()));
        assert!(!store.calls().iter().any(|call| call.starts_with("create")));
    }

    #[test]
    fn configure_self_signed_on_an_unsupported_platform_fails_or_continues_unauthenticated() {
        assert_eq!(
            configure(
                &self_signed(ClientCertificateMode::Required),
                unsupported(),
                now()
            )
            .unwrap_err(),
            ClientAuthError::Unsupported
        );
        assert!(matches!(
            configure(
                &self_signed(ClientCertificateMode::Optional),
                unsupported(),
                now()
            )
            .unwrap(),
            ClientAuth::Unauthenticated(ClientAuthError::Unsupported)
        ));
    }

    #[test]
    fn fixed_client_certificates_are_sent_unchanged() {
        let store = FakeStore::new();
        let path = write_temp("fixed.pem", client(&store.key).pem.as_bytes());
        let identity = enabled(
            configure(
                &options(ClientCertificateMode::Required, Some(path)),
                Ok(&store),
                now(),
            )
            .unwrap(),
        );
        let certified_key = identity.certified_key.clone();

        let Some(certificate) = ClientAuth::Enabled(identity).into_client_certificate() else {
            panic!("no client certificate");
        };

        assert!(matches!(certificate, ClientCertificate::Fixed(_)));
        assert!(Arc::ptr_eq(
            &certificate.certified_key(now()).unwrap(),
            &certified_key
        ));
    }

    #[test]
    fn off_and_unauthenticated_send_no_client_certificate() {
        assert!(ClientAuth::Off.into_client_certificate().is_none());
        assert!(
            ClientAuth::Unauthenticated(ClientAuthError::Unsupported)
                .into_client_certificate()
                .is_none()
        );
    }

    #[test]
    fn self_signed_source_and_issue_errors_are_named() {
        assert_eq!(CertificateSource::SelfSigned.to_string(), "self-signed");
        assert_eq!(
            ClientAuthError::Issue(IssueError::Verify).to_string(),
            IssueError::Verify.to_string()
        );
    }

    fn unsupported() -> Result<&'static FakeStore, UnsupportedPlatform> {
        Err(UnsupportedPlatform)
    }

    #[test]
    fn configure_off_touches_neither_the_store_nor_the_file() {
        let store = FakeStore::new();
        let missing = PathBuf::from("/nonexistent/gateinto-client.pem");

        let auth = configure(
            &options(ClientCertificateMode::Off, Some(missing)),
            Ok(&store),
            now(),
        )
        .unwrap();

        assert!(matches!(auth, ClientAuth::Off));
        assert!(store.calls().is_empty());
    }

    #[test]
    fn configure_required_on_an_unsupported_platform_fails() {
        let error = configure(
            &options(ClientCertificateMode::Required, None),
            unsupported(),
            now(),
        )
        .unwrap_err();

        assert_eq!(error, ClientAuthError::Unsupported);
        assert_eq!(
            error.to_string(),
            "device keys are only supported on Windows"
        );
    }

    #[test]
    fn configure_optional_on_an_unsupported_platform_continues_unauthenticated() {
        let auth = configure(
            &options(ClientCertificateMode::Optional, None),
            unsupported(),
            now(),
        )
        .unwrap();

        assert!(matches!(
            auth,
            ClientAuth::Unauthenticated(ClientAuthError::Unsupported)
        ));
    }

    #[test]
    fn configure_loads_the_file_and_binds_it_to_the_device_key() {
        let store = FakeStore::new();
        let issued = client(&store.key);
        let path = write_temp("configure.pem", issued.pem.as_bytes());

        let auth = configure(
            &options(ClientCertificateMode::Required, Some(path.clone())),
            Ok(&store),
            now(),
        )
        .unwrap();

        let ClientAuth::Enabled(identity) = auth else {
            panic!("client auth was not enabled");
        };
        assert_eq!(identity.binding.source, CertificateSource::File(path));
        assert_eq!(identity.certified_key.cert, vec![issued.der]);
    }

    #[test]
    fn configure_reports_an_unreadable_file() {
        let store = FakeStore::new();
        let missing = PathBuf::from("/nonexistent/gateinto-client.pem");

        let error = configure(
            &options(ClientCertificateMode::Required, Some(missing.clone())),
            Ok(&store),
            now(),
        )
        .unwrap_err();

        assert!(matches!(error, ClientAuthError::File(_)));
        assert!(
            error.to_string().starts_with(
                "cannot read client certificate file /nonexistent/gateinto-client.pem"
            ),
            "{error}"
        );
        let auth = configure(
            &options(ClientCertificateMode::Optional, Some(missing)),
            Ok(&store),
            now(),
        )
        .unwrap();
        assert!(matches!(
            auth,
            ClientAuth::Unauthenticated(ClientAuthError::File(_))
        ));
    }

    #[test]
    fn configure_optional_with_a_certificate_for_another_key_continues_unauthenticated() {
        let store = FakeStore::new();
        let other = KeyPair::generate().unwrap();
        let path = write_temp("other.pem", client(&other).pem.as_bytes());

        let auth = configure(
            &options(ClientCertificateMode::Optional, Some(path)),
            Ok(&store),
            now(),
        )
        .unwrap();

        let ClientAuth::Unauthenticated(error) = auth else {
            panic!("client auth was not refused");
        };
        assert!(matches!(error, ClientAuthError::Mismatch { .. }));
        assert!(!store.calls().contains(&"signing key".to_owned()));
    }

    #[test]
    fn describe_binding_without_a_certificate_says_none() {
        let store = FakeStore::new();

        assert_eq!(
            describe_binding(&store, &store.spki(), None, now()).unwrap(),
            "client-certificate: none\n"
        );
    }

    #[test]
    fn describe_binding_lists_the_certificate_found_in_the_store() {
        let mut store = FakeStore::new();
        let issued = client(&store.key);
        let thumbprint = parse_certificate(&issued.der).unwrap().sha1_thumbprint;
        store.certificates = Ok(vec![issued.der]);

        assert_eq!(
            describe_binding(&store, &store.spki(), None, now()).unwrap(),
            format!(
                "client-certificate: CN=gateinto-client\nclient-certificate-sha1: {thumbprint}\n\
                 client-certificate-not-after: 2030-01-01T00:00:00Z\n\
                 client-certificate-source: CurrentUser\\My\n"
            )
        );
    }

    #[test]
    fn describe_binding_checks_a_given_file_against_the_key() {
        let store = FakeStore::new();
        let matching = write_temp("matching.pem", client(&store.key).pem.as_bytes());
        let other = KeyPair::generate().unwrap();
        let foreign = write_temp("foreign.pem", client(&other).pem.as_bytes());

        let described = describe_binding(&store, &store.spki(), Some(&matching), now()).unwrap();
        assert!(
            described.ends_with(&format!(
                "client-certificate-source: file {}\n",
                matching.display()
            )),
            "{described}"
        );
        assert!(matches!(
            describe_binding(&store, &store.spki(), Some(&foreign), now()).unwrap_err(),
            ClientAuthError::Mismatch { .. }
        ));
        assert!(!store.calls().contains(&"certificates".to_owned()));
    }

    #[test]
    fn binding_reports_no_certificate_as_none() {
        let store = FakeStore::new();

        assert!(
            bind_certificate(&store, &store.spki(), None, now())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn binding_summary_lists_subject_thumbprint_expiry_and_source() {
        let store = FakeStore::new();
        let file = file_for(&store.key);
        let thumbprint = file.leaf.sha1_thumbprint.clone();
        let path = file.path.clone();

        let binding = bind_certificate(&store, &store.spki(), Some(file), now())
            .unwrap()
            .unwrap();

        assert_eq!(
            binding.summary(),
            format!(
                "client-certificate: CN=gateinto-client\nclient-certificate-sha1: {thumbprint}\n\
                 client-certificate-not-after: 2030-01-01T00:00:00Z\n\
                 client-certificate-source: file {}\n",
                path.display()
            )
        );
    }

    #[test]
    fn error_messages_explain_the_problem() {
        assert_eq!(
            ClientAuthError::Unsupported.to_string(),
            "device keys are only supported on Windows"
        );
        assert_eq!(
            ClientAuthError::NoCertificate {
                name: KeyName::default(),
                key_fingerprint: "ab".to_owned(),
            }
            .to_string(),
            "no client certificate for device key \"gateinto-device-v1\" (spki-sha256: ab): \
             none was given with --client-cert-file and CurrentUser\\My has no currently valid \
             certificate for this key that allows client authentication"
        );
        assert_eq!(
            ClientAuthError::Mismatch {
                subject: "CN=x".to_owned(),
                source: CertificateSource::Store,
                certificate_fingerprint: "aa".to_owned(),
                key_fingerprint: "bb".to_owned(),
            }
            .to_string(),
            "client certificate \"CN=x\" from CurrentUser\\My does not belong to the device key: \
             its public key (spki-sha256: aa) differs from the device key (spki-sha256: bb); \
             a certificate whose private key is not held is never sent"
        );
        assert_eq!(
            ClientAuthError::Store(StoreError::Failed("denied".to_owned())).to_string(),
            "reading the CurrentUser\\My certificate store failed: denied"
        );
        assert_eq!(
            ClientAuthError::Signer(StoreError::Failed("bad key".to_owned())).to_string(),
            "the device key cannot be used for TLS signing: bad key"
        );
        assert_eq!(
            failure().to_string(),
            KeyError::NotFound(KeyName::default()).to_string()
        );
    }
}
