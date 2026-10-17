use std::fmt;
use std::str::FromStr;

use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};

use crate::identity::encoding::{P256Point, p256_spki_der, sha256_fingerprint};

pub const DEFAULT_KEY_NAME: &str = "gateinto-device-v1";
pub const ALGORITHM: &str = "ECDSA P-256";
pub const PLATFORM_CRYPTO_PROVIDER: &str = "Microsoft Platform Crypto Provider";
pub const SOFTWARE_KEY_STORAGE_PROVIDER: &str = "Microsoft Software Key Storage Provider";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    Tpm,
    Software,
}

impl Backend {
    pub fn provider(self) -> &'static str {
        match self {
            Self::Tpm => PLATFORM_CRYPTO_PROVIDER,
            Self::Software => SOFTWARE_KEY_STORAGE_PROVIDER,
        }
    }
}

impl fmt::Display for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tpm => "tpm",
            Self::Software => "software",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(try_from = "String")]
pub struct KeyName(String);

impl TryFrom<String> for KeyName {
    type Error = InvalidKeyName;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        name.parse()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidKeyName {
    Empty,
    ContainsNul,
}

impl fmt::Display for InvalidKeyName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "key name must not be empty",
            Self::ContainsNul => "key name must not contain NUL",
        })
    }
}

impl std::error::Error for InvalidKeyName {}

impl FromStr for KeyName {
    type Err = InvalidKeyName;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        if name.is_empty() {
            Err(InvalidKeyName::Empty)
        } else if name.contains('\0') {
            Err(InvalidKeyName::ContainsNul)
        } else {
            Ok(Self(name.to_owned()))
        }
    }
}

impl KeyName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for KeyName {
    fn default() -> Self {
        Self(DEFAULT_KEY_NAME.to_owned())
    }
}

impl fmt::Display for KeyName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    NotFound,
    ProviderUnavailable(String),
    ProviderNotReady(String),
    Failed(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("key not found"),
            Self::ProviderUnavailable(reason) => write!(f, "provider unavailable: {reason}"),
            Self::ProviderNotReady(reason) => {
                write!(f, "provider present but not usable: {reason}")
            }
            Self::Failed(reason) => f.write_str(reason),
        }
    }
}

pub trait KeyStore {
    type Key;

    fn open(&self, backend: Backend, name: &KeyName) -> Result<Self::Key, StoreError>;
    fn create(&self, backend: Backend, name: &KeyName) -> Result<Self::Key, StoreError>;
    fn delete(&self, key: Self::Key) -> Result<(), StoreError>;
    fn public_point(&self, key: &Self::Key) -> Result<P256Point, StoreError>;
    fn sign_digest(&self, key: &Self::Key, digest: &[u8]) -> Result<Vec<u8>, StoreError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitOptions {
    pub backend: Backend,
    pub allow_software_fallback: bool,
}

impl Default for InitOptions {
    fn default() -> Self {
        Self {
            backend: Backend::Tpm,
            allow_software_fallback: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TpmProblem {
    Unavailable(String),
    CreateFailed(String),
    SelfTestFailed(String),
}

impl fmt::Display for TpmProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(reason) => write!(f, "the TPM provider is unavailable: {reason}"),
            Self::CreateFailed(reason) => write!(f, "creating the TPM key failed: {reason}"),
            Self::SelfTestFailed(reason) => {
                write!(f, "the new TPM key failed its signing self-test: {reason}")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provenance {
    Reused,
    Created,
    CreatedAfterFallback(TpmProblem),
}

#[derive(Debug)]
pub struct DeviceKey<K> {
    pub backend: Backend,
    pub point: P256Point,
    pub key: K,
}

impl<K> DeviceKey<K> {
    pub fn spki_der(&self) -> Vec<u8> {
        p256_spki_der(&self.point)
    }

    pub fn fingerprint(&self) -> String {
        sha256_fingerprint(&self.spki_der())
    }

    pub fn summary(&self) -> String {
        format!(
            "backend: {}\nalgorithm: {ALGORITHM}\nspki-sha256: {}\ntrust: {}\n",
            self.backend,
            self.fingerprint(),
            trust_note(self.backend)
        )
    }
}

pub fn trust_note(backend: Backend) -> &'static str {
    match backend {
        Backend::Tpm => "hardware-protected private key (TPM)",
        Backend::Software => {
            "non-exportable flag set, but not protected against copying by an administrator or malware running as the user"
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateKeys {
    pub name: KeyName,
    pub tpm_fingerprint: String,
    pub software_fingerprint: String,
}

impl DuplicateKeys {
    pub fn info_warning(&self) -> String {
        format!(
            "warning: {self}; showing the tpm key. `gateinto key init` refuses to run until one \
             of them is deleted"
        )
    }
}

impl fmt::Display for DuplicateKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "device keys named \"{}\" exist in both the tpm provider (spki-sha256: {}) and the \
             software provider (spki-sha256: {})",
            self.name, self.tpm_fingerprint, self.software_fingerprint
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    NotFound(KeyName),
    Duplicate(DuplicateKeys),
    ProviderNotReady { backend: Backend, reason: String },
    Open { backend: Backend, error: StoreError },
    PublicKey { backend: Backend, error: StoreError },
    TpmUnusable(TpmProblem),
    Create { backend: Backend, error: StoreError },
    SelfTest { backend: Backend, error: String },
    Cleanup { backend: Backend, error: StoreError },
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(name) => write!(
                f,
                "no device key named \"{name}\"; run `gateinto setup` to create it"
            ),
            Self::Duplicate(duplicate) => write!(
                f,
                "{duplicate}; refusing to choose one. Delete the key that should not be used and \
                 retry"
            ),
            Self::ProviderNotReady {
                backend: Backend::Tpm,
                reason,
            } => write!(
                f,
                "the TPM is present but not usable right now: {reason}; no key was created and no \
                 software key was substituted. Make sure the TPM and the TPM Base Services are \
                 enabled and ready, then retry"
            ),
            Self::ProviderNotReady {
                backend: Backend::Software,
                reason,
            } => write!(
                f,
                "the software key storage provider is present but not usable right now: \
                 {reason}; no key was created"
            ),
            Self::Open { backend, error } => write!(
                f,
                "opening the existing {backend} device key failed: {error}; no new key was created"
            ),
            Self::PublicKey { backend, error } => {
                write!(f, "reading the {backend} public key failed: {error}")
            }
            Self::TpmUnusable(problem) => write!(f, "{problem}; software fallback is disabled"),
            Self::Create { backend, error } => {
                write!(f, "creating the {backend} key failed: {error}")
            }
            Self::SelfTest { backend, error } => write!(
                f,
                "the new {backend} key failed its signing self-test and was deleted: {error}"
            ),
            Self::Cleanup { backend, error } => write!(
                f,
                "deleting the {backend} key that failed its self-test failed: {error}"
            ),
        }
    }
}

impl std::error::Error for KeyError {}

const SELF_TEST_MESSAGE: &[u8] = b"gateinto device key self-test";

fn self_test_digest() -> aws_lc_rs::digest::Digest {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, SELF_TEST_MESSAGE)
}

fn verify_self_test(point: &P256Point, signature: &[u8]) -> bool {
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
        .verify(SELF_TEST_MESSAGE, signature)
        .is_ok()
}

fn self_test<S: KeyStore>(store: &S, key: &S::Key) -> Result<P256Point, String> {
    let point = store.public_point(key).map_err(|error| error.to_string())?;
    let signature = store
        .sign_digest(key, self_test_digest().as_ref())
        .map_err(|error| error.to_string())?;
    if verify_self_test(&point, &signature) {
        Ok(point)
    } else {
        Err("the signature did not verify".to_owned())
    }
}

fn open_existing<S: KeyStore>(
    store: &S,
    backend: Backend,
    name: &KeyName,
) -> Result<Option<DeviceKey<S::Key>>, KeyError> {
    match store.open(backend, name) {
        Ok(key) => {
            let point = store
                .public_point(&key)
                .map_err(|error| KeyError::PublicKey { backend, error })?;
            Ok(Some(DeviceKey {
                backend,
                point,
                key,
            }))
        }
        Err(StoreError::NotFound | StoreError::ProviderUnavailable(_)) => Ok(None),
        Err(StoreError::ProviderNotReady(reason)) => {
            Err(KeyError::ProviderNotReady { backend, reason })
        }
        Err(error) => Err(KeyError::Open { backend, error }),
    }
}

enum Found<K> {
    Nothing,
    One(DeviceKey<K>),
    Both {
        tpm: DeviceKey<K>,
        duplicate: DuplicateKeys,
    },
}

fn find<S: KeyStore>(store: &S, name: &KeyName) -> Result<Found<S::Key>, KeyError> {
    let tpm = open_existing(store, Backend::Tpm, name)?;
    let software = open_existing(store, Backend::Software, name)?;
    Ok(match (tpm, software) {
        (Some(tpm), Some(software)) => Found::Both {
            duplicate: DuplicateKeys {
                name: name.clone(),
                tpm_fingerprint: tpm.fingerprint(),
                software_fingerprint: software.fingerprint(),
            },
            tpm,
        },
        (Some(key), None) | (None, Some(key)) => Found::One(key),
        (None, None) => Found::Nothing,
    })
}

fn create_tested<S: KeyStore>(
    store: &S,
    backend: Backend,
    name: &KeyName,
) -> Result<DeviceKey<S::Key>, KeyError> {
    let key = store
        .create(backend, name)
        .map_err(|error| KeyError::Create { backend, error })?;
    match self_test(store, &key) {
        Ok(point) => Ok(DeviceKey {
            backend,
            point,
            key,
        }),
        Err(error) => {
            store
                .delete(key)
                .map_err(|error| KeyError::Cleanup { backend, error })?;
            Err(KeyError::SelfTest { backend, error })
        }
    }
}

pub fn init<S: KeyStore>(
    store: &S,
    name: &KeyName,
    options: InitOptions,
) -> Result<(DeviceKey<S::Key>, Provenance), KeyError> {
    match find(store, name)? {
        Found::One(key) => return Ok((key, Provenance::Reused)),
        Found::Both { duplicate, .. } => return Err(KeyError::Duplicate(duplicate)),
        Found::Nothing => {}
    }
    if options.backend == Backend::Software {
        return Ok((
            create_tested(store, Backend::Software, name)?,
            Provenance::Created,
        ));
    }
    let problem = match create_tested(store, Backend::Tpm, name) {
        Ok(key) => return Ok((key, Provenance::Created)),
        Err(KeyError::Create {
            error: StoreError::ProviderUnavailable(reason),
            ..
        }) => TpmProblem::Unavailable(reason),
        Err(KeyError::Create { error, .. }) => TpmProblem::CreateFailed(error.to_string()),
        Err(KeyError::SelfTest { error, .. }) => TpmProblem::SelfTestFailed(error),
        Err(error) => return Err(error),
    };
    if !options.allow_software_fallback {
        return Err(KeyError::TpmUnusable(problem));
    }
    let key = create_tested(store, Backend::Software, name)?;
    Ok((key, Provenance::CreatedAfterFallback(problem)))
}

pub fn info<S: KeyStore>(
    store: &S,
    name: &KeyName,
) -> Result<(DeviceKey<S::Key>, Option<DuplicateKeys>), KeyError> {
    match find(store, name)? {
        Found::One(key) => Ok((key, None)),
        Found::Both { tpm, duplicate } => Ok((tpm, Some(duplicate))),
        Found::Nothing => Err(KeyError::NotFound(name.clone())),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpkiConfirmation(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidSpkiConfirmation;

impl fmt::Display for InvalidSpkiConfirmation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected 16 to 64 hexadecimal digits of the SPKI SHA-256 fingerprint")
    }
}

impl std::error::Error for InvalidSpkiConfirmation {}

impl FromStr for SpkiConfirmation {
    type Err = InvalidSpkiConfirmation;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if (16..=64).contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            Ok(Self(text.to_ascii_lowercase()))
        } else {
            Err(InvalidSpkiConfirmation)
        }
    }
}

impl SpkiConfirmation {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn matches(&self, fingerprint: &str) -> bool {
        fingerprint.starts_with(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgedKey {
    pub backend: Backend,
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PurgeError {
    Key(KeyError),
    Mismatch {
        fingerprint: String,
        confirmed: String,
    },
    Delete {
        backend: Backend,
        error: StoreError,
    },
}

impl fmt::Display for PurgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(error) => write!(f, "{error}"),
            Self::Mismatch {
                fingerprint,
                confirmed,
            } => write!(
                f,
                "the device key has spki-sha256 {fingerprint}, which does not start with the \
                 confirmed {confirmed}; nothing was deleted"
            ),
            Self::Delete { backend, error } => {
                write!(f, "deleting the {backend} device key failed: {error}")
            }
        }
    }
}

impl std::error::Error for PurgeError {}

pub fn confirmed<S: KeyStore>(
    store: &S,
    name: &KeyName,
    confirmation: &SpkiConfirmation,
) -> Result<DeviceKey<S::Key>, PurgeError> {
    let key = match find(store, name).map_err(PurgeError::Key)? {
        Found::One(key) => key,
        Found::Both { duplicate, .. } => {
            return Err(PurgeError::Key(KeyError::Duplicate(duplicate)));
        }
        Found::Nothing => return Err(PurgeError::Key(KeyError::NotFound(name.clone()))),
    };
    let fingerprint = key.fingerprint();
    if !confirmation.matches(&fingerprint) {
        return Err(PurgeError::Mismatch {
            fingerprint,
            confirmed: confirmation.as_str().to_owned(),
        });
    }
    Ok(key)
}

pub fn purge<S: KeyStore>(
    store: &S,
    name: &KeyName,
    confirmation: &SpkiConfirmation,
) -> Result<PurgedKey, PurgeError> {
    let key = confirmed(store, name, confirmation)?;
    let fingerprint = key.fingerprint();
    let backend = key.backend;
    store
        .delete(key.key)
        .map_err(|error| PurgeError::Delete { backend, error })?;
    Ok(PurgedKey {
        backend,
        fingerprint,
    })
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

    use super::*;

    #[derive(Clone, Debug)]
    struct FakeKey {
        backend: Backend,
        pair: Rc<EcdsaKeyPair>,
        broken: bool,
    }

    #[derive(Default)]
    struct FakeStore {
        keys: RefCell<HashMap<Backend, FakeKey>>,
        open_errors: HashMap<Backend, StoreError>,
        create_errors: HashMap<Backend, StoreError>,
        broken_signer: Vec<Backend>,
        delete_error: Option<StoreError>,
        calls: RefCell<Vec<String>>,
    }

    impl FakeStore {
        fn with_key(self, backend: Backend) -> Self {
            self.keys
                .borrow_mut()
                .insert(backend, new_key(backend, false));
            self
        }

        fn open_error(mut self, backend: Backend, error: StoreError) -> Self {
            self.open_errors.insert(backend, error);
            self
        }

        fn create_error(mut self, backend: Backend, error: StoreError) -> Self {
            self.create_errors.insert(backend, error);
            self
        }

        fn tpm_unavailable(self) -> Self {
            let unavailable = StoreError::ProviderUnavailable("no TPM".to_owned());
            self.open_error(Backend::Tpm, unavailable.clone())
                .create_error(Backend::Tpm, unavailable)
        }

        fn point(&self, backend: Backend) -> Option<P256Point> {
            self.keys
                .borrow()
                .get(&backend)
                .map(|key| key.pair.public_key().as_ref().try_into().unwrap())
        }

        fn backends(&self) -> Vec<Backend> {
            let mut backends: Vec<_> = self.keys.borrow().keys().copied().collect();
            backends.sort_by_key(|backend| *backend == Backend::Software);
            backends
        }

        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }

        fn created(&self) -> Vec<String> {
            self.calls()
                .into_iter()
                .filter(|call| call.starts_with("create"))
                .collect()
        }
    }

    fn new_key(backend: Backend, broken: bool) -> FakeKey {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .unwrap();
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref()).unwrap();
        FakeKey {
            backend,
            pair: Rc::new(pair),
            broken,
        }
    }

    impl KeyStore for FakeStore {
        type Key = FakeKey;

        fn open(&self, backend: Backend, name: &KeyName) -> Result<FakeKey, StoreError> {
            self.calls
                .borrow_mut()
                .push(format!("open {backend} {name}"));
            if let Some(error) = self.open_errors.get(&backend) {
                return Err(error.clone());
            }
            self.keys
                .borrow()
                .get(&backend)
                .cloned()
                .ok_or(StoreError::NotFound)
        }

        fn create(&self, backend: Backend, name: &KeyName) -> Result<FakeKey, StoreError> {
            self.calls
                .borrow_mut()
                .push(format!("create {backend} {name}"));
            if let Some(error) = self.create_errors.get(&backend) {
                return Err(error.clone());
            }
            let key = new_key(backend, self.broken_signer.contains(&backend));
            let previous = self.keys.borrow_mut().insert(backend, key.clone());
            assert!(previous.is_none(), "created a second {backend} key");
            Ok(key)
        }

        fn delete(&self, key: FakeKey) -> Result<(), StoreError> {
            self.calls
                .borrow_mut()
                .push(format!("delete {}", key.backend));
            if let Some(error) = &self.delete_error {
                return Err(error.clone());
            }
            self.keys.borrow_mut().remove(&key.backend);
            Ok(())
        }

        fn public_point(&self, key: &FakeKey) -> Result<P256Point, StoreError> {
            Ok(key.pair.public_key().as_ref().try_into().unwrap())
        }

        fn sign_digest(&self, key: &FakeKey, digest: &[u8]) -> Result<Vec<u8>, StoreError> {
            assert_eq!(digest, self_test_digest().as_ref());
            if key.broken {
                return Ok(vec![0; 64]);
            }
            let signature = key
                .pair
                .sign(&SystemRandom::new(), SELF_TEST_MESSAGE)
                .unwrap();
            Ok(signature.as_ref().to_vec())
        }
    }

    fn name() -> KeyName {
        KeyName::default()
    }

    fn no_fallback() -> InitOptions {
        InitOptions {
            allow_software_fallback: false,
            ..InitOptions::default()
        }
    }

    #[test]
    fn existing_tpm_key_is_reused() {
        let store = FakeStore::default().with_key(Backend::Tpm);

        let (key, provenance) = init(&store, &name(), InitOptions::default()).unwrap();

        assert_eq!(provenance, Provenance::Reused);
        assert_eq!(key.backend, Backend::Tpm);
        assert_eq!(Some(key.point), store.point(Backend::Tpm));
        assert!(store.created().is_empty());
    }

    #[test]
    fn existing_software_key_is_reused() {
        let store = FakeStore::default().with_key(Backend::Software);

        let (key, provenance) = init(&store, &name(), InitOptions::default()).unwrap();

        assert_eq!(provenance, Provenance::Reused);
        assert_eq!(key.backend, Backend::Software);
        assert_eq!(Some(key.point), store.point(Backend::Software));
        assert!(store.created().is_empty());
    }

    #[test]
    fn existing_key_is_reused_even_when_tpm_is_unavailable() {
        let store = FakeStore::default()
            .with_key(Backend::Software)
            .tpm_unavailable();

        let (key, provenance) = init(&store, &name(), no_fallback()).unwrap();

        assert_eq!(provenance, Provenance::Reused);
        assert_eq!(key.backend, Backend::Software);
        assert!(store.created().is_empty());
    }

    #[test]
    fn existing_tpm_key_is_reused_when_software_backend_is_requested() {
        let store = FakeStore::default().with_key(Backend::Tpm);
        let options = InitOptions {
            backend: Backend::Software,
            ..InitOptions::default()
        };

        let (key, provenance) = init(&store, &name(), options).unwrap();

        assert_eq!(provenance, Provenance::Reused);
        assert_eq!(key.backend, Backend::Tpm);
        assert!(store.created().is_empty());
    }

    #[test]
    fn tpm_open_failure_other_than_not_found_is_an_error_and_creates_nothing() {
        let failure = StoreError::Failed("NTE_PERM (0x80090010)".to_owned());
        let store = FakeStore::default().open_error(Backend::Tpm, failure.clone());

        let error = init(&store, &name(), InitOptions::default()).unwrap_err();

        assert_eq!(
            error,
            KeyError::Open {
                backend: Backend::Tpm,
                error: failure
            }
        );
        assert!(store.created().is_empty());
        assert!(store.backends().is_empty());
    }

    #[test]
    fn software_open_failure_other_than_not_found_is_an_error_and_creates_nothing() {
        let failure = StoreError::Failed("NTE_PERM (0x80090010)".to_owned());
        let store = FakeStore::default()
            .tpm_unavailable()
            .open_error(Backend::Software, failure.clone());

        let error = init(&store, &name(), InitOptions::default()).unwrap_err();

        assert_eq!(
            error,
            KeyError::Open {
                backend: Backend::Software,
                error: failure
            }
        );
        assert!(store.created().is_empty());
    }

    fn tpm_not_ready() -> StoreError {
        StoreError::ProviderNotReady("TBS_E_SERVICE_NOT_RUNNING (0x80284008)".to_owned())
    }

    #[test]
    fn tpm_not_ready_during_lookup_stops_init_and_creates_nothing() {
        let store = FakeStore::default().open_error(Backend::Tpm, tpm_not_ready());

        let error = init(&store, &name(), InitOptions::default()).unwrap_err();

        assert_eq!(
            error,
            KeyError::ProviderNotReady {
                backend: Backend::Tpm,
                reason: "TBS_E_SERVICE_NOT_RUNNING (0x80284008)".to_owned()
            }
        );
        assert!(store.created().is_empty());
        assert!(store.backends().is_empty());
    }

    #[test]
    fn tpm_not_ready_during_lookup_is_an_error_even_with_a_software_key() {
        let store = FakeStore::default()
            .with_key(Backend::Software)
            .open_error(Backend::Tpm, tpm_not_ready());

        assert!(matches!(
            init(&store, &name(), InitOptions::default()).unwrap_err(),
            KeyError::ProviderNotReady {
                backend: Backend::Tpm,
                ..
            }
        ));
        assert!(matches!(
            info(&store, &name()).unwrap_err(),
            KeyError::ProviderNotReady {
                backend: Backend::Tpm,
                ..
            }
        ));
        assert!(store.created().is_empty());
        assert_eq!(store.backends(), vec![Backend::Software]);
    }

    #[test]
    fn tpm_not_ready_message_says_the_tpm_is_present_and_nothing_was_created() {
        let message = KeyError::ProviderNotReady {
            backend: Backend::Tpm,
            reason: "NTE_DEVICE_NOT_READY (0x80090030)".to_owned(),
        }
        .to_string();

        assert_eq!(
            message,
            "the TPM is present but not usable right now: NTE_DEVICE_NOT_READY (0x80090030); \
             no key was created and no software key was substituted. Make sure the TPM and the \
             TPM Base Services are enabled and ready, then retry"
        );
    }

    fn device_not_ready_with_tpm_probe(
        probe: Result<(), crate::identity::cng_status::TpmProbeError>,
    ) -> StoreError {
        crate::identity::cng_status::tpm_provider_error(
            crate::identity::cng_status::store_error(0x8009_0030),
            || probe,
        )
    }

    fn device_not_ready_without_a_tpm(store: FakeStore) -> FakeStore {
        let error = device_not_ready_with_tpm_probe(Err(
            crate::identity::cng_status::TpmProbeError::Status(0x8028_400F),
        ));
        store
            .open_error(Backend::Tpm, error.clone())
            .create_error(Backend::Tpm, error)
    }

    #[test]
    fn device_not_ready_without_a_tpm_falls_back_to_software_and_then_reuses_it() {
        let store = device_not_ready_without_a_tpm(FakeStore::default());

        let (created, provenance) = init(&store, &name(), InitOptions::default()).unwrap();

        assert!(matches!(
            provenance,
            Provenance::CreatedAfterFallback(TpmProblem::Unavailable(_))
        ));
        assert_eq!(created.backend, Backend::Software);
        let (reused, provenance) = init(&store, &name(), InitOptions::default()).unwrap();
        assert_eq!(provenance, Provenance::Reused);
        assert_eq!(reused.backend, Backend::Software);
        assert_eq!(reused.fingerprint(), created.fingerprint());
        assert_eq!(
            store.created(),
            vec![
                "create tpm gateinto-device-v1",
                "create software gateinto-device-v1"
            ]
        );
        let (shown, duplicate_keys) = info(&store, &name()).unwrap();
        assert_eq!(shown.fingerprint(), created.fingerprint());
        assert_eq!(duplicate_keys, None);
    }

    #[test]
    fn device_not_ready_without_tpm_device_info_falls_back_to_software() {
        let error = device_not_ready_with_tpm_probe(Err(
            crate::identity::cng_status::TpmProbeError::DeviceInfoUnavailable,
        ));
        let store = FakeStore::default()
            .open_error(Backend::Tpm, error.clone())
            .create_error(Backend::Tpm, error);

        let (created, provenance) = init(&store, &name(), InitOptions::default()).unwrap();

        assert_eq!(created.backend, Backend::Software);
        let Provenance::CreatedAfterFallback(problem) = provenance else {
            panic!("expected a software fallback, got {provenance:?}");
        };
        assert!(
            problem
                .to_string()
                .ends_with("Tbsi_GetDeviceInfo unavailable (expected on Windows 7)"),
            "{problem}"
        );
    }

    #[test]
    fn device_not_ready_without_a_tpm_and_disabled_fallback_creates_nothing() {
        let store = device_not_ready_without_a_tpm(FakeStore::default());

        let error = init(&store, &name(), no_fallback()).unwrap_err();

        assert!(matches!(
            error,
            KeyError::TpmUnusable(TpmProblem::Unavailable(_))
        ));
        assert!(
            error
                .to_string()
                .starts_with("the TPM provider is unavailable: ")
        );
        assert!(store.backends().is_empty());
    }

    #[test]
    fn device_not_ready_with_a_tpm_stops_init_and_creates_nothing() {
        let error = device_not_ready_with_tpm_probe(Ok(()));
        let store = FakeStore::default().open_error(Backend::Tpm, error.clone());

        assert!(matches!(
            init(&store, &name(), InitOptions::default()).unwrap_err(),
            KeyError::ProviderNotReady {
                backend: Backend::Tpm,
                ..
            }
        ));
        assert!(store.created().is_empty());
        assert!(store.backends().is_empty());

        let store = FakeStore::default()
            .with_key(Backend::Software)
            .open_error(Backend::Tpm, error);
        assert!(matches!(
            init(&store, &name(), InitOptions::default()).unwrap_err(),
            KeyError::ProviderNotReady {
                backend: Backend::Tpm,
                ..
            }
        ));
        assert!(store.created().is_empty());
    }

    #[test]
    fn software_provider_not_ready_during_lookup_is_an_error() {
        let store = FakeStore::default().open_error(
            Backend::Software,
            StoreError::ProviderNotReady("NTE_PROVIDER_DLL_FAIL (0x8009001d)".to_owned()),
        );

        let error = init(&store, &name(), InitOptions::default()).unwrap_err();

        assert_eq!(
            error.to_string(),
            "the software key storage provider is present but not usable right now: \
             NTE_PROVIDER_DLL_FAIL (0x8009001d); no key was created"
        );
        assert!(store.created().is_empty());
    }

    fn fingerprint_of(store: &FakeStore, backend: Backend) -> String {
        sha256_fingerprint(&p256_spki_der(&store.point(backend).unwrap()))
    }

    fn duplicate(store: &FakeStore) -> DuplicateKeys {
        DuplicateKeys {
            name: name(),
            tpm_fingerprint: fingerprint_of(store, Backend::Tpm),
            software_fingerprint: fingerprint_of(store, Backend::Software),
        }
    }

    #[test]
    fn keys_in_both_providers_stop_init_without_picking_one() {
        let store = FakeStore::default()
            .with_key(Backend::Tpm)
            .with_key(Backend::Software);

        let error = init(&store, &name(), InitOptions::default()).unwrap_err();

        assert_eq!(error, KeyError::Duplicate(duplicate(&store)));
        assert!(store.created().is_empty());
        assert_eq!(store.backends(), vec![Backend::Tpm, Backend::Software]);
    }

    #[test]
    fn duplicate_key_messages_name_both_backends() {
        let store = FakeStore::default()
            .with_key(Backend::Tpm)
            .with_key(Backend::Software);
        let duplicate = duplicate(&store);
        let found = format!(
            "device keys named \"gateinto-device-v1\" exist in both the tpm provider \
             (spki-sha256: {}) and the software provider (spki-sha256: {})",
            duplicate.tpm_fingerprint, duplicate.software_fingerprint
        );

        assert_eq!(duplicate.to_string(), found);
        assert_eq!(
            KeyError::Duplicate(duplicate).to_string(),
            format!(
                "{found}; refusing to choose one. Delete the key that should not be used and retry"
            )
        );
    }

    #[test]
    fn info_with_keys_in_both_providers_shows_the_tpm_key_and_reports_both() {
        let store = FakeStore::default()
            .with_key(Backend::Tpm)
            .with_key(Backend::Software);

        let (key, duplicate_keys) = info(&store, &name()).unwrap();

        assert_eq!(key.backend, Backend::Tpm);
        assert_eq!(Some(key.point), store.point(Backend::Tpm));
        assert_eq!(duplicate_keys, Some(duplicate(&store)));
        assert!(store.created().is_empty());
    }

    #[test]
    fn info_warning_for_duplicate_keys_names_both_backends_and_the_shown_key() {
        let store = FakeStore::default()
            .with_key(Backend::Tpm)
            .with_key(Backend::Software);
        let duplicate = duplicate(&store);

        assert_eq!(
            duplicate.info_warning(),
            format!(
                "warning: {duplicate}; showing the tpm key. `gateinto key init` refuses to run \
                 until one of them is deleted"
            )
        );
    }

    #[test]
    fn software_lookup_failure_is_an_error_even_with_a_tpm_key() {
        let failure = StoreError::Failed("NTE_PERM (0x80090010)".to_owned());
        let store = FakeStore::default()
            .with_key(Backend::Tpm)
            .open_error(Backend::Software, failure.clone());

        let error = init(&store, &name(), InitOptions::default()).unwrap_err();

        assert_eq!(
            error,
            KeyError::Open {
                backend: Backend::Software,
                error: failure
            }
        );
        assert!(store.created().is_empty());
    }

    #[test]
    fn new_tpm_key_is_created_and_self_tested() {
        let store = FakeStore::default();

        let (key, provenance) = init(&store, &name(), InitOptions::default()).unwrap();

        assert_eq!(provenance, Provenance::Created);
        assert_eq!(key.backend, Backend::Tpm);
        assert_eq!(store.backends(), vec![Backend::Tpm]);
        assert_eq!(Some(key.point), store.point(Backend::Tpm));
    }

    #[test]
    fn unavailable_tpm_falls_back_to_a_software_key() {
        let store = FakeStore::default().tpm_unavailable();

        let (key, provenance) = init(&store, &name(), InitOptions::default()).unwrap();

        assert_eq!(
            provenance,
            Provenance::CreatedAfterFallback(TpmProblem::Unavailable("no TPM".to_owned()))
        );
        assert_eq!(key.backend, Backend::Software);
        assert_eq!(store.backends(), vec![Backend::Software]);
    }

    #[test]
    fn failed_tpm_creation_falls_back_to_a_software_key() {
        let failure = StoreError::Failed("TPM_E_COMMAND_BLOCKED".to_owned());
        let store = FakeStore::default().create_error(Backend::Tpm, failure);

        let (key, provenance) = init(&store, &name(), InitOptions::default()).unwrap();

        assert_eq!(
            provenance,
            Provenance::CreatedAfterFallback(TpmProblem::CreateFailed(
                "TPM_E_COMMAND_BLOCKED".to_owned()
            ))
        );
        assert_eq!(key.backend, Backend::Software);
    }

    #[test]
    fn failed_tpm_self_test_deletes_the_half_created_key_and_falls_back() {
        let store = FakeStore {
            broken_signer: vec![Backend::Tpm],
            ..FakeStore::default()
        };

        let (key, provenance) = init(&store, &name(), InitOptions::default()).unwrap();

        assert!(matches!(
            provenance,
            Provenance::CreatedAfterFallback(TpmProblem::SelfTestFailed(_))
        ));
        assert_eq!(key.backend, Backend::Software);
        assert!(store.calls().contains(&"delete tpm".to_owned()));
        assert_eq!(store.backends(), vec![Backend::Software]);
    }

    #[test]
    fn half_created_tpm_key_that_cannot_be_deleted_stops_the_fallback() {
        let failure = StoreError::Failed("NTE_PERM".to_owned());
        let store = FakeStore {
            broken_signer: vec![Backend::Tpm],
            delete_error: Some(failure.clone()),
            ..FakeStore::default()
        };

        let error = init(&store, &name(), InitOptions::default()).unwrap_err();

        assert_eq!(
            error,
            KeyError::Cleanup {
                backend: Backend::Tpm,
                error: failure
            }
        );
        assert_eq!(store.created(), vec!["create tpm gateinto-device-v1"]);
    }

    #[test]
    fn disabled_fallback_is_an_error() {
        let store = FakeStore::default().tpm_unavailable();

        let error = init(&store, &name(), no_fallback()).unwrap_err();

        assert_eq!(
            error,
            KeyError::TpmUnusable(TpmProblem::Unavailable("no TPM".to_owned()))
        );
        assert_eq!(store.created(), vec!["create tpm gateinto-device-v1"]);
        assert!(store.backends().is_empty());
    }

    #[test]
    fn disabled_fallback_still_deletes_a_tpm_key_that_failed_its_self_test() {
        let store = FakeStore {
            broken_signer: vec![Backend::Tpm],
            ..FakeStore::default()
        };

        let error = init(&store, &name(), no_fallback()).unwrap_err();

        assert!(matches!(
            error,
            KeyError::TpmUnusable(TpmProblem::SelfTestFailed(_))
        ));
        assert!(store.backends().is_empty());
    }

    #[test]
    fn software_backend_skips_the_tpm() {
        let store = FakeStore::default();
        let options = InitOptions {
            backend: Backend::Software,
            allow_software_fallback: false,
        };

        let (key, provenance) = init(&store, &name(), options).unwrap();

        assert_eq!(provenance, Provenance::Created);
        assert_eq!(key.backend, Backend::Software);
        assert_eq!(store.created(), vec!["create software gateinto-device-v1"]);
    }

    #[test]
    fn failed_software_creation_is_an_error() {
        let failure = StoreError::Failed("NTE_NO_MEMORY".to_owned());
        let store = FakeStore::default()
            .tpm_unavailable()
            .create_error(Backend::Software, failure.clone());

        let error = init(&store, &name(), InitOptions::default()).unwrap_err();

        assert_eq!(
            error,
            KeyError::Create {
                backend: Backend::Software,
                error: failure
            }
        );
    }

    #[test]
    fn failed_software_self_test_deletes_the_key_and_is_an_error() {
        let store = FakeStore {
            broken_signer: vec![Backend::Software],
            ..FakeStore::default()
        }
        .tpm_unavailable();

        let error = init(&store, &name(), InitOptions::default()).unwrap_err();

        assert!(matches!(
            error,
            KeyError::SelfTest {
                backend: Backend::Software,
                ..
            }
        ));
        assert!(store.backends().is_empty());
    }

    #[test]
    fn info_opens_the_existing_key() {
        let store = FakeStore::default().with_key(Backend::Software);

        let (key, duplicate_keys) = info(&store, &name()).unwrap();

        assert_eq!(key.backend, Backend::Software);
        assert_eq!(Some(key.point), store.point(Backend::Software));
        assert_eq!(duplicate_keys, None);
    }

    #[test]
    fn info_never_creates_a_key() {
        let store = FakeStore::default();

        let error = info(&store, &name()).unwrap_err();

        assert_eq!(error, KeyError::NotFound(name()));
        assert!(store.created().is_empty());
    }

    #[test]
    fn info_reports_open_failures() {
        let failure = StoreError::Failed("NTE_PERM".to_owned());
        let store = FakeStore::default().open_error(Backend::Tpm, failure.clone());

        assert_eq!(
            info(&store, &name()).unwrap_err(),
            KeyError::Open {
                backend: Backend::Tpm,
                error: failure
            }
        );
    }

    #[test]
    fn info_and_init_agree_on_the_fingerprint() {
        let store = FakeStore::default();
        let (created, _) = init(&store, &name(), InitOptions::default()).unwrap();

        let (opened, _) = info(&store, &name()).unwrap();

        assert_eq!(opened.fingerprint(), created.fingerprint());
        assert_eq!(opened.backend, created.backend);
    }

    fn confirm(store: &FakeStore, backend: Backend, len: usize) -> SpkiConfirmation {
        fingerprint_of(store, backend)[..len].parse().unwrap()
    }

    #[test]
    fn spki_confirmations_are_16_to_64_hex_digits() {
        let digits = "0123456789abcdef".repeat(4);
        for len in [16, 40, 64] {
            assert_eq!(
                digits[..len].parse::<SpkiConfirmation>().unwrap().as_str(),
                &digits[..len]
            );
        }
        assert_eq!(
            "0123456789ABCDEF"
                .parse::<SpkiConfirmation>()
                .unwrap()
                .as_str(),
            "0123456789abcdef"
        );
        for text in [
            "",
            &digits[..15],
            &format!("{digits}0"),
            "0123456789abcdeg",
            " 0123456789abcdef",
            "0123:456789abcdef",
        ] {
            assert_eq!(
                text.parse::<SpkiConfirmation>(),
                Err(InvalidSpkiConfirmation),
                "{text:?}"
            );
        }
    }

    #[test]
    fn spki_confirmations_match_fingerprints_by_prefix() {
        let fingerprint = "0123456789abcdef".repeat(4);
        let confirmation: SpkiConfirmation = fingerprint[..20].parse().unwrap();
        assert!(confirmation.matches(&fingerprint));
        assert!(!confirmation.matches(&"f".repeat(64)));
        assert!(!confirmation.matches(&fingerprint[..19]));
    }

    #[test]
    fn purge_deletes_the_confirmed_key() {
        let store = FakeStore::default().with_key(Backend::Software);
        let fingerprint = fingerprint_of(&store, Backend::Software);

        let purged = purge(&store, &name(), &confirm(&store, Backend::Software, 16)).unwrap();

        assert_eq!(
            purged,
            PurgedKey {
                backend: Backend::Software,
                fingerprint
            }
        );
        assert!(store.backends().is_empty());
        assert_eq!(
            store.calls(),
            vec![
                "open tpm gateinto-device-v1",
                "open software gateinto-device-v1",
                "delete software"
            ]
        );
    }

    #[test]
    fn purge_accepts_the_full_fingerprint() {
        let store = FakeStore::default().with_key(Backend::Tpm);

        let purged = purge(&store, &name(), &confirm(&store, Backend::Tpm, 64)).unwrap();

        assert_eq!(purged.backend, Backend::Tpm);
        assert!(store.backends().is_empty());
    }

    #[test]
    fn purge_with_another_fingerprint_deletes_nothing() {
        let store = FakeStore::default().with_key(Backend::Software);
        let fingerprint = fingerprint_of(&store, Backend::Software);
        let wrong = if fingerprint.starts_with('0') {
            "1"
        } else {
            "0"
        }
        .repeat(16);

        let error = purge(&store, &name(), &wrong.parse().unwrap()).unwrap_err();

        assert_eq!(
            error,
            PurgeError::Mismatch {
                fingerprint,
                confirmed: wrong
            }
        );
        assert_eq!(store.backends(), vec![Backend::Software]);
        assert!(!store.calls().iter().any(|call| call.starts_with("delete")));
    }

    #[test]
    fn purge_without_a_key_deletes_nothing() {
        let store = FakeStore::default();

        let error = purge(&store, &name(), &"0".repeat(16).parse().unwrap()).unwrap_err();

        assert_eq!(error, PurgeError::Key(KeyError::NotFound(name())));
        assert!(!store.calls().iter().any(|call| call.starts_with("delete")));
    }

    #[test]
    fn purge_refuses_to_choose_between_keys_in_both_providers() {
        let store = FakeStore::default()
            .with_key(Backend::Tpm)
            .with_key(Backend::Software);

        let error = purge(&store, &name(), &confirm(&store, Backend::Tpm, 64)).unwrap_err();

        assert_eq!(
            error,
            PurgeError::Key(KeyError::Duplicate(duplicate(&store)))
        );
        assert_eq!(store.backends(), vec![Backend::Tpm, Backend::Software]);
    }

    #[test]
    fn purge_reports_a_failed_delete() {
        let failure = StoreError::Failed("NTE_PERM".to_owned());
        let store = FakeStore {
            delete_error: Some(failure.clone()),
            ..FakeStore::default()
        }
        .with_key(Backend::Software);

        let error = purge(&store, &name(), &confirm(&store, Backend::Software, 16)).unwrap_err();

        assert_eq!(
            error,
            PurgeError::Delete {
                backend: Backend::Software,
                error: failure
            }
        );
    }

    #[test]
    fn init_after_purge_creates_a_new_key() {
        let store = FakeStore::default().tpm_unavailable();
        let (first, _) = init(&store, &name(), InitOptions::default()).unwrap();
        let (again, provenance) = init(&store, &name(), InitOptions::default()).unwrap();
        assert_eq!(provenance, Provenance::Reused);
        assert_eq!(again.fingerprint(), first.fingerprint());

        purge(&store, &name(), &first.fingerprint().parse().unwrap()).unwrap();
        let (second, provenance) = init(&store, &name(), InitOptions::default()).unwrap();

        assert_ne!(provenance, Provenance::Reused);
        assert_ne!(second.fingerprint(), first.fingerprint());
    }

    #[test]
    fn providers_are_the_microsoft_cng_providers() {
        assert_eq!(
            Backend::Tpm.provider(),
            "Microsoft Platform Crypto Provider"
        );
        assert_eq!(
            Backend::Software.provider(),
            "Microsoft Software Key Storage Provider"
        );
    }

    #[test]
    fn key_names_must_be_non_empty_and_free_of_nul() {
        assert_eq!("".parse::<KeyName>(), Err(InvalidKeyName::Empty));
        assert_eq!("a\0b".parse::<KeyName>(), Err(InvalidKeyName::ContainsNul));
        assert_eq!("custom".parse::<KeyName>().unwrap().as_str(), "custom");
        assert_eq!(KeyName::default().as_str(), "gateinto-device-v1");
    }

    #[test]
    fn summary_lists_backend_algorithm_fingerprint_and_trust() {
        let key = DeviceKey {
            backend: Backend::Software,
            point: [4; 65],
            key: (),
        };

        assert_eq!(
            key.summary(),
            format!(
                "backend: software\nalgorithm: ECDSA P-256\nspki-sha256: {}\ntrust: {}\n",
                key.fingerprint(),
                trust_note(Backend::Software)
            )
        );
    }

    #[test]
    fn trust_notes_describe_the_protection() {
        assert_eq!(
            trust_note(Backend::Tpm),
            "hardware-protected private key (TPM)"
        );
        assert_eq!(
            trust_note(Backend::Software),
            "non-exportable flag set, but not protected against copying by an administrator or malware running as the user"
        );
    }

    #[test]
    fn self_test_accepts_only_a_signature_by_the_key() {
        let key = new_key(Backend::Software, false);
        let other = new_key(Backend::Software, false);
        let store = FakeStore::default();
        let point = store.public_point(&key).unwrap();
        let signature = store
            .sign_digest(&key, self_test_digest().as_ref())
            .unwrap();
        let other_signature = store
            .sign_digest(&other, self_test_digest().as_ref())
            .unwrap();

        assert!(verify_self_test(&point, &signature));
        assert!(!verify_self_test(&point, &other_signature));
        assert!(!verify_self_test(&point, &[0; 64]));
    }
}
