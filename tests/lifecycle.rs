use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use gateinto::identity::device_key::{
    self, Backend, InitOptions, KeyError, KeyName, KeyStore, Provenance, PurgeError,
    SpkiConfirmation, StoreError,
};
use gateinto::identity::encoding::P256Point;
use gateinto::lifecycle::{self, ResetError};

#[derive(Clone)]
struct MemoryKey {
    backend: Backend,
    name: KeyName,
    pair: Rc<EcdsaKeyPair>,
}

#[derive(Default)]
struct MemoryStore {
    keys: RefCell<HashMap<(Backend, String), Rc<EcdsaKeyPair>>>,
    tpm_unavailable: bool,
}

impl MemoryStore {
    fn without_tpm() -> Self {
        Self {
            tpm_unavailable: true,
            ..Self::default()
        }
    }

    fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .keys
            .borrow()
            .keys()
            .map(|(backend, name)| format!("{backend} {name}"))
            .collect();
        names.sort();
        names
    }
}

impl KeyStore for MemoryStore {
    type Key = MemoryKey;

    fn open(&self, backend: Backend, name: &KeyName) -> Result<MemoryKey, StoreError> {
        if backend == Backend::Tpm && self.tpm_unavailable {
            return Err(StoreError::ProviderUnavailable("no TPM".to_owned()));
        }
        let pair = self
            .keys
            .borrow()
            .get(&(backend, name.to_string()))
            .cloned()
            .ok_or(StoreError::NotFound)?;
        Ok(MemoryKey {
            backend,
            name: name.clone(),
            pair,
        })
    }

    fn create(&self, backend: Backend, name: &KeyName) -> Result<MemoryKey, StoreError> {
        if backend == Backend::Tpm && self.tpm_unavailable {
            return Err(StoreError::ProviderUnavailable("no TPM".to_owned()));
        }
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair = Rc::new(
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref()).unwrap(),
        );
        let previous = self
            .keys
            .borrow_mut()
            .insert((backend, name.to_string()), pair.clone());
        assert!(previous.is_none(), "created a second {backend} key {name}");
        Ok(MemoryKey {
            backend,
            name: name.clone(),
            pair,
        })
    }

    fn delete(&self, key: MemoryKey) -> Result<(), StoreError> {
        self.keys
            .borrow_mut()
            .remove(&(key.backend, key.name.to_string()))
            .map(drop)
            .ok_or(StoreError::NotFound)
    }

    fn public_point(&self, key: &MemoryKey) -> Result<P256Point, StoreError> {
        Ok(key.pair.public_key().as_ref().try_into().unwrap())
    }

    fn sign_digest(&self, key: &MemoryKey, _digest: &[u8]) -> Result<Vec<u8>, StoreError> {
        let message = b"gateinto device key self-test";
        let signature = key.pair.sign(&SystemRandom::new(), message).unwrap();
        Ok(signature.as_ref().to_vec())
    }
}

fn name() -> KeyName {
    KeyName::default()
}

fn setup(store: &MemoryStore) -> (String, Provenance) {
    let (key, provenance) = device_key::init(store, &name(), InitOptions::default()).unwrap();
    (key.fingerprint(), provenance)
}

fn confirmation(text: &str) -> SpkiConfirmation {
    text.parse().unwrap()
}

fn other_prefix(fingerprint: &str) -> String {
    if fingerprint.starts_with('0') {
        "1"
    } else {
        "0"
    }
    .repeat(16)
}

#[test]
fn setup_after_a_default_uninstall_and_reinstall_reuses_the_key() {
    let store = MemoryStore::without_tpm();

    let (first, provenance) = setup(&store);
    assert!(matches!(provenance, Provenance::CreatedAfterFallback(_)));
    let (again, provenance) = setup(&store);

    assert_eq!(provenance, Provenance::Reused);
    assert_eq!(again, first);
    assert_eq!(store.names(), vec!["software gateinto-device-v1"]);
}

#[tokio::test]
async fn reset_with_a_wrong_prefix_deletes_nothing_and_leaves_the_agent_running() {
    let store = MemoryStore::without_tpm();
    let (fingerprint, _) = setup(&store);
    let wrong = other_prefix(&fingerprint);
    let mut stopped = false;

    let error = lifecycle::purge_device_identity(&store, &name(), &confirmation(&wrong), async {
        stopped = true;
        Ok(())
    })
    .await
    .unwrap_err();

    assert_eq!(
        error,
        ResetError::Purge(PurgeError::Mismatch {
            fingerprint: fingerprint.clone(),
            confirmed: wrong
        })
    );
    assert!(!stopped);
    assert_eq!(setup(&store), (fingerprint, Provenance::Reused));
}

#[tokio::test]
async fn reset_stops_the_agent_then_deletes_the_key_and_setup_creates_a_new_one() {
    let store = MemoryStore::without_tpm();
    let (fingerprint, _) = setup(&store);
    let mut stopped = false;

    let purged = lifecycle::purge_device_identity(
        &store,
        &name(),
        &confirmation(&fingerprint[..16]),
        async {
            stopped = true;
            Ok(())
        },
    )
    .await
    .unwrap();

    assert!(stopped);
    assert_eq!(purged.fingerprint, fingerprint);
    assert_eq!(purged.backend, Backend::Software);
    assert!(store.names().is_empty());
    assert!(matches!(
        device_key::info(&store, &name()),
        Err(KeyError::NotFound(missing)) if missing == name()
    ));
    let (new, provenance) = setup(&store);
    assert_ne!(provenance, Provenance::Reused);
    assert_ne!(new, fingerprint);
}

#[tokio::test]
async fn reset_keeps_the_key_when_the_agent_cannot_be_stopped() {
    let store = MemoryStore::without_tpm();
    let (fingerprint, _) = setup(&store);

    let error =
        lifecycle::purge_device_identity(&store, &name(), &confirmation(&fingerprint), async {
            Err("access denied".to_owned())
        })
        .await
        .unwrap_err();

    assert_eq!(error, ResetError::StopAgent("access denied".to_owned()));
    assert_eq!(
        error.to_string(),
        "stopping the running agent failed: access denied; nothing was deleted"
    );
    assert_eq!(setup(&store), (fingerprint, Provenance::Reused));
}

#[tokio::test]
async fn reset_touches_only_the_named_key() {
    let store = MemoryStore::without_tpm();
    let other: KeyName = "another-program-key".parse().unwrap();
    store.create(Backend::Software, &other).unwrap();
    let (fingerprint, _) = setup(&store);

    lifecycle::purge_device_identity(&store, &name(), &confirmation(&fingerprint), async {
        Ok(())
    })
    .await
    .unwrap();

    assert_eq!(store.names(), vec!["software another-program-key"]);
}

#[tokio::test]
async fn reset_without_a_key_reports_it_and_leaves_the_agent_running() {
    let store = MemoryStore::without_tpm();
    let mut stopped = false;

    let error =
        lifecycle::purge_device_identity(&store, &name(), &confirmation(&"0".repeat(16)), async {
            stopped = true;
            Ok(())
        })
        .await
        .unwrap_err();

    assert_eq!(
        error,
        ResetError::Purge(PurgeError::Key(KeyError::NotFound(name())))
    );
    assert!(!stopped);
}
