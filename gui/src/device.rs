use gateinto::identity::UnsupportedPlatform;
use gateinto::identity::device_key::{self, Backend, KeyError, KeyName, KeyStore};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
    pub backend: Backend,
    pub name: KeyName,
    pub fingerprint: String,
    pub duplicate: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyState {
    Present(Key),
    Missing(KeyName),
    Unsupported(String),
    Failed(String),
}

pub fn key<S: KeyStore>(store: Result<S, UnsupportedPlatform>, name: &KeyName) -> KeyState {
    let store = match store {
        Ok(store) => store,
        Err(error) => return KeyState::Unsupported(error.to_string()),
    };
    match device_key::info(&store, name) {
        Ok((key, duplicate)) => KeyState::Present(Key {
            backend: key.backend,
            name: name.clone(),
            fingerprint: key.fingerprint(),
            duplicate: duplicate.is_some(),
        }),
        Err(KeyError::NotFound(name)) => KeyState::Missing(name),
        Err(error) => KeyState::Failed(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use gateinto::identity::device_key::StoreError;
    use gateinto::identity::encoding::{P256Point, p256_spki_der, sha256_fingerprint};

    use super::*;

    struct Store {
        tpm: Result<P256Point, StoreError>,
        software: Result<P256Point, StoreError>,
    }

    impl Store {
        fn slot(&self, backend: Backend) -> &Result<P256Point, StoreError> {
            match backend {
                Backend::Tpm => &self.tpm,
                Backend::Software => &self.software,
            }
        }
    }

    impl KeyStore for Store {
        type Key = Backend;

        fn open(&self, backend: Backend, _: &KeyName) -> Result<Backend, StoreError> {
            self.slot(backend)
                .as_ref()
                .map(|_| backend)
                .map_err(Clone::clone)
        }

        fn create(&self, _: Backend, _: &KeyName) -> Result<Backend, StoreError> {
            panic!("created a device key")
        }

        fn delete(&self, _: Backend) -> Result<(), StoreError> {
            panic!("deleted a device key")
        }

        fn public_point(&self, key: &Backend) -> Result<P256Point, StoreError> {
            self.slot(*key).clone()
        }

        fn sign_digest(&self, _: &Backend, _: &[u8]) -> Result<Vec<u8>, StoreError> {
            panic!("signed with the device key")
        }
    }

    fn point(byte: u8) -> P256Point {
        let mut point = [byte; 65];
        point[0] = 4;
        point
    }

    fn id(byte: u8) -> String {
        sha256_fingerprint(&p256_spki_der(&point(byte)))
    }

    fn store(
        tpm: Result<P256Point, StoreError>,
        software: Result<P256Point, StoreError>,
    ) -> Result<Store, UnsupportedPlatform> {
        Ok(Store { tpm, software })
    }

    fn present(backend: Backend, fingerprint: String, duplicate: bool) -> KeyState {
        KeyState::Present(Key {
            backend,
            name: KeyName::default(),
            fingerprint,
            duplicate,
        })
    }

    #[test]
    fn a_tpm_key_is_read_with_its_spki_fingerprint() {
        let state = key(
            store(Ok(point(1)), Err(StoreError::NotFound)),
            &KeyName::default(),
        );
        assert_eq!(state, present(Backend::Tpm, id(1), false));
    }

    #[test]
    fn a_software_key_is_reported_as_software() {
        let unavailable = Err(StoreError::ProviderUnavailable("no tpm".to_owned()));
        let state = key(store(unavailable, Ok(point(2))), &KeyName::default());
        assert_eq!(state, present(Backend::Software, id(2), false));
    }

    #[test]
    fn keys_in_both_providers_show_the_tpm_one_and_flag_the_duplicate() {
        let state = key(store(Ok(point(1)), Ok(point(2))), &KeyName::default());
        assert_eq!(state, present(Backend::Tpm, id(1), true));
    }

    #[test]
    fn no_key_is_missing_and_nothing_is_created() {
        let name: KeyName = "work".parse().unwrap();
        let state = key(
            store(Err(StoreError::NotFound), Err(StoreError::NotFound)),
            &name,
        );
        assert_eq!(state, KeyState::Missing(name));
    }

    #[test]
    fn a_store_error_is_a_failure() {
        let broken = Err(StoreError::Failed("access denied".to_owned()));
        let state = key(
            store(broken, Err(StoreError::NotFound)),
            &KeyName::default(),
        );
        assert_eq!(
            state,
            KeyState::Failed(
                "opening the existing tpm device key failed: access denied; no new key was created"
                    .to_owned()
            )
        );
    }

    #[test]
    fn another_platform_has_no_device_key() {
        let state = key::<Store>(Err(UnsupportedPlatform), &KeyName::default());
        assert_eq!(
            state,
            KeyState::Unsupported("device keys are only supported on Windows".to_owned())
        );
    }
}
