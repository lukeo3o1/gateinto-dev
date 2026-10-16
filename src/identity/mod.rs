pub mod cng_status;
pub mod device_key;
pub mod encoding;
#[cfg(windows)]
pub mod windows_cng;

#[derive(Debug)]
pub struct UnsupportedPlatform;

impl std::fmt::Display for UnsupportedPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("device keys are only supported on Windows")
    }
}

impl std::error::Error for UnsupportedPlatform {}

#[cfg(windows)]
pub type SystemStore = windows_cng::CngStore;

#[cfg(windows)]
pub fn system_store() -> Result<SystemStore, UnsupportedPlatform> {
    Ok(windows_cng::CngStore)
}

#[cfg(not(windows))]
pub enum SystemStore {}

#[cfg(not(windows))]
pub fn system_store() -> Result<SystemStore, UnsupportedPlatform> {
    Err(UnsupportedPlatform)
}

#[cfg(not(windows))]
impl device_key::KeyStore for SystemStore {
    type Key = std::convert::Infallible;

    fn open(
        &self,
        _: device_key::Backend,
        _: &device_key::KeyName,
    ) -> Result<Self::Key, device_key::StoreError> {
        match *self {}
    }

    fn create(
        &self,
        _: device_key::Backend,
        _: &device_key::KeyName,
    ) -> Result<Self::Key, device_key::StoreError> {
        match *self {}
    }

    fn delete(&self, _: Self::Key) -> Result<(), device_key::StoreError> {
        match *self {}
    }

    fn public_point(&self, _: &Self::Key) -> Result<encoding::P256Point, device_key::StoreError> {
        match *self {}
    }

    fn sign_digest(&self, _: &Self::Key, _: &[u8]) -> Result<Vec<u8>, device_key::StoreError> {
        match *self {}
    }
}
