use std::{fmt, mem, ptr};

use rustls_cng::error::CngError;
use rustls_cng::key::{NCryptKey, SignaturePadding};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALGORITHM, NCRYPT_EXPORT_POLICY_PROPERTY,
    NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG, NCryptCreatePersistedKey,
    NCryptDeleteKey, NCryptExportKey, NCryptFinalizeKey, NCryptFreeObject, NCryptOpenKey,
    NCryptOpenStorageProvider, NCryptSetProperty,
};

use crate::identity::cng_status;
use crate::identity::device_key::{Backend, KeyName, KeyStore, StoreError};
use crate::identity::encoding::{BlobError, P256Point, parse_ecc_public_blob};

pub const PLATFORM_CRYPTO_PROVIDER: &str = "Microsoft Platform Crypto Provider";
pub const SOFTWARE_KEY_STORAGE_PROVIDER: &str = "Microsoft Software Key Storage Provider";

fn provider_name(backend: Backend) -> &'static str {
    match backend {
        Backend::Tpm => PLATFORM_CRYPTO_PROVIDER,
        Backend::Software => SOFTWARE_KEY_STORAGE_PROVIDER,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PublicKeyError {
    Cng(CngError),
    Blob(BlobError),
}

impl fmt::Display for PublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cng(error) => write!(f, "exporting the public key failed: {error}"),
            Self::Blob(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for PublicKeyError {}

struct StorageProvider(NCRYPT_PROV_HANDLE);

impl StorageProvider {
    fn open(name: &str) -> Result<Self, CngError> {
        let name = wide(name);
        let mut handle = 0;
        CngError::from_hresult(unsafe {
            NCryptOpenStorageProvider(&mut handle, name.as_ptr(), 0)
        })?;
        Ok(Self(handle))
    }

    fn open_key(&self, name: &str) -> Result<CngKey, CngError> {
        let name = wide(name);
        let mut handle = 0;
        CngError::from_hresult(unsafe {
            NCryptOpenKey(self.0, &mut handle, name.as_ptr(), 0, NCRYPT_SILENT_FLAG)
        })?;
        Ok(CngKey(handle))
    }

    fn create_key(&self, name: &str) -> Result<CngKey, CngError> {
        let name = wide(name);
        let mut handle = 0;
        CngError::from_hresult(unsafe {
            NCryptCreatePersistedKey(
                self.0,
                &mut handle,
                BCRYPT_ECDSA_P256_ALGORITHM,
                name.as_ptr(),
                0,
                0,
            )
        })?;
        let key = CngKey(handle);
        let export_policy: u32 = 0;
        CngError::from_hresult(unsafe {
            NCryptSetProperty(
                key.0,
                NCRYPT_EXPORT_POLICY_PROPERTY,
                (&raw const export_policy).cast(),
                size_of::<u32>() as u32,
                NCRYPT_SILENT_FLAG,
            )
        })?;
        CngError::from_hresult(unsafe { NCryptFinalizeKey(key.0, NCRYPT_SILENT_FLAG) })?;
        Ok(key)
    }
}

impl Drop for StorageProvider {
    fn drop(&mut self) {
        unsafe { NCryptFreeObject(self.0) };
    }
}

#[derive(Debug)]
pub struct CngKey(NCRYPT_KEY_HANDLE);

impl CngKey {
    pub fn handle(&self) -> NCRYPT_KEY_HANDLE {
        self.0
    }

    fn into_ncrypt_key(self) -> NCryptKey {
        NCryptKey::new_owned(self.into_handle())
    }

    fn into_handle(self) -> NCRYPT_KEY_HANDLE {
        let handle = self.0;
        mem::forget(self);
        handle
    }

    fn delete(self) -> Result<(), CngError> {
        let handle = self.into_handle();
        let result = CngError::from_hresult(unsafe { NCryptDeleteKey(handle, NCRYPT_SILENT_FLAG) });
        if result.is_err() {
            unsafe { NCryptFreeObject(handle) };
        }
        result
    }
}

impl Drop for CngKey {
    fn drop(&mut self) {
        unsafe { NCryptFreeObject(self.0) };
    }
}

fn export_public_point(handle: NCRYPT_KEY_HANDLE) -> Result<P256Point, PublicKeyError> {
    let export = |output: &mut [u8], written: &mut u32| {
        CngError::from_hresult(unsafe {
            NCryptExportKey(
                handle,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                ptr::null(),
                if output.is_empty() {
                    ptr::null_mut()
                } else {
                    output.as_mut_ptr()
                },
                output.len() as u32,
                written,
                NCRYPT_SILENT_FLAG,
            )
        })
        .map_err(PublicKeyError::Cng)
    };
    let mut size = 0;
    export(&mut [], &mut size)?;
    let mut blob = vec![0u8; size as usize];
    export(&mut blob, &mut size)?;
    blob.truncate(size as usize);
    parse_ecc_public_blob(&blob).map_err(PublicKeyError::Blob)
}

fn store_error(error: CngError) -> StoreError {
    match error {
        CngError::WindowsError(code) => cng_status::store_error(code),
        other => StoreError::Failed(other.to_string()),
    }
}

fn open_provider(backend: Backend) -> Result<StorageProvider, StoreError> {
    StorageProvider::open(provider_name(backend)).map_err(|error| match error {
        CngError::WindowsError(code) => cng_status::provider_error(code),
        other => StoreError::Failed(other.to_string()),
    })
}

pub struct CngStore;

impl KeyStore for CngStore {
    type Key = CngKey;

    fn open(&self, backend: Backend, name: &KeyName) -> Result<CngKey, StoreError> {
        open_provider(backend)?
            .open_key(name.as_str())
            .map_err(store_error)
    }

    fn create(&self, backend: Backend, name: &KeyName) -> Result<CngKey, StoreError> {
        open_provider(backend)?
            .create_key(name.as_str())
            .map_err(store_error)
    }

    fn delete(&self, key: CngKey) -> Result<(), StoreError> {
        key.delete().map_err(store_error)
    }

    fn public_point(&self, key: &CngKey) -> Result<P256Point, StoreError> {
        export_public_point(key.0).map_err(|error| match error {
            PublicKeyError::Cng(error) => store_error(error),
            PublicKeyError::Blob(error) => StoreError::Failed(error.to_string()),
        })
    }

    fn sign_digest(&self, key: &CngKey, digest: &[u8]) -> Result<Vec<u8>, StoreError> {
        NCryptKey::new_borrowed(key.0)
            .sign(digest, SignaturePadding::None)
            .map_err(store_error)
    }
}

pub fn create_ecdsa_p256_key(provider: &str, name: &str) -> Result<NCryptKey, CngError> {
    Ok(StorageProvider::open(provider)?
        .create_key(name)?
        .into_ncrypt_key())
}

pub fn open_key(provider: &str, name: &str) -> Result<NCryptKey, CngError> {
    Ok(StorageProvider::open(provider)?
        .open_key(name)?
        .into_ncrypt_key())
}

pub fn delete_key(provider: &str, name: &str) -> Result<(), CngError> {
    StorageProvider::open(provider)?.open_key(name)?.delete()
}

pub fn export_public_key(key: &NCryptKey) -> Result<P256Point, PublicKeyError> {
    export_public_point(key.inner())
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}
