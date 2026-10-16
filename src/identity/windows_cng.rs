use std::ptr;

use rustls_cng::error::CngError;
use rustls_cng::key::NCryptKey;
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_ECCKEY_BLOB, BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALGORITHM,
    BCRYPT_ECDSA_PUBLIC_P256_MAGIC, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
    NCryptCreatePersistedKey, NCryptDeleteKey, NCryptExportKey, NCryptFinalizeKey,
    NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider,
};

pub const SOFTWARE_KEY_STORAGE_PROVIDER: &str = "Microsoft Software Key Storage Provider";

const P256_COORDINATE_LEN: usize = 32;
const ECC_BLOB_HEADER_LEN: usize = size_of::<BCRYPT_ECCKEY_BLOB>();

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

    fn open_key_handle(&self, name: &str) -> Result<NCRYPT_KEY_HANDLE, CngError> {
        let name = wide(name);
        let mut handle = 0;
        CngError::from_hresult(unsafe {
            NCryptOpenKey(self.0, &mut handle, name.as_ptr(), 0, NCRYPT_SILENT_FLAG)
        })?;
        Ok(handle)
    }
}

impl Drop for StorageProvider {
    fn drop(&mut self) {
        unsafe { NCryptFreeObject(self.0) };
    }
}

pub fn create_ecdsa_p256_key(provider: &str, name: &str) -> Result<NCryptKey, CngError> {
    let provider = StorageProvider::open(provider)?;
    let name = wide(name);
    let mut handle = 0;
    CngError::from_hresult(unsafe {
        NCryptCreatePersistedKey(
            provider.0,
            &mut handle,
            BCRYPT_ECDSA_P256_ALGORITHM,
            name.as_ptr(),
            0,
            0,
        )
    })?;
    let key = NCryptKey::new_owned(handle);
    CngError::from_hresult(unsafe { NCryptFinalizeKey(key.inner(), NCRYPT_SILENT_FLAG) })?;
    Ok(key)
}

pub fn open_key(provider: &str, name: &str) -> Result<NCryptKey, CngError> {
    let handle = StorageProvider::open(provider)?.open_key_handle(name)?;
    Ok(NCryptKey::new_owned(handle))
}

pub fn delete_key(provider: &str, name: &str) -> Result<(), CngError> {
    let handle = StorageProvider::open(provider)?.open_key_handle(name)?;
    let result = CngError::from_hresult(unsafe { NCryptDeleteKey(handle, NCRYPT_SILENT_FLAG) });
    if result.is_err() {
        unsafe { NCryptFreeObject(handle) };
    }
    result
}

pub fn export_public_key(key: &NCryptKey) -> Result<Vec<u8>, CngError> {
    let mut blob = vec![0u8; ECC_BLOB_HEADER_LEN + 2 * P256_COORDINATE_LEN];
    let mut written = 0;
    CngError::from_hresult(unsafe {
        NCryptExportKey(
            key.inner(),
            0,
            BCRYPT_ECCPUBLIC_BLOB,
            ptr::null(),
            blob.as_mut_ptr(),
            blob.len() as u32,
            &mut written,
            NCRYPT_SILENT_FLAG,
        )
    })?;

    let header = unsafe { ptr::read_unaligned(blob.as_ptr().cast::<BCRYPT_ECCKEY_BLOB>()) };
    if written as usize != blob.len()
        || header.dwMagic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC
        || header.cbKey as usize != P256_COORDINATE_LEN
    {
        return Err(CngError::UnsupportedKeyAlgorithmGroup);
    }

    let mut point = Vec::with_capacity(1 + 2 * P256_COORDINATE_LEN);
    point.push(0x04);
    point.extend_from_slice(&blob[ECC_BLOB_HEADER_LEN..]);
    Ok(point)
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}
