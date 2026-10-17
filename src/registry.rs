use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR};
use windows_sys::Win32::System::Registry::{
    HKEY, KEY_READ, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ, RRF_RT_REG_SZ, RegCloseKey,
    RegCreateKeyExW, RegDeleteTreeW, RegGetValueW, RegOpenKeyExW, RegSetValueExW,
};

use crate::registration::RegistrationError;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

fn check(operation: &'static str, code: WIN32_ERROR) -> Result<(), RegistrationError> {
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(RegistrationError::Registry { operation, code })
    }
}

pub struct Key(HKEY);

impl Key {
    pub fn create(parent: HKEY, path: &str) -> Result<Self, RegistrationError> {
        let path = wide(path);
        let mut key = null_mut();
        // SAFETY: path is NUL-terminated and key receives an owned handle closed by Drop.
        let code = unsafe {
            RegCreateKeyExW(
                parent,
                path.as_ptr(),
                0,
                null(),
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                null(),
                &mut key,
                null_mut(),
            )
        };
        check("RegCreateKeyExW", code)?;
        Ok(Self(key))
    }

    pub fn raw(&self) -> HKEY {
        self.0
    }

    pub fn set_string(&self, name: Option<&str>, value: &str) -> Result<(), RegistrationError> {
        let name = name.map(wide);
        let value = wide(value);
        let bytes = u32::try_from(value.len() * 2).map_err(|_| RegistrationError::Registry {
            operation: "RegSetValueExW",
            code: 0,
        })?;
        // SAFETY: both strings are NUL-terminated and bytes is the size of value in bytes.
        let code = unsafe {
            RegSetValueExW(
                self.0,
                name.as_ref().map_or(null(), |name| name.as_ptr()),
                0,
                REG_SZ,
                value.as_ptr().cast(),
                bytes,
            )
        };
        check("RegSetValueExW", code)
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by RegCreateKeyExW or RegOpenKeyExW and is closed once.
        unsafe { RegCloseKey(self.0) };
    }
}

pub fn key_exists(root: HKEY, path: &str) -> Result<bool, RegistrationError> {
    let path = wide(path);
    let mut key = null_mut();
    // SAFETY: path is NUL-terminated and an opened key is closed by Key's Drop.
    let code = unsafe { RegOpenKeyExW(root, path.as_ptr(), 0, KEY_READ, &mut key) };
    if code == ERROR_FILE_NOT_FOUND {
        return Ok(false);
    }
    check("RegOpenKeyExW", code)?;
    drop(Key(key));
    Ok(true)
}

pub fn read_string(
    root: HKEY,
    path: &str,
    name: Option<&str>,
) -> Result<Option<String>, RegistrationError> {
    let path = wide(path);
    let name = name.map(wide);
    let name = name.as_ref().map_or(null(), |name| name.as_ptr());
    let mut size = 0u32;
    // SAFETY: path and name are NUL-terminated; a null buffer asks for the size only.
    let code = unsafe {
        RegGetValueW(
            root,
            path.as_ptr(),
            name,
            RRF_RT_REG_SZ,
            null_mut(),
            null_mut(),
            &mut size,
        )
    };
    if code == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    check("RegGetValueW", code)?;
    let mut buffer = vec![0u16; (size as usize).div_ceil(2)];
    // SAFETY: buffer holds size bytes, as RegGetValueW reported.
    let code = unsafe {
        RegGetValueW(
            root,
            path.as_ptr(),
            name,
            RRF_RT_REG_SZ,
            null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if code == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    check("RegGetValueW", code)?;
    let len = buffer
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(buffer.len());
    Ok(Some(String::from_utf16_lossy(&buffer[..len])))
}

pub fn delete_tree(root: HKEY, path: &str) -> Result<(), RegistrationError> {
    let path = wide(path);
    // SAFETY: path is NUL-terminated.
    check("RegDeleteTreeW", unsafe {
        RegDeleteTreeW(root, path.as_ptr())
    })
}
