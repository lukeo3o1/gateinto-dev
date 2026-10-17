use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_INVALID_PARAMETER, ERROR_SUCCESS, WIN32_ERROR,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, KEY_WRITE,
    REG_OPTION_NON_VOLATILE, REG_SZ, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY, RegCloseKey,
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
            code: ERROR_INVALID_PARAMETER,
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
    let code =
        unsafe { RegOpenKeyExW(root, path.as_ptr(), 0, KEY_READ | KEY_WOW64_64KEY, &mut key) };
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
            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
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
            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
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

pub fn app_path(executable: &str) -> Option<std::path::PathBuf> {
    let path = format!(r"Software\Microsoft\Windows\CurrentVersion\App Paths\{executable}");
    [HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE]
        .into_iter()
        .find_map(|root| read_string(root, &path, None).ok().flatten())
        .map(|value| std::path::PathBuf::from(value.trim_matches('"')))
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;
    use windows_sys::Win32::System::Registry::{KEY_WOW64_64KEY, RegDeleteKeyExW};

    struct NativeLocalMachineKey(Vec<u16>);

    impl Drop for NativeLocalMachineKey {
        fn drop(&mut self) {
            // SAFETY: the path is NUL-terminated.
            unsafe { RegDeleteKeyExW(HKEY_LOCAL_MACHINE, self.0.as_ptr(), KEY_WOW64_64KEY, 0) };
        }
    }

    #[test]
    fn local_machine_keys_are_read_from_the_native_view() {
        let path = format!(r"SOFTWARE\Gateinto-test-{}", std::process::id());
        let wide_path = wide(&path);
        let mut key = null_mut();
        // SAFETY: the path is NUL-terminated and key receives an owned handle closed by Key's Drop.
        let code = unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                wide_path.as_ptr(),
                0,
                null(),
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE | KEY_WOW64_64KEY,
                null(),
                &mut key,
                null_mut(),
            )
        };
        if code == ERROR_ACCESS_DENIED && std::env::var_os("GITHUB_ACTIONS").is_none() {
            eprintln!("skipped: creating a key under HKLM needs an elevated process");
            return;
        }
        check("RegCreateKeyExW", code).unwrap();
        let _cleanup = NativeLocalMachineKey(wide_path);
        Key(key).set_string(None, "native").unwrap();

        assert!(key_exists(HKEY_LOCAL_MACHINE, &path).unwrap());
        assert_eq!(
            read_string(HKEY_LOCAL_MACHINE, &path, None)
                .unwrap()
                .as_deref(),
            Some("native")
        );
    }
}
