use std::ffi::c_void;
use std::path::PathBuf;

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    HKEY_CURRENT_USER, REG_SZ, RegDeleteKeyValueW, RegSetKeyValueW,
};

use super::sys::{reg_string, wide};
use crate::settings;

const KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

fn exe() -> Option<PathBuf> {
    std::env::current_exe().ok()
}

fn value() -> Result<Option<String>, ()> {
    reg_string(HKEY_CURRENT_USER, KEY, settings::RUN_VALUE, 0)
}

pub fn enabled() -> Result<bool, ()> {
    let exe = exe().ok_or(())?;
    Ok(value()?.is_some_and(|value| settings::launches(&value, &exe)))
}

pub fn set(on: bool) -> Result<(), ()> {
    let (key, name) = (wide(KEY), wide(settings::RUN_VALUE));
    let code = if on {
        let command = exe().as_deref().and_then(settings::command).ok_or(())?;
        let data = wide(&command);
        unsafe {
            RegSetKeyValueW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                name.as_ptr(),
                REG_SZ,
                data.as_ptr().cast::<c_void>(),
                (data.len() * 2) as u32,
            )
        }
    } else {
        match unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, key.as_ptr(), name.as_ptr()) } {
            ERROR_FILE_NOT_FOUND => ERROR_SUCCESS,
            code => code,
        }
    };
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(())
    }
}
