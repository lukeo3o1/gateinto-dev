use std::ffi::c_void;
use std::path::PathBuf;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS, ERROR_UNSUPPORTED_TYPE,
};
use windows_sys::Win32::System::Registry::{
    HKEY_CURRENT_USER, REG_SZ, RRF_RT_REG_SZ, RegDeleteKeyValueW, RegGetValueW, RegSetKeyValueW,
};

use super::sys::wide;
use crate::settings;

const KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

fn exe() -> Option<PathBuf> {
    std::env::current_exe().ok()
}

fn value() -> Result<Option<String>, ()> {
    let (key, name) = (wide(KEY), wide(settings::RUN_VALUE));
    let mut buf: Vec<u16> = Vec::new();
    for _ in 0..4 {
        let mut size = (buf.len() * 2) as u32;
        let data = if buf.is_empty() {
            null_mut()
        } else {
            buf.as_mut_ptr().cast::<c_void>()
        };
        let code = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                name.as_ptr(),
                RRF_RT_REG_SZ,
                null_mut(),
                data,
                &mut size,
            )
        };
        match code {
            ERROR_SUCCESS if !buf.is_empty() => {
                let text = &buf[..(size as usize / 2).min(buf.len())];
                let end = text.iter().position(|&c| c == 0).unwrap_or(text.len());
                return Ok(Some(String::from_utf16_lossy(&text[..end])));
            }
            ERROR_SUCCESS | ERROR_MORE_DATA => buf = vec![0; (size as usize).div_ceil(2) + 1],
            ERROR_FILE_NOT_FOUND | ERROR_UNSUPPORTED_TYPE => return Ok(None),
            _ => return Err(()),
        }
    }
    Err(())
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
