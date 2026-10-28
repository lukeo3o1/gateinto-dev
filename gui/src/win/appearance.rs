use std::ffi::c_void;

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, REG_SZ, RegSetKeyValueW};

use super::sys::{reg_dword, reg_string, wide};
use crate::theme::{self, Choice};

pub fn choice() -> Choice {
    let value = reg_string(HKEY_CURRENT_USER, theme::KEY, theme::VALUE, 0);
    Choice::parse(value.ok().flatten().as_deref())
}

pub fn save(choice: Choice) -> Result<(), ()> {
    let (key, name, data) = (wide(theme::KEY), wide(theme::VALUE), wide(choice.name()));
    let code = unsafe {
        RegSetKeyValueW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            name.as_ptr(),
            REG_SZ,
            data.as_ptr().cast::<c_void>(),
            (data.len() * 2) as u32,
        )
    };
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(())
    }
}

pub fn light_apps() -> bool {
    theme::light_apps(reg_dword(
        HKEY_CURRENT_USER,
        theme::PERSONALIZE,
        theme::APPS_USE_LIGHT,
    ))
}
