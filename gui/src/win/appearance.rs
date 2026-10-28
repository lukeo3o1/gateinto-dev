use std::ffi::c_void;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::Globalization::{
    GetUserDefaultUILanguage, GetUserPreferredUILanguages, MUI_LANGUAGE_NAME,
};
use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, REG_SZ, RegSetKeyValueW};

use super::sys::{reg_dword, reg_string, wide};
use crate::i18n::{self, Language};
use crate::theme::{self, Choice};

pub fn choice() -> Choice {
    let value = reg_string(HKEY_CURRENT_USER, theme::KEY, theme::VALUE, 0);
    Choice::parse(value.ok().flatten().as_deref())
}

pub fn save(choice: Choice) -> Result<(), ()> {
    write(theme::KEY, theme::VALUE, choice.name())
}

pub fn language() -> i18n::Choice {
    let value = reg_string(HKEY_CURRENT_USER, i18n::KEY, i18n::VALUE, 0);
    i18n::Choice::parse(value.ok().flatten().as_deref())
}

pub fn save_language(choice: i18n::Choice) -> Result<(), ()> {
    write(i18n::KEY, i18n::VALUE, choice.name())
}

pub fn system_language() -> Language {
    let (mut count, mut len) = (0, 0);
    let sized =
        unsafe { GetUserPreferredUILanguages(MUI_LANGUAGE_NAME, &mut count, null_mut(), &mut len) };
    if sized != 0 && len > 0 {
        let mut list = vec![0u16; len as usize];
        let read = unsafe {
            GetUserPreferredUILanguages(MUI_LANGUAGE_NAME, &mut count, list.as_mut_ptr(), &mut len)
        };
        if read != 0
            && let Some(language) = i18n::from_tags(&i18n::names(&list))
        {
            return language;
        }
    }
    i18n::from_langid(unsafe { GetUserDefaultUILanguage() })
}

fn write(key: &str, name: &str, data: &str) -> Result<(), ()> {
    let (key, name, data) = (wide(key), wide(name), wide(data));
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
