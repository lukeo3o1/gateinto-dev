use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{GlobalFree, HWND};
use windows_sys::Win32::Security::Authentication::Identity::{GetUserNameExW, NameSamCompatible};
use windows_sys::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
};
use windows_sys::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
use windows_sys::Win32::System::Ole::CF_UNICODETEXT;
use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_SUBKEY_WOW6464KEY};
use windows_sys::Win32::System::SystemInformation::{
    ComputerNameNetBIOS, GetComputerNameExW, GetNativeSystemInfo, SYSTEM_INFO,
};

use zeroize::Zeroize;

use super::sys::{reg_string, wide};
use crate::device::System;

const CURRENT_VERSION: &str = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";

fn sized(read: impl Fn(*mut u16, &mut u32) -> bool) -> Option<String> {
    let mut size = 0u32;
    read(null_mut(), &mut size);
    for _ in 0..4 {
        let mut buf = vec![0u16; size.max(1) as usize + 1];
        let mut len = buf.len() as u32;
        if read(buf.as_mut_ptr(), &mut len) {
            buf.truncate((len as usize).min(buf.len()));
            let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            let text = String::from_utf16_lossy(&buf[..end]);
            return (!text.is_empty()).then_some(text);
        }
        if len as usize <= buf.len() {
            return None;
        }
        size = len;
    }
    None
}

fn computer() -> Option<String> {
    sized(|buf, len| unsafe { GetComputerNameExW(ComputerNameNetBIOS, buf, len) != 0 })
}

fn account() -> Option<String> {
    sized(|buf, len| unsafe { GetUserNameExW(NameSamCompatible, buf, len) })
}

fn version(name: &str) -> Option<String> {
    reg_string(
        HKEY_LOCAL_MACHINE,
        CURRENT_VERSION,
        name,
        RRF_SUBKEY_WOW6464KEY,
    )
    .ok()
    .flatten()
}

fn arch() -> u16 {
    let mut info = SYSTEM_INFO::default();
    unsafe {
        GetNativeSystemInfo(&mut info);
        info.Anonymous.Anonymous.wProcessorArchitecture
    }
}

pub fn system() -> System {
    System {
        computer: computer(),
        account: account(),
        product: version("ProductName"),
        build: version("CurrentBuild").and_then(|build| build.trim().parse().ok()),
        arch: Some(arch()),
    }
}

const PRIVATE_FORMATS: [&str; 3] = [
    "ExcludeClipboardContentFromMonitorProcessing",
    "CanIncludeInClipboardHistory",
    "CanUploadToCloudClipboard",
];

pub fn copy(hwnd: HWND, text: &str) -> bool {
    let units: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    open(hwnd, || unsafe { place(u32::from(CF_UNICODETEXT), &units) })
}

pub fn copy_secret(hwnd: HWND, text: &str) -> bool {
    let mut units: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let placed = open(hwnd, || unsafe {
        place(u32::from(CF_UNICODETEXT), &units)
            && PRIVATE_FORMATS.iter().all(|name| {
                let format = RegisterClipboardFormatW(wide(name).as_ptr());
                format != 0 && place(format, &[0, 0])
            })
    });
    units.zeroize();
    placed
}

fn open(hwnd: HWND, fill: impl FnOnce() -> bool) -> bool {
    unsafe {
        if OpenClipboard(hwnd) == 0 {
            return false;
        }
        let placed = EmptyClipboard() != 0 && fill();
        if !placed {
            EmptyClipboard();
        }
        CloseClipboard();
        placed
    }
}

unsafe fn place(format: u32, units: &[u16]) -> bool {
    unsafe {
        let memory = GlobalAlloc(GMEM_MOVEABLE, std::mem::size_of_val(units));
        if memory.is_null() {
            return false;
        }
        let target = GlobalLock(memory).cast::<u16>();
        if target.is_null() {
            GlobalFree(memory);
            return false;
        }
        target.copy_from_nonoverlapping(units.as_ptr(), units.len());
        GlobalUnlock(memory);
        if SetClipboardData(format, memory).is_null() {
            GlobalFree(memory);
            return false;
        }
        true
    }
}
