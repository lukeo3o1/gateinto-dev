use std::ffi::{CStr, c_void};

use windows_sys::Win32::Foundation::{HWND, RECT};
use windows_sys::Win32::Graphics::Dwm::{
    DWMWA_CAPTION_COLOR, DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND,
};
use windows_sys::Win32::Graphics::Gdi::{GetDC, GetDeviceCaps, LOGPIXELSY, ReleaseDC};
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleHandleW, GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_sys::Win32::UI::HiDpi::DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2;
use windows_sys::Win32::UI::WindowsAndMessaging::{AdjustWindowRectEx, SetProcessDPIAware};

use crate::color;

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn lookup(module: &str, name: &CStr, load: bool) -> Option<unsafe extern "system" fn() -> isize> {
    let module = wide(module);
    unsafe {
        let mut handle = GetModuleHandleW(module.as_ptr());
        if handle.is_null() && load {
            handle = LoadLibraryExW(
                module.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            );
        }
        if handle.is_null() {
            return None;
        }
        GetProcAddress(handle, name.as_ptr().cast())
    }
}

macro_rules! resolve {
    ($module:literal, $name:literal, $load:expr, $ty:ty) => {
        lookup($module, $name, $load).map(|f| unsafe { std::mem::transmute::<_, $ty>(f) })
    };
}

type SetContext = unsafe extern "system" fn(isize) -> i32;
type DpiForWindow = unsafe extern "system" fn(HWND) -> u32;
type AdjustForDpi = unsafe extern "system" fn(*mut RECT, u32, i32, u32, u32) -> i32;
type SetAttribute = unsafe extern "system" fn(HWND, u32, *const c_void, u32) -> i32;

pub fn enable_dpi_awareness() {
    let context = resolve!(
        "user32.dll",
        c"SetProcessDpiAwarenessContext",
        false,
        SetContext
    );
    let done = context
        .is_some_and(|f| unsafe { f(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 as isize) } != 0);
    if !done {
        unsafe { SetProcessDPIAware() };
    }
}

fn screen_dpi(hwnd: HWND) -> u32 {
    unsafe {
        let dc = GetDC(hwnd);
        let dpi = GetDeviceCaps(dc, LOGPIXELSY as i32);
        ReleaseDC(hwnd, dc);
        if dpi > 0 { dpi as u32 } else { 96 }
    }
}

pub fn window_dpi(hwnd: HWND) -> u32 {
    match resolve!("user32.dll", c"GetDpiForWindow", false, DpiForWindow) {
        Some(f) => match unsafe { f(hwnd) } {
            0 => screen_dpi(hwnd),
            dpi => dpi,
        },
        None => screen_dpi(hwnd),
    }
}

pub fn window_size_for_client(w: i32, h: i32, style: u32, ex_style: u32, dpi: u32) -> (i32, i32) {
    let mut r = RECT {
        left: 0,
        top: 0,
        right: w,
        bottom: h,
    };
    let adjusted = resolve!(
        "user32.dll",
        c"AdjustWindowRectExForDpi",
        false,
        AdjustForDpi
    )
    .is_some_and(|f| unsafe { f(&mut r, style, 0, ex_style, dpi) } != 0);
    if !adjusted {
        unsafe { AdjustWindowRectEx(&mut r, style, 0, ex_style) };
    }
    (r.right - r.left, r.bottom - r.top)
}

pub fn apply_window_chrome(hwnd: HWND) {
    let Some(set) = resolve!("dwmapi.dll", c"DwmSetWindowAttribute", true, SetAttribute) else {
        return;
    };
    let corners = DWMWCP_ROUND;
    let caption = color::WINDOW.colorref();
    unsafe {
        set(
            hwnd,
            DWMWA_WINDOW_CORNER_PREFERENCE as u32,
            (&raw const corners).cast(),
            size_of_val(&corners) as u32,
        );
        set(
            hwnd,
            DWMWA_CAPTION_COLOR as u32,
            (&raw const caption).cast(),
            size_of_val(&caption) as u32,
        );
    }
}
