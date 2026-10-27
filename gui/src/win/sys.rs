use std::ffi::CStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::null;

use windows_sys::Win32::Foundation::{HWND, RECT};
use windows_sys::Win32::Graphics::Gdi::{GetDC, GetDeviceCaps, LOGPIXELSY, ReleaseDC};
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleHandleW, GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_sys::Win32::System::SystemInformation::OSVERSIONINFOW;
use windows_sys::Win32::UI::HiDpi::DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2;
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AdjustWindowRectEx, GetSystemMetrics, SM_CXPADDEDBORDER, SM_CYFRAME, SPI_GETWHEELSCROLLLINES,
    SW_SHOWNORMAL, SYSTEM_METRICS_INDEX, SetProcessDPIAware, SystemParametersInfoW,
};

use crate::menu;

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn open_https(hwnd: HWND, url: &str) -> bool {
    menu::https(url) && open(hwnd, wide(url))
}

pub fn open_file(hwnd: HWND, path: &Path) -> bool {
    let path = path.as_os_str().encode_wide().chain(Some(0)).collect();
    open(hwnd, path)
}

fn open(hwnd: HWND, target: Vec<u16>) -> bool {
    let verb = wide("open");
    let code = unsafe {
        ShellExecuteW(
            hwnd,
            verb.as_ptr(),
            target.as_ptr(),
            null(),
            null(),
            SW_SHOWNORMAL,
        )
    };
    menu::opened(code as isize)
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
type MetricsForDpi = unsafe extern "system" fn(SYSTEM_METRICS_INDEX, u32) -> i32;
type GetVersion = unsafe extern "system" fn(*mut OSVERSIONINFOW) -> i32;
type CompositionEnabled = unsafe extern "system" fn(*mut i32) -> i32;

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

pub fn metric_for_dpi(index: SYSTEM_METRICS_INDEX, dpi: u32) -> i32 {
    match resolve!(
        "user32.dll",
        c"GetSystemMetricsForDpi",
        false,
        MetricsForDpi
    ) {
        Some(f) => unsafe { f(index, dpi) },
        None => unsafe { GetSystemMetrics(index) },
    }
}

pub fn frame_thickness(dpi: u32) -> i32 {
    metric_for_dpi(SM_CYFRAME, dpi) + metric_for_dpi(SM_CXPADDEDBORDER, dpi)
}

pub fn adjusted_rect(w: i32, h: i32, style: u32, ex_style: u32, dpi: u32) -> [i32; 4] {
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
    [r.left, r.top, r.right, r.bottom]
}

pub fn wheel_lines() -> u32 {
    let mut lines = 3u32;
    let ok =
        unsafe { SystemParametersInfoW(SPI_GETWHEELSCROLLLINES, 0, (&raw mut lines).cast(), 0) };
    if ok != 0 { lines } else { 3 }
}

pub fn os_major() -> u32 {
    let Some(get) = resolve!("ntdll.dll", c"RtlGetVersion", false, GetVersion) else {
        return 0;
    };
    let mut info = OSVERSIONINFOW {
        dwOSVersionInfoSize: size_of::<OSVERSIONINFOW>() as u32,
        ..unsafe { std::mem::zeroed() }
    };
    if unsafe { get(&mut info) } == 0 {
        info.dwMajorVersion
    } else {
        0
    }
}

pub fn composition_enabled() -> bool {
    let Some(enabled) = resolve!(
        "dwmapi.dll",
        c"DwmIsCompositionEnabled",
        true,
        CompositionEnabled
    ) else {
        return false;
    };
    let mut on = 0;
    let ok = unsafe { enabled(&mut on) } == 0;
    ok && on != 0
}
