use std::ptr::{null, null_mut};
use std::thread;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, GetLastError, HANDLE, HWND, LocalFree,
    SetLastError,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows_sys::Win32::System::Threading::{
    CreateMutexW, GetCurrentProcess, OpenProcess, OpenProcessToken,
    PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AllowSetForegroundWindow, FindWindowExW, GetWindowThreadProcessId, PostMessageW, WM_APP,
};
use windows_sys::core::PWSTR;

use super::sys::wide;
use crate::instance;

pub const WM_REVEAL: u32 = WM_APP + 2;

pub struct Guard(HANDLE);

impl Drop for Guard {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

pub enum Start {
    Alone(Option<Guard>),
    Second(String),
}

pub fn start(demo: bool) -> Start {
    let Some(sid) = process_sid(unsafe { GetCurrentProcess() }) else {
        return Start::Alone(None);
    };
    match create(&sid, demo) {
        Ok(guard) => Start::Alone(Some(guard)),
        Err(ERROR_ALREADY_EXISTS) => Start::Second(sid),
        Err(_) => Start::Alone(None),
    }
}

fn create(sid: &str, demo: bool) -> Result<Guard, u32> {
    let sddl = wide(&instance::descriptor(sid));
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    };
    if converted == 0 {
        return Err(unsafe { GetLastError() });
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let name = wide(&instance::mutex_name(sid, demo));
    let (handle, error) = unsafe {
        SetLastError(ERROR_SUCCESS);
        let handle = CreateMutexW(&attributes, 0, name.as_ptr());
        (handle, GetLastError())
    };
    unsafe { LocalFree(descriptor) };
    if handle.is_null() {
        return Err(error);
    }
    let guard = Guard(handle);
    if error == ERROR_ALREADY_EXISTS {
        Err(error)
    } else {
        Ok(guard)
    }
}

fn process_sid(process: HANDLE) -> Option<String> {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return None;
    }
    let sid = token_sid(token);
    unsafe { CloseHandle(token) };
    sid
}

fn token_sid(token: HANDLE) -> Option<String> {
    let mut size = 0;
    unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut size) };
    let mut buffer = vec![0u64; (size as usize).div_ceil(size_of::<u64>())];
    let read = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            size,
            &mut size,
        )
    };
    if read == 0 || (size as usize) < size_of::<TOKEN_USER>() {
        return None;
    }
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut text: PWSTR = null_mut();
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
        return None;
    }
    let sid = unsafe {
        let len = (0..).take_while(|&i| *text.add(i) != 0).count();
        String::from_utf16(std::slice::from_raw_parts(text, len)).ok()
    };
    unsafe { LocalFree(text.cast()) };
    sid
}

pub fn activate(demo: bool, sid: &str) {
    let class = wide(instance::class(demo));
    for attempt in 0..instance::ATTEMPTS {
        if attempt > 0 {
            thread::sleep(instance::PAUSE);
        }
        if let Some((hwnd, pid)) = find(&class, sid) {
            unsafe {
                AllowSetForegroundWindow(pid);
                PostMessageW(hwnd, WM_REVEAL, 0, 0);
            }
            return;
        }
    }
}

fn find(class: &[u16], sid: &str) -> Option<(HWND, u32)> {
    let mut hwnd = null_mut();
    loop {
        hwnd = unsafe { FindWindowExW(null_mut(), hwnd, class.as_ptr(), null()) };
        if hwnd.is_null() {
            return None;
        }
        let mut pid = 0;
        unsafe { GetWindowThreadProcessId(hwnd, &mut pid) };
        if pid != 0 && owner(pid).as_deref() == Some(sid) {
            return Some((hwnd, pid));
        }
    }
}

fn owner(pid: u32) -> Option<String> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return None;
    }
    let sid = process_sid(process);
    unsafe { CloseHandle(process) };
    sid
}
