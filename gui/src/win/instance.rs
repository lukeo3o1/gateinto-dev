use std::ptr::{null, null_mut};
use std::thread;
use std::time::Instant;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, ERROR_TIMEOUT, GetLastError, HANDLE, HWND,
    LocalFree, SetLastError,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::DataExchange::COPYDATASTRUCT;
use windows_sys::Win32::System::Threading::{
    CreateMutexW, GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, QueryFullProcessImageNameW,
    WaitForSingleObject,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AllowSetForegroundWindow, FindWindowExW, GetWindowThreadProcessId, PostMessageW,
    SMTO_ABORTIFHUNG, SMTO_BLOCK, SendMessageTimeoutW, WM_COPYDATA,
};
use windows_sys::core::PWSTR;

use gateinto::link::handoff as reply;

use super::sys::wide;
use crate::handoff::{self, Link};
use crate::{instance, message, uninstall};

pub const WM_REVEAL: u32 = message::REVEAL;
pub const WM_EXIT: u32 = message::EXIT;

const FORWARD_TIMEOUT_MS: u32 = 5_000;
const LONGEST_PATH: usize = 32_768;

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
        Some((guard, false)) => Start::Alone(Some(guard)),
        Some((guard, true)) if instance::running(mutex_owner(&guard).as_deref(), &sid) => {
            Start::Second(sid)
        }
        _ => Start::Alone(None),
    }
}

fn create(sid: &str, demo: bool) -> Option<(Guard, bool)> {
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
        return None;
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
    (!handle.is_null()).then(|| (Guard(handle), error == ERROR_ALREADY_EXISTS))
}

fn mutex_owner(guard: &Guard) -> Option<String> {
    let mut owner: PSID = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let error = unsafe {
        GetSecurityInfo(
            guard.0,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if error != ERROR_SUCCESS {
        return None;
    }
    let sid = sid_string(owner);
    unsafe { LocalFree(descriptor) };
    sid
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
    sid_string(user.User.Sid)
}

fn sid_string(sid: PSID) -> Option<String> {
    let mut text: PWSTR = null_mut();
    if sid.is_null() || unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
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
    let same_user = |process| process_sid(process).as_deref() == Some(sid);
    if let Some((hwnd, pid, _process)) = wait_for(&class, same_user) {
        unsafe {
            AllowSetForegroundWindow(pid);
            PostMessageW(hwnd, WM_REVEAL, 0, 0);
        }
    }
}

pub fn forward(sid: &str, link: &Link) -> &'static str {
    let Some(image) = image_of(unsafe { GetCurrentProcess() }) else {
        return reply::REFUSED;
    };
    let class = wide(instance::class(false));
    let same_app = |process| {
        process_sid(process).as_deref() == Some(sid)
            && image_of(process).is_some_and(|other| handoff::same_image(&image, &other))
    };
    let Some((hwnd, pid, _process)) = wait_for(&class, same_app) else {
        return reply::REFUSED;
    };
    if window_process(hwnd) != pid {
        return reply::REFUSED;
    }
    let payload = link.payload();
    let data = COPYDATASTRUCT {
        dwData: handoff::COPYDATA,
        cbData: payload.len() as u32,
        lpData: payload.as_ptr().cast_mut().cast(),
    };
    let mut answer = 0;
    let (sent, error) = unsafe {
        AllowSetForegroundWindow(pid);
        SetLastError(ERROR_SUCCESS);
        let sent = SendMessageTimeoutW(
            hwnd,
            WM_COPYDATA,
            0,
            &raw const data as isize,
            SMTO_ABORTIFHUNG | SMTO_BLOCK,
            FORWARD_TIMEOUT_MS,
            &mut answer,
        );
        (sent, GetLastError())
    };
    handoff::forwarded(
        sent != 0,
        answer as isize,
        sent == 0 && error == ERROR_TIMEOUT,
    )
}

pub fn exit_all() {
    let current = unsafe { GetCurrentProcess() };
    let (Some(sid), Some(image)) = (process_sid(current), image_of(current)) else {
        return;
    };
    let same_app = |process| {
        process_sid(process).as_deref() == Some(sid.as_str())
            && image_of(process).is_some_and(|other| handoff::same_image(&image, &other))
    };
    let mut found = Vec::new();
    for demo in [false, true] {
        let class = wide(instance::class(demo));
        let mut after = null_mut();
        while let Some((hwnd, pid, _query)) = find_after(&class, after, same_app) {
            after = hwnd;
            let process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
            if !process.is_null() {
                found.push((hwnd, Process(process)));
            }
        }
    }
    let exiting: Vec<Process> = found
        .into_iter()
        .filter(|&(hwnd, _)| unsafe { PostMessageW(hwnd, WM_EXIT, 0, 0) } != 0)
        .map(|(_, process)| process)
        .collect();
    let deadline = Instant::now() + uninstall::WAIT;
    for process in exiting {
        let left = deadline.saturating_duration_since(Instant::now());
        unsafe { WaitForSingleObject(process.0, left.as_millis() as u32) };
    }
}

struct Process(HANDLE);

impl Drop for Process {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

fn wait_for(class: &[u16], accept: impl Fn(HANDLE) -> bool) -> Option<(HWND, u32, Process)> {
    for attempt in 0..instance::ATTEMPTS {
        if attempt > 0 {
            thread::sleep(instance::PAUSE);
        }
        if let Some(found) = find(class, &accept) {
            return Some(found);
        }
    }
    None
}

fn find(class: &[u16], accept: impl Fn(HANDLE) -> bool) -> Option<(HWND, u32, Process)> {
    find_after(class, null_mut(), accept)
}

// The open handle keeps the process id from being reused until it is dropped.
fn find_after(
    class: &[u16],
    after: HWND,
    accept: impl Fn(HANDLE) -> bool,
) -> Option<(HWND, u32, Process)> {
    let mut hwnd = after;
    loop {
        hwnd = unsafe { FindWindowExW(null_mut(), hwnd, class.as_ptr(), null()) };
        if hwnd.is_null() {
            return None;
        }
        let pid = window_process(hwnd);
        if pid == 0 {
            continue;
        }
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() {
            continue;
        }
        let process = Process(process);
        if accept(process.0) && window_process(hwnd) == pid {
            return Some((hwnd, pid, process));
        }
    }
}

fn window_process(hwnd: HWND) -> u32 {
    let mut pid = 0;
    unsafe { GetWindowThreadProcessId(hwnd, &mut pid) };
    pid
}

fn image_of(process: HANDLE) -> Option<String> {
    let mut buffer = vec![0u16; LONGEST_PATH];
    let mut size = buffer.len() as u32;
    let read = unsafe {
        QueryFullProcessImageNameW(process, PROCESS_NAME_WIN32, buffer.as_mut_ptr(), &mut size)
    };
    if read == 0 {
        return None;
    }
    String::from_utf16(&buffer[..size as usize]).ok()
}
