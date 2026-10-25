use std::io;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::{GetTokenInformation, PSID, TOKEN_QUERY, TOKEN_USER, TokenUser};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub(crate) struct Handle(pub(crate) HANDLE);

// SAFETY: a kernel handle may be used and closed from any thread.
unsafe impl Send for Handle {}
// SAFETY: the handle is only passed by value to thread-safe kernel calls.
unsafe impl Sync for Handle {}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle is owned by this value and closed once.
        unsafe { CloseHandle(self.0) };
    }
}

pub(crate) fn current_token() -> io::Result<Handle> {
    let mut token = null_mut();
    // SAFETY: the current process pseudo handle needs no closing; token receives an owned handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Handle(token))
}

pub(crate) struct TokenUserInfo(Vec<u64>);

impl TokenUserInfo {
    pub(crate) fn current() -> io::Result<Self> {
        Self::of(&current_token()?)
    }

    pub(crate) fn of(token: &Handle) -> io::Result<Self> {
        let mut len = 0;
        // SAFETY: a null buffer of length 0 asks for the required length.
        unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut len) };
        let mut buffer = vec![0u64; (len as usize).div_ceil(8)];
        // SAFETY: buffer is 8-byte aligned and holds at least len bytes.
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                len,
                &mut len,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(buffer))
    }

    pub(crate) fn sid(&self) -> PSID {
        // SAFETY: GetTokenInformation wrote a TOKEN_USER at the start of the aligned buffer.
        unsafe { (*self.0.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }
}
