use std::io;
use std::time::Duration;

pub fn wait_for_exit(pid: u32, timeout: Duration) -> io::Result<bool> {
    platform::wait_for_exit(pid, timeout)
}

#[cfg(windows)]
mod platform {
    use std::io;
    use std::time::Duration;

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_INVALID_PARAMETER, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
    };

    pub fn wait_for_exit(pid: u32, timeout: Duration) -> io::Result<bool> {
        // SAFETY: OpenProcess has no pointer arguments; a null handle reports an error.
        let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
        if handle.is_null() {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
                Ok(true)
            } else {
                Err(error)
            };
        }
        let millis = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX - 1);
        // SAFETY: handle is an owned process handle, closed once below.
        let result = unsafe { WaitForSingleObject(handle, millis) };
        let error = io::Error::last_os_error();
        // SAFETY: handle is owned and closed once.
        unsafe { CloseHandle(handle) };
        match result {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            _ => Err(error),
        }
    }
}

#[cfg(unix)]
mod platform {
    use std::io;
    use std::time::{Duration, Instant};

    const POLL: Duration = Duration::from_millis(50);

    #[cfg(target_os = "linux")]
    fn running(pid: u32) -> io::Result<bool> {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => Ok(!matches!(
                stat.rsplit_once(')')
                    .and_then(|(_, rest)| rest.trim_start().chars().next()),
                Some('Z' | 'X') | None
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn running(pid: u32) -> io::Result<bool> {
        Ok(std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stderr(std::process::Stdio::null())
            .status()?
            .success())
    }

    pub fn wait_for_exit(pid: u32, timeout: Duration) -> io::Result<bool> {
        let deadline = Instant::now() + timeout;
        loop {
            if !running(pid)? {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(POLL);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn a_running_process_is_reported_after_the_timeout() {
        let started = Instant::now();
        assert!(!wait_for_exit(std::process::id(), Duration::from_millis(300)).unwrap());
        assert!(started.elapsed() >= Duration::from_millis(300));
    }

    #[test]
    fn an_exited_process_is_reported_at_once() {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--list")
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        child.wait().unwrap();

        assert!(wait_for_exit(pid, Duration::from_secs(10)).unwrap());
    }

    #[test]
    fn a_process_that_exits_while_waiting_is_reported() {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--list")
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        let reaper = std::thread::spawn(move || child.wait().unwrap());

        assert!(wait_for_exit(pid, Duration::from_secs(30)).unwrap());
        reaper.join().unwrap();
    }
}
