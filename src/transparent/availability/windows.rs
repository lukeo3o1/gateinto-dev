use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::mem;
use std::os::windows::io::AsRawHandle;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::SystemInformation::{
    IMAGE_FILE_MACHINE, IMAGE_FILE_MACHINE_ARM64, OSVERSIONINFOW,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::core::BOOL;

use super::{Stamp, Version};

type GetVersionFn = unsafe extern "system" fn(*mut OSVERSIONINFOW) -> i32;
type MachinesFn =
    unsafe extern "system" fn(HANDLE, *mut IMAGE_FILE_MACHINE, *mut IMAGE_FILE_MACHINE) -> BOOL;

pub(super) struct Probe;

impl super::Probe for Probe {
    type File = File;

    fn version(&mut self) -> Option<Version> {
        // SAFETY: RtlGetVersion takes a pointer to an OSVERSIONINFOW and returns an NTSTATUS.
        let get: GetVersionFn = unsafe { function("ntdll.dll", c"RtlGetVersion") }?;
        let mut info = OSVERSIONINFOW {
            dwOSVersionInfoSize: size_of::<OSVERSIONINFOW>() as u32,
            ..OSVERSIONINFOW::default()
        };
        // SAFETY: info is an OSVERSIONINFOW whose size field is set.
        (unsafe { get(&mut info) } == 0).then_some(Version {
            major: info.dwMajorVersion,
            build: info.dwBuildNumber,
        })
    }

    fn arm64(&mut self) -> bool {
        !cfg!(any(target_arch = "x86", target_arch = "x86_64"))
            || native_machine() == Some(IMAGE_FILE_MACHINE_ARM64)
    }

    fn open(&mut self, name: &str) -> io::Result<File> {
        let image = std::env::current_exe()?;
        let directory = image.parent().ok_or(io::ErrorKind::NotFound)?;
        File::open(directory.join(name))
    }

    fn stamp(&mut self, file: &File) -> Option<Stamp> {
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the handle belongs to file, which outlives the call; info is a valid out pointer.
        let read = unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) };
        let high_low = |high: u32, low: u32| u64::from(high) << 32 | u64::from(low);
        (read != 0).then(|| Stamp {
            volume: info.dwVolumeSerialNumber,
            index: high_low(info.nFileIndexHigh, info.nFileIndexLow),
            size: high_low(info.nFileSizeHigh, info.nFileSizeLow),
            modified: high_low(
                info.ftLastWriteTime.dwHighDateTime,
                info.ftLastWriteTime.dwLowDateTime,
            ),
        })
    }
}

fn native_machine() -> Option<IMAGE_FILE_MACHINE> {
    // SAFETY: IsWow64Process2 takes a process handle and two IMAGE_FILE_MACHINE out pointers.
    let machines: MachinesFn = unsafe { function("kernel32.dll", c"IsWow64Process2") }?;
    let (mut process, mut native) = (0, 0);
    // SAFETY: the pseudo handle of the current process needs no closing; both pointers are valid.
    let read = unsafe { machines(GetCurrentProcess(), &mut process, &mut native) };
    (read != 0).then_some(native)
}

unsafe fn function<T: Copy>(module: &str, name: &CStr) -> Option<T> {
    const { assert!(size_of::<T>() == size_of::<usize>()) };
    let module: Vec<u16> = module.encode_utf16().chain([0]).collect();
    // SAFETY: module is NUL-terminated; ntdll.dll and kernel32.dll are loaded in every process.
    let handle = unsafe { GetModuleHandleW(module.as_ptr()) };
    if handle.is_null() {
        return None;
    }
    // SAFETY: the module stays loaded for the life of the process and name is NUL-terminated.
    let address = unsafe { GetProcAddress(handle, name.as_ptr().cast()) }?;
    // SAFETY: the caller names the function pointer type of the export.
    Some(unsafe { mem::transmute_copy(&address) })
}

#[cfg(test)]
mod tests {
    use super::super::{Availability, Probe as _, Reason, available};
    use super::*;

    #[test]
    fn the_version_is_read_from_the_kernel() {
        let version = Probe.version().expect("RtlGetVersion answered");
        assert!(version.major >= 6, "{version:?}");
        assert!(version.build > 0, "{version:?}");
    }

    #[test]
    fn an_x86_or_x64_runner_is_not_arm64() {
        let native = native_machine().expect("IsWow64Process2 answered");
        assert_ne!(native, IMAGE_FILE_MACHINE_ARM64);
        assert!(!Probe.arm64());
    }

    #[test]
    fn the_windivert_files_are_looked_for_beside_the_executable() {
        let image = std::env::current_exe().unwrap();
        let missing = image.with_file_name("WinDivert.dll");
        assert!(!missing.exists(), "{missing:?}");
        assert_eq!(
            Probe.open("WinDivert.dll").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert!(
            Probe
                .open(image.file_name().unwrap().to_str().unwrap())
                .is_ok()
        );
        assert_eq!(
            available(),
            Availability::Unavailable(Reason::FilesMissing("WinDivert.dll"))
        );
    }

    struct Scratch(std::path::PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn a_stamp_names_the_file_and_changes_when_it_is_rewritten() {
        let scratch =
            Scratch(std::env::temp_dir().join(format!("gateinto-stamp-{}", std::process::id())));
        let path = &scratch.0;
        std::fs::write(path, b"first").unwrap();
        let first = Probe.stamp(&File::open(path).unwrap()).unwrap();
        assert_eq!(Probe.stamp(&File::open(path).unwrap()), Some(first));
        let image = File::open(std::env::current_exe().unwrap()).unwrap();
        assert_ne!(Probe.stamp(&image).unwrap().index, first.index);
        std::fs::write(path, b"second").unwrap();
        let second = Probe.stamp(&File::open(path).unwrap()).unwrap();
        assert_eq!((second.volume, second.index), (first.volume, first.index));
        assert_eq!((first.size, second.size), (5, 6));
        assert!(second.modified >= first.modified);
    }
}
