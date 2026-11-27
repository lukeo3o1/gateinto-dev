use std::ffi::{CStr, CString, OsStr, OsString, c_char, c_int, c_void};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::mem;
use std::num::NonZeroU32;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::ptr::{null, null_mut};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_INVALID_PARAMETER, ERROR_IO_PENDING, FALSE, FreeLibrary,
    GetLastError, HANDLE, HMODULE, INVALID_HANDLE_VALUE, SetLastError, TRUE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, ReadFile, SECURITY_IDENTIFICATION, WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CreateEventW, CreateMutexW, INFINITE, OpenProcess, PROCESS_SYNCHRONIZE,
    WaitForMultipleObjects, WaitForSingleObject,
};
use windows_sys::core::BOOL;

use super::firewall::NetshCommand;
use super::helper::{
    self, Abandon, Arguments, DriverVersion, FilesError, PipeName, Platform, sha256_matches,
};
use super::pump::{DivertPort, Liveness, Received, RecvError};
use super::windivert::{Address, FILES, PinnedFile, recv_error};
use crate::token::Handle;

const MUTEX: &str = r"Global\Gateinto-divert";
const NETSH_TIMEOUT: Duration = Duration::from_secs(10);
const PIPE_WRITE_TIMEOUT_MS: u32 = 2000;
const LAYER_NETWORK: c_int = 0;
const PARAM_VERSION_MAJOR: c_int = 3;
const PARAM_VERSION_MINOR: c_int = 4;
const SHUTDOWN_BOTH: c_int = 3;

type OpenFn = unsafe extern "C" fn(*const c_char, c_int, i16, u64) -> HANDLE;
type RecvFn = unsafe extern "C" fn(HANDLE, *mut c_void, u32, *mut u32, *mut Address) -> BOOL;
type SendFn = unsafe extern "C" fn(HANDLE, *const c_void, u32, *mut u32, *const Address) -> BOOL;
type ShutdownFn = unsafe extern "C" fn(HANDLE, c_int) -> BOOL;
type CloseFn = unsafe extern "C" fn(HANDLE) -> BOOL;
type GetParamFn = unsafe extern "C" fn(HANDLE, c_int, *mut u64) -> BOOL;

pub fn run(arguments: &Arguments<'_>) -> u8 {
    helper::run(&mut Windows, arguments)
}

struct Windows;

impl Platform for Windows {
    type Pipe = Pipe;
    type Watch = Watch;
    type Lock = Handle;
    type Files = Files;
    type Port = Port;
    type Abandon = GiveUp;

    fn connect(&mut self, pipe: &PipeName, agent: NonZeroU32) -> io::Result<(Pipe, Watch)> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OVERLAPPED)
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(pipe.as_str())?;
        let mut server = 0;
        // SAFETY: the handle is an open pipe and server is a valid out pointer.
        if unsafe { GetNamedPipeServerProcessId(file.as_raw_handle(), &mut server) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if server != agent.get() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the pipe is not served by the agent",
            ));
        }
        let file = Arc::new(file);
        let watch = watch(Arc::clone(&file), agent.get())?;
        let event = event()?;
        Ok((Pipe { file, event }, watch))
    }

    fn lock(&mut self) -> Option<Handle> {
        create_lock(MUTEX)
    }

    fn image_path(&mut self) -> Option<String> {
        std::env::current_exe()
            .ok()?
            .into_os_string()
            .into_string()
            .ok()
    }

    fn netsh(&mut self, command: &NetshCommand) -> bool {
        netsh(command)
    }

    fn open_files(&mut self) -> Result<Files, FilesError> {
        let image = std::env::current_exe().map_err(|_| FilesError::Missing)?;
        let directory = image.parent().ok_or(FilesError::Missing)?;
        open_files(directory, FILES)
    }

    fn open_port(&mut self, files: &Files, filter: &str) -> Result<Port, u32> {
        let library = Library::load(&files.library)?;
        let filter = CString::new(filter).map_err(|_| ERROR_INVALID_PARAMETER)?;
        // SAFETY: filter is NUL-terminated and the layer, priority and flags are valid values.
        let handle = unsafe { (library.open)(filter.as_ptr(), LAYER_NETWORK, 0, 0) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(last_error());
        }
        Ok(Port {
            handle,
            library,
            shutting_down: AtomicBool::new(false),
        })
    }

    fn driver_version(&mut self, port: &Port) -> Option<DriverVersion> {
        Some(DriverVersion {
            major: port.param(PARAM_VERSION_MAJOR)?,
            minor: port.param(PARAM_VERSION_MINOR)?,
        })
    }

    fn abandon(&mut self) -> GiveUp {
        GiveUp
    }
}

struct GiveUp;

impl Abandon for GiveUp {
    fn netsh(&mut self, command: &NetshCommand) -> bool {
        netsh(command)
    }

    fn exit(self, code: u8) {
        std::process::exit(i32::from(code))
    }
}

fn create_lock(name: &str) -> Option<Handle> {
    let name = wide(OsStr::new(name));
    // SAFETY: SetLastError only stores the calling thread's error code.
    unsafe { SetLastError(0) };
    // SAFETY: name is a NUL-terminated UTF-16 string and no security attributes are passed.
    let mutex = unsafe { CreateMutexW(null(), FALSE, name.as_ptr()) };
    // SAFETY: GetLastError only reads the calling thread's error code.
    let existed = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
    if mutex.is_null() {
        return None;
    }
    let mutex = Handle(mutex);
    (!existed).then_some(mutex)
}

fn netsh(command: &NetshCommand) -> bool {
    netsh_path().is_ok_and(|netsh| {
        run_bounded(
            Command::new(netsh)
                .raw_arg(command.as_str())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(CREATE_NO_WINDOW),
            NETSH_TIMEOUT,
        )
    })
}

struct Files {
    library: PathBuf,
    _held: Vec<File>,
}

fn open_files(directory: &Path, pinned: &[PinnedFile]) -> Result<Files, FilesError> {
    let library = pinned.first().ok_or(FilesError::Missing)?;
    let held = pinned
        .iter()
        .map(|file| {
            OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .open(directory.join(file.name))
        })
        .collect::<io::Result<Vec<_>>>()
        .map_err(|_| FilesError::Missing)?;
    for (file, pinned) in held.iter().zip(pinned) {
        if !sha256_matches(file, &pinned.sha256) {
            return Err(FilesError::DigestMismatch);
        }
    }
    Ok(Files {
        library: directory.join(library.name),
        _held: held,
    })
}

struct Module(HMODULE);

impl Drop for Module {
    fn drop(&mut self) {
        // SAFETY: the module was loaded by this value and is freed once.
        unsafe { FreeLibrary(self.0) };
    }
}

struct Library {
    open: OpenFn,
    recv: RecvFn,
    send: SendFn,
    shutdown: ShutdownFn,
    close: CloseFn,
    get_param: GetParamFn,
    _module: Module,
}

impl Library {
    fn load(path: &Path) -> Result<Self, u32> {
        let path = wide(path.as_os_str());
        // SAFETY: path is an absolute, NUL-terminated UTF-16 path and the flags limit the search
        // for its dependencies to its own directory and System32.
        let module = unsafe {
            LoadLibraryExW(
                path.as_ptr(),
                null_mut(),
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            return Err(last_error());
        }
        let module = Module(module);
        // SAFETY: each type is the signature that windivert.h declares for the export.
        unsafe {
            Ok(Self {
                open: symbol(&module, c"WinDivertOpen")?,
                recv: symbol(&module, c"WinDivertRecv")?,
                send: symbol(&module, c"WinDivertSend")?,
                shutdown: symbol(&module, c"WinDivertShutdown")?,
                close: symbol(&module, c"WinDivertClose")?,
                get_param: symbol(&module, c"WinDivertGetParam")?,
                _module: module,
            })
        }
    }
}

unsafe fn symbol<T: Copy>(module: &Module, name: &CStr) -> Result<T, u32> {
    const { assert!(size_of::<T>() == size_of::<usize>()) };
    // SAFETY: the module is loaded and name is NUL-terminated.
    let address =
        unsafe { GetProcAddress(module.0, name.as_ptr().cast()) }.ok_or_else(last_error)?;
    // SAFETY: the caller names the function pointer type of the export.
    Ok(unsafe { mem::transmute_copy(&address) })
}

struct Port {
    handle: HANDLE,
    library: Library,
    shutting_down: AtomicBool,
}

// SAFETY: WinDivert documents using one handle from several threads at once (Performance,
// Multi-threading), and the function pointers never change.
unsafe impl Sync for Port {}

impl Port {
    fn param(&self, param: c_int) -> Option<u64> {
        let mut value = 0;
        // SAFETY: the handle is open and value is a valid out pointer.
        let read = unsafe { (self.library.get_param)(self.handle, param, &mut value) };
        (read != 0).then_some(value)
    }
}

impl DivertPort for Port {
    type Address = Address;

    fn recv(&self, buffer: &mut [u8]) -> Result<Received<Address>, RecvError> {
        let mut address = Address::zeroed();
        let mut length = 0;
        let capacity = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        // SAFETY: buffer holds at least capacity bytes, length and address are valid out
        // pointers, and the handle stays open until the port is dropped.
        let received = unsafe {
            (self.library.recv)(
                self.handle,
                buffer.as_mut_ptr().cast(),
                capacity,
                &mut length,
                &mut address,
            )
        };
        if received == 0 {
            let error = io::Error::last_os_error();
            return Err(match recv_error(error) {
                RecvError::Shutdown if !self.shutting_down.load(Ordering::Acquire) => {
                    RecvError::Failed(io::Error::other("WinDivert stopped receiving unexpectedly"))
                }
                result => result,
            });
        }
        Ok(Received {
            length: length as usize,
            direction: address.direction(),
            address,
        })
    }

    fn inject_inbound(&self, packet: &[u8], address: &Address) -> io::Result<()> {
        let inbound = address.inbound();
        let length = u32::try_from(packet.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
        // SAFETY: packet holds length bytes, inbound is a valid address and the handle is open.
        let sent = unsafe {
            (self.library.send)(
                self.handle,
                packet.as_ptr().cast(),
                length,
                null_mut(),
                &inbound,
            )
        };
        if sent == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn shutdown(&self) {
        self.shutting_down.store(true, Ordering::Release);
        // SAFETY: the handle is open and SHUTDOWN_BOTH is a valid WINDIVERT_SHUTDOWN value.
        unsafe { (self.library.shutdown)(self.handle, SHUTDOWN_BOTH) };
    }
}

impl Drop for Port {
    fn drop(&mut self) {
        // SAFETY: the handle is open and closed once, before the library is freed.
        unsafe { (self.library.close)(self.handle) };
    }
}

struct Pipe {
    file: Arc<File>,
    event: Handle,
}

impl Read for Pipe {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let handle = self.file.as_raw_handle();
        let mut overlapped = OVERLAPPED {
            hEvent: self.event.0,
            ..OVERLAPPED::default()
        };
        let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        // SAFETY: bytes and overlapped stay in place until finish has waited for the read.
        let started = unsafe {
            ReadFile(
                handle,
                bytes.as_mut_ptr(),
                length,
                null_mut(),
                &mut overlapped,
            )
        };
        finish(
            handle,
            &overlapped,
            started,
            super::protocol::START_TIMEOUT.as_millis() as u32,
        )
        .map(|read| read as usize)
    }
}

impl Write for Pipe {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let handle = self.file.as_raw_handle();
        let mut overlapped = OVERLAPPED {
            hEvent: self.event.0,
            ..OVERLAPPED::default()
        };
        let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        // SAFETY: bytes and overlapped stay in place until finish has waited for the write.
        let started =
            unsafe { WriteFile(handle, bytes.as_ptr(), length, null_mut(), &mut overlapped) };
        finish(handle, &overlapped, started, PIPE_WRITE_TIMEOUT_MS).map(|written| written as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn finish(
    handle: HANDLE,
    overlapped: &OVERLAPPED,
    started: BOOL,
    timeout_ms: u32,
) -> io::Result<u32> {
    // SAFETY: GetLastError only reads the calling thread's error code.
    if started == 0 {
        if unsafe { GetLastError() } != ERROR_IO_PENDING {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the operation's event and OVERLAPPED remain live through cancellation and completion.
        if unsafe { WaitForSingleObject(overlapped.hEvent, timeout_ms) } != WAIT_OBJECT_0 {
            let mut transferred = 0;
            unsafe {
                CancelIoEx(handle, overlapped);
                GetOverlappedResult(handle, overlapped, &mut transferred, TRUE);
            }
            return Err(io::ErrorKind::TimedOut.into());
        }
    }
    let mut transferred = 0;
    // SAFETY: overlapped belongs to an operation on handle, and TRUE waits until it has finished.
    if unsafe { GetOverlappedResult(handle, overlapped, &mut transferred, TRUE) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(transferred)
}

struct Watch {
    file: Arc<File>,
    agent: Handle,
}

fn watch(file: Arc<File>, agent: u32) -> io::Result<Watch> {
    // SAFETY: OpenProcess takes no pointers; a null result is checked below.
    let process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, FALSE, agent) };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(Watch {
        file,
        agent: Handle(process),
    })
}

impl Liveness for Watch {
    fn wait_until_gone(self) {
        let Ok(event) = event() else {
            return;
        };
        let handle = self.file.as_raw_handle();
        let mut overlapped = OVERLAPPED {
            hEvent: event.0,
            ..OVERLAPPED::default()
        };
        let mut byte = 0;
        // SAFETY: byte and overlapped stay in place until the read has finished or has been
        // cancelled and waited for below.
        let started = unsafe { ReadFile(handle, &mut byte, 1, null_mut(), &mut overlapped) };
        // SAFETY: GetLastError only reads the calling thread's error code.
        if started != 0 || unsafe { GetLastError() } != ERROR_IO_PENDING {
            return;
        }
        let handles = [event.0, self.agent.0];
        // SAFETY: both handles stay open during the wait.
        unsafe { WaitForMultipleObjects(2, handles.as_ptr(), FALSE, INFINITE) };
        let mut read = 0;
        // SAFETY: cancels the read on handle if it is still pending, then waits until it has
        // finished, so byte and overlapped are no longer in use when they go out of scope.
        unsafe {
            CancelIoEx(handle, &overlapped);
            GetOverlappedResult(handle, &overlapped, &mut read, TRUE);
        }
    }
}

fn event() -> io::Result<Handle> {
    // SAFETY: creates an unnamed manual-reset event without security attributes.
    let event = unsafe { CreateEventW(null(), TRUE, FALSE, null()) };
    if event.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(Handle(event))
}

fn system_directory() -> io::Result<PathBuf> {
    let mut buffer = vec![0; 260];
    loop {
        let capacity = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        // SAFETY: buffer holds capacity UTF-16 units.
        let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), capacity) } as usize;
        match length {
            0 => return Err(io::Error::last_os_error()),
            length if length < buffer.len() => {
                return Ok(PathBuf::from(OsString::from_wide(&buffer[..length])));
            }
            length => buffer.resize(length, 0),
        }
    }
}

fn run_bounded(command: &mut Command, timeout: Duration) -> bool {
    let Ok(mut child) = command.spawn() else {
        return false;
    };
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

fn netsh_path() -> io::Result<PathBuf> {
    Ok(system_directory()?.join("netsh.exe"))
}

fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain([0]).collect()
}

fn last_error() -> u32 {
    // SAFETY: GetLastError only reads the calling thread's error code.
    unsafe { GetLastError() }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::fs;
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use tokio::sync::oneshot;
    use tokio::time::timeout;
    use windows_sys::Win32::Foundation::{ERROR_MOD_NOT_FOUND, ERROR_PROC_NOT_FOUND};

    use super::*;

    const PATIENCE: Duration = Duration::from_secs(10);

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("gateinto-divert-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn pinned(name: &'static str, contents: &[u8]) -> PinnedFile {
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, contents);
        PinnedFile {
            name,
            sha256: digest.as_ref().try_into().unwrap(),
        }
    }

    fn library_and_driver(dir: &Path) -> [PinnedFile; 2] {
        fs::write(dir.join("a.dll"), b"library").unwrap();
        fs::write(dir.join("b.sys"), b"driver").unwrap();
        [pinned("a.dll", b"library"), pinned("b.sys", b"driver")]
    }

    #[test]
    fn files_are_missing_when_one_cannot_be_opened() {
        let dir = temp_dir("missing");
        let pinned = library_and_driver(&dir);
        fs::remove_file(dir.join("b.sys")).unwrap();
        assert!(matches!(
            open_files(&dir, &pinned),
            Err(FilesError::Missing)
        ));
        assert!(matches!(open_files(&dir, &[]), Err(FilesError::Missing)));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_file_with_other_contents_is_a_digest_mismatch() {
        let dir = temp_dir("mismatch");
        let pinned = library_and_driver(&dir);
        fs::write(dir.join("b.sys"), b"changed").unwrap();
        assert!(matches!(
            open_files(&dir, &pinned),
            Err(FilesError::DigestMismatch)
        ));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn verified_files_can_be_read_but_not_written_renamed_or_deleted_while_held() {
        let dir = temp_dir("held");
        let pinned = library_and_driver(&dir);
        let files = open_files(&dir, &pinned).unwrap();
        assert_eq!(files.library, dir.join("a.dll"));
        for name in ["a.dll", "b.sys"] {
            let path = dir.join(name);
            assert!(fs::read(&path).is_ok(), "{name}");
            assert!(
                OpenOptions::new().write(true).open(&path).is_err(),
                "{name}"
            );
            assert!(fs::remove_file(&path).is_err(), "{name}");
            assert!(fs::rename(&path, dir.join("renamed")).is_err(), "{name}");
        }
        drop(files);
        OpenOptions::new()
            .write(true)
            .open(dir.join("a.dll"))
            .unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_directory_of_held_files_and_its_ancestors_cannot_be_renamed() {
        let root = temp_dir("held-directory");
        let programs = root.join("Programs");
        let dir = programs.join("Gateinto");
        fs::create_dir_all(&dir).unwrap();
        let pinned = library_and_driver(&dir);
        let files = open_files(&dir, &pinned).unwrap();
        assert!(fs::rename(&dir, programs.join("moved")).is_err());
        assert!(fs::rename(&programs, root.join("moved")).is_err());
        drop(files);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_windivert_files_are_looked_for_beside_the_executable() {
        let image = Windows.image_path().unwrap();
        assert_eq!(PathBuf::from(image), std::env::current_exe().unwrap());
        assert!(matches!(Windows.open_files(), Err(FilesError::Missing)));
    }

    #[test]
    fn a_library_that_is_not_windivert_is_refused_with_its_error() {
        let dir = temp_dir("no-library");
        let missing = Files {
            library: dir.join("WinDivert.dll"),
            _held: Vec::new(),
        };
        assert_eq!(
            Windows.open_port(&missing, "true").err(),
            Some(ERROR_MOD_NOT_FOUND)
        );
        let other = Files {
            library: system_directory().unwrap().join("kernel32.dll"),
            _held: Vec::new(),
        };
        assert_eq!(
            Windows.open_port(&other, "true").err(),
            Some(ERROR_PROC_NOT_FOUND)
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_second_helper_finds_the_machine_wide_mutex_taken() {
        assert_eq!(MUTEX, r"Global\Gateinto-divert");
        let name = format!(r"Global\Gateinto-divert-test-{}", random_hex());
        let first = create_lock(&name).expect("the mutex is free");
        assert!(create_lock(&name).is_none());
        drop(first);
        assert!(create_lock(&name).is_some());
    }

    #[test]
    fn netsh_is_started_from_the_system_directory() {
        let path = netsh_path().unwrap();
        assert!(path.is_absolute(), "{path:?}");
        assert_eq!(path.file_name(), Some(OsStr::new("netsh.exe")));
        let root = PathBuf::from(std::env::var_os("SystemRoot").unwrap());
        let parent = path.parent().unwrap().as_os_str();
        assert!(
            parent.eq_ignore_ascii_case(root.join("System32").as_os_str()),
            "{path:?}"
        );
    }

    #[test]
    fn netsh_is_given_ten_seconds() {
        assert_eq!(NETSH_TIMEOUT, Duration::from_secs(10));
    }

    #[test]
    fn a_command_succeeds_only_with_exit_code_zero_within_its_time() {
        let cmd = system_directory().unwrap().join("cmd.exe");
        assert!(run_bounded(
            Command::new(&cmd).args(["/d", "/c", "exit 0"]),
            PATIENCE
        ));
        assert!(!run_bounded(
            Command::new(&cmd).args(["/d", "/c", "exit 1"]),
            PATIENCE
        ));
        let dir = temp_dir("no-command");
        assert!(!run_bounded(
            &mut Command::new(dir.join("missing.exe")),
            PATIENCE
        ));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_command_that_does_not_end_in_time_is_killed_and_fails() {
        let ping = system_directory().unwrap().join("ping.exe");
        let start = Instant::now();
        assert!(!run_bounded(
            Command::new(ping)
                .args(["-n", "30", "127.0.0.1"])
                .stdout(Stdio::null()),
            Duration::from_millis(500)
        ));
        assert!(start.elapsed() < PATIENCE, "{:?}", start.elapsed());
    }

    fn random() -> [u8; 16] {
        let mut random = [0; 16];
        aws_lc_rs::rand::fill(&mut random).unwrap();
        random
    }

    fn random_hex() -> String {
        random().iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn pipe_name() -> PipeName {
        PipeName::from_random(random())
    }

    fn agent_pipe() -> (PipeName, NamedPipeServer) {
        let name = pipe_name();
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(name.as_str())
            .unwrap();
        (name, server)
    }

    fn own_pid() -> NonZeroU32 {
        NonZeroU32::new(std::process::id()).unwrap()
    }

    async fn connect_to(name: PipeName, agent: NonZeroU32) -> io::Result<(Pipe, Watch)> {
        tokio::task::spawn_blocking(move || Windows.connect(&name, agent))
            .await
            .unwrap()
    }

    fn watching(watch: Watch) -> oneshot::Receiver<()> {
        let (gone, watched) = oneshot::channel();
        thread::spawn(move || {
            watch.wait_until_gone();
            let _ = gone.send(());
        });
        watched
    }

    // A dropped tokio pipe closes its handle only once the runtime has processed the read it
    // cancelled, so waiting must keep the runtime running.
    async fn gone_within(watched: &mut oneshot::Receiver<()>, time: Duration) -> bool {
        matches!(timeout(time, watched).await, Ok(Ok(())))
    }

    #[tokio::test]
    async fn a_pipe_served_by_another_process_is_refused() {
        let (name, _server) = agent_pipe();
        let other = NonZeroU32::new(if own_pid().get() == 4 { 8 } else { 4 }).unwrap();
        let refused = connect_to(name, other).await.err().unwrap();
        assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn the_helper_writes_lines_to_the_agent_and_notices_when_it_closes() {
        let (name, mut server) = agent_pipe();
        let (mut pipe, watch) = connect_to(name, own_pid()).await.unwrap();
        server.connect().await.unwrap();
        server
            .write_all(&[super::super::protocol::START_ACK])
            .await
            .unwrap();
        let mut ack = [0];
        pipe.read_exact(&mut ack).unwrap();
        assert_eq!(ack, [super::super::protocol::START_ACK]);
        let mut watched = watching(watch);
        pipe.write_all(b"ready\n").unwrap();
        let mut line = [0; 6];
        server.read_exact(&mut line).await.unwrap();
        assert_eq!(&line, b"ready\n");
        assert!(!gone_within(&mut watched, Duration::from_millis(200)).await);
        drop(server);
        assert!(
            gone_within(&mut watched, PATIENCE).await,
            "the closed pipe was not noticed"
        );
        assert!(pipe.write_all(b"counters\n").is_err());
    }

    #[tokio::test]
    async fn a_byte_during_capture_means_the_agent_is_gone() {
        let (name, mut server) = agent_pipe();
        let (_pipe, watch) = connect_to(name, own_pid()).await.unwrap();
        server.connect().await.unwrap();
        let mut watched = watching(watch);
        assert!(!gone_within(&mut watched, Duration::from_millis(200)).await);
        server.write_all(b"x").await.unwrap();
        assert!(
            gone_within(&mut watched, PATIENCE).await,
            "the byte was not noticed"
        );
    }

    #[tokio::test]
    async fn the_end_of_the_agent_process_means_it_is_gone() {
        let (name, server) = agent_pipe();
        let (pipe, _) = connect_to(name, own_pid()).await.unwrap();
        server.connect().await.unwrap();
        let mut agent = Command::new(system_directory().unwrap().join("cmd.exe"))
            .args(["/d", "/c", "set /p line="])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let watch = watch(pipe.file, agent.id()).unwrap();
        let mut watched = watching(watch);
        assert!(!gone_within(&mut watched, Duration::from_millis(200)).await);
        drop(agent.stdin.take());
        agent.wait().unwrap();
        assert!(
            gone_within(&mut watched, PATIENCE).await,
            "the end of the agent was not noticed"
        );
    }
}
