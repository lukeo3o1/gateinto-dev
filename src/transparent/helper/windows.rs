use std::ffi::OsStr;
use std::future::Future;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::pin::Pin;
use std::ptr::null_mut;
use std::task::{Context, Poll};
use std::thread;

use tokio::io::{AsyncRead, ReadBuf};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::oneshot;
use windows_sys::Win32::Foundation::{FALSE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::Threading::GetProcessId;
use windows_sys::Win32::UI::Shell::{
    SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
    ShellExecuteExW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

use super::pipe_sddl;
use crate::divert::helper::PipeName;
use crate::job::{parameters, wait_for};
use crate::token::Handle;

const MASK: u32 = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;

pub struct Windows;

impl super::Platform for Windows {
    type Pipe = Server;
    type Process = Elevated;

    fn create_pipe(&self, name: &PipeName) -> io::Result<Server> {
        let descriptor = Descriptor::from_sddl(&pipe_sddl(&crate::ipc::user_sid()?))?;
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: FALSE,
        };
        // SAFETY: attributes and the descriptor it points to outlive the call.
        let server = unsafe {
            options()
                .create_with_security_attributes_raw(name.as_str(), (&raw mut attributes).cast())
        }?;
        Ok(Server(server))
    }

    async fn launch(&self, arguments: Vec<String>) -> io::Result<Elevated> {
        tokio::task::spawn_blocking(move || {
            let image = std::env::current_exe()?;
            run_elevated(&image, &arguments)
        })
        .await
        .map_err(io::Error::other)?
    }
}

fn options() -> ServerOptions {
    let mut options = ServerOptions::new();
    options
        .access_inbound(true)
        .access_outbound(true)
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .max_instances(1);
    options
}

struct Descriptor(PSECURITY_DESCRIPTOR);

impl Descriptor {
    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let sddl: Vec<u16> = sddl.encode_utf16().chain([0]).collect();
        let mut descriptor = null_mut();
        // SAFETY: sddl is NUL-terminated; descriptor receives a LocalAlloc block freed in Drop.
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        if converted == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(descriptor))
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: the block was allocated by Windows with LocalAlloc and is freed once.
        unsafe { LocalFree(self.0) };
    }
}

pub struct Server(NamedPipeServer);

impl AsyncRead for Server {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buffer)
    }
}

impl super::Pipe for Server {
    fn connect(&mut self) -> impl Future<Output = io::Result<()>> + Send {
        self.0.connect()
    }

    fn client_pid(&self) -> io::Result<u32> {
        let mut pid = 0;
        // SAFETY: the handle is an open pipe and pid is a valid out pointer.
        if unsafe { GetNamedPipeClientProcessId(self.0.as_raw_handle(), &mut pid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(pid)
    }
}

pub struct Elevated {
    handle: Handle,
    id: u32,
}

impl Elevated {
    fn new(handle: Handle) -> io::Result<Self> {
        // SAFETY: the handle is an open process handle.
        let id = unsafe { GetProcessId(handle.0) };
        if id == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { handle, id })
    }
}

impl super::Process for Elevated {
    fn id(&self) -> u32 {
        self.id
    }

    fn wait(self) -> impl Future<Output = Option<u32>> + Send + 'static {
        let (sender, exited) = oneshot::channel();
        let handle = self.handle;
        let _ = thread::Builder::new().spawn(move || {
            let code = wait_for(&handle).ok().and_then(|status| status.code());
            let _ = sender.send(code.map(|code| code as u32));
        });
        async move { exited.await.ok().flatten() }
    }
}

fn run_elevated(image: &Path, arguments: &[String]) -> io::Result<Elevated> {
    let verb = wide(OsStr::new("runas"));
    let file = wide(image.as_os_str());
    let arguments: Vec<Vec<u16>> = arguments
        .iter()
        .map(|argument| argument.encode_utf16().collect())
        .collect();
    let parameters = parameters(&arguments)?;
    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: MASK,
        lpVerb: verb.as_ptr(),
        lpFile: file.as_ptr(),
        lpParameters: parameters.as_ptr(),
        nShow: SW_HIDE,
        ..SHELLEXECUTEINFOW::default()
    };
    // SAFETY: info has its size set and its strings are NUL-terminated and outlive the call.
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let process = info.hProcess;
    if process.is_null() {
        return Err(io::Error::other(
            "the transparent engine was started without a process handle",
        ));
    }
    Elevated::new(Handle(process))
}

fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain([0]).collect()
}

#[cfg(test)]
mod tests {
    use std::os::windows::io::IntoRawHandle;
    use std::process::Command;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::ClientOptions;
    use windows_sys::Win32::Foundation::{
        ERROR_PIPE_BUSY, ERROR_SUCCESS, GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SE_KERNEL_OBJECT,
    };
    use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;

    use super::super::{Pipe as _, Platform as _, Process as _};
    use super::*;

    fn name() -> PipeName {
        let mut bytes = [0; 16];
        aws_lc_rs::rand::fill(&mut bytes).unwrap();
        PipeName::from_random(bytes)
    }

    fn sddl_of(descriptor: &Descriptor) -> String {
        let mut text = null_mut();
        let mut length = 0;
        // SAFETY: the descriptor is valid; text receives a LocalAlloc string freed below.
        let converted = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor.0,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                &mut length,
            )
        };
        assert_ne!(converted, 0, "{}", io::Error::last_os_error());
        // SAFETY: text holds length UTF-16 units and is released once.
        let sddl = unsafe {
            let sddl = String::from_utf16_lossy(std::slice::from_raw_parts(text, length as usize));
            LocalFree(text.cast());
            sddl
        };
        sddl.trim_end_matches('\0').to_owned()
    }

    fn dacl(handle: HANDLE) -> String {
        let mut descriptor = null_mut();
        // SAFETY: the handle is open; descriptor receives a LocalAlloc block freed on drop.
        let status = unsafe {
            GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(status, ERROR_SUCCESS);
        sddl_of(&Descriptor(descriptor))
    }

    fn grants(sddl: &str) -> Vec<(String, String)> {
        sddl.split('(')
            .skip(1)
            .map(|ace| {
                let fields: Vec<&str> = ace.trim_end_matches(')').split(';').collect();
                (fields[0].to_owned(), fields[5].to_owned())
            })
            .collect()
    }

    #[tokio::test]
    async fn the_pipe_allows_only_the_user_and_the_administrators() {
        let server = Windows.create_pipe(&name()).unwrap();
        let user = crate::ipc::user_sid().unwrap();
        let expected = sddl_of(&Descriptor::from_sddl(&pipe_sddl(&user)).unwrap());
        let granted = grants(&dacl(server.0.as_raw_handle()));
        assert_eq!(granted, grants(&expected));
        assert_eq!(granted.len(), 2, "{granted:?}");
        assert!(granted.iter().all(|(kind, _)| kind == "A"), "{granted:?}");
        assert_eq!(granted[1].1, "BA");
    }

    #[tokio::test]
    async fn a_client_of_the_same_user_connects_and_its_pid_is_read() {
        let name = name();
        let mut server = Windows.create_pipe(&name).unwrap();
        let mut client = ClientOptions::new().open(name.as_str()).unwrap();
        server.connect().await.unwrap();
        assert_eq!(server.client_pid().unwrap(), std::process::id());
        client.write_all(b"ready\n").await.unwrap();
        let mut line = [0; 6];
        server.read_exact(&mut line).await.unwrap();
        assert_eq!(&line, b"ready\n");
        drop(client);
        assert_eq!(server.read(&mut line).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn the_pipe_has_one_instance_and_a_second_client_is_refused() {
        let name = name();
        let mut server = Windows.create_pipe(&name).unwrap();
        assert_eq!(server.0.info().unwrap().max_instances, 1);
        let _client = ClientOptions::new().open(name.as_str()).unwrap();
        server.connect().await.unwrap();
        let refused = ClientOptions::new().open(name.as_str()).unwrap_err();
        assert_eq!(refused.raw_os_error(), Some(ERROR_PIPE_BUSY as i32));
    }

    #[tokio::test]
    async fn a_second_server_of_the_same_name_cannot_be_created() {
        let name = name();
        let _first = Windows.create_pipe(&name).unwrap();
        assert!(Windows.create_pipe(&name).is_err());
        assert!(ServerOptions::new().create(name.as_str()).is_err());
    }

    #[test]
    fn the_pipe_is_duplex_first_and_only_and_rejects_remote_clients() {
        let options = format!("{:?}", options());
        for set in [
            "access_inbound: true",
            "access_outbound: true",
            "first_pipe_instance: true",
            "reject_remote_clients: true",
            "max_instances: 1,",
        ] {
            assert!(options.contains(set), "{set} in {options}");
        }
    }

    #[tokio::test]
    async fn the_pipe_handle_is_not_inherited() {
        let server = Windows.create_pipe(&name()).unwrap();
        let mut flags = 0;
        // SAFETY: the handle is open and flags is a valid out pointer.
        let read = unsafe { GetHandleInformation(server.0.as_raw_handle(), &mut flags) };
        assert_ne!(read, 0, "{}", io::Error::last_os_error());
        assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
    }

    #[test]
    fn the_launch_waits_for_completion_keeps_the_process_handle_and_shows_no_error_dialog() {
        for (flag, name) in [
            (SEE_MASK_NOCLOSEPROCESS, "SEE_MASK_NOCLOSEPROCESS"),
            (SEE_MASK_NOASYNC, "SEE_MASK_NOASYNC"),
            (SEE_MASK_FLAG_NO_UI, "SEE_MASK_FLAG_NO_UI"),
        ] {
            assert_eq!(MASK & flag, flag, "{name} is missing from the mask");
        }
    }

    #[tokio::test]
    async fn the_id_and_the_exit_code_are_read_from_the_process_handle() {
        let shell = std::env::var_os("ComSpec").unwrap();
        let child = Command::new(shell)
            .args(["/d", "/c", "exit 7"])
            .spawn()
            .unwrap();
        let id = child.id();
        let process = Elevated::new(Handle(child.into_raw_handle())).unwrap();
        assert_eq!(process.id(), id);
        assert_eq!(process.wait().await, Some(7));
    }
}
