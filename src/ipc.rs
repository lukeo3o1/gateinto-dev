use std::ffi::OsString;
use std::fmt;
use std::io;
use std::path::PathBuf;
use std::str::FromStr;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::sessions::SessionId;
use crate::uri::LaunchRequest;

pub const MAX_REQUEST_BYTES: usize = 1024;
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;
pub const INSTANCE_VARIABLE: &str = "GATEINTO_INSTANCE";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Launch(LaunchRequest),
    List,
    Close(SessionId),
    Stop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolError(&'static str);

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for ProtocolError {}

impl fmt::Display for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Launch(request) => write!(f, "launch {} {}", request.profile, request.auth),
            Self::List => f.write_str("list"),
            Self::Close(id) => write!(f, "close {id}"),
            Self::Stop => f.write_str("stop"),
        }
    }
}

impl FromStr for Request {
    type Err = ProtocolError;

    fn from_str(line: &str) -> Result<Self, Self::Err> {
        let invalid = ProtocolError("invalid request");
        let words: Vec<&str> = line.split(' ').collect();
        match words.as_slice() {
            ["launch", profile, auth] => LaunchRequest::new(profile, auth)
                .map(Self::Launch)
                .map_err(|_| ProtocolError("invalid launch request")),
            ["list"] => Ok(Self::List),
            ["close", id] => id.parse().map(Self::Close).map_err(|_| invalid),
            ["stop"] => Ok(Self::Stop),
            _ => Err(invalid),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    Ok(Vec<String>),
    Error(String),
}

fn single_line(text: &str) -> String {
    text.replace(['\r', '\n'], " ")
}

impl Response {
    pub fn encode(&self) -> String {
        match self {
            Self::Ok(lines) => {
                let mut text = String::from("ok\n");
                for line in lines {
                    text.push_str(&single_line(line));
                    text.push('\n');
                }
                text
            }
            Self::Error(message) => format!("error: {}\n", single_line(message)),
        }
    }

    pub fn decode(text: &str) -> Result<Self, ProtocolError> {
        let invalid = ProtocolError("invalid response from the agent");
        let mut lines = text.strip_suffix('\n').ok_or(invalid.clone())?.split('\n');
        match lines.next() {
            Some("ok") => Ok(Self::Ok(lines.map(str::to_owned).collect())),
            Some(error) => match (error.strip_prefix("error: "), lines.next()) {
                (Some(message), None) if !message.is_empty() => Ok(Self::Error(message.to_owned())),
                _ => Err(invalid),
            },
            None => Err(invalid),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint(OsString);

impl Endpoint {
    #[cfg(unix)]
    pub fn for_current_user() -> io::Result<Self> {
        Self::from_env_with(|name| std::env::var_os(name), "")
    }

    #[cfg(windows)]
    pub fn for_current_user() -> io::Result<Self> {
        Self::from_env_with(|name| std::env::var_os(name), &windows::user_sid()?)
    }

    pub fn from_env_with(env: impl Fn(&str) -> Option<OsString>, user: &str) -> io::Result<Self> {
        let suffix = match env(INSTANCE_VARIABLE) {
            None => String::new(),
            Some(instance) => {
                let instance = instance.into_string().unwrap_or_default();
                let valid = (1..=32).contains(&instance.len())
                    && instance
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-');
                if !valid {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "{INSTANCE_VARIABLE} must have 1 to 32 characters from A-Z, a-z, \
                             0-9, _ and -"
                        ),
                    ));
                }
                format!("-{instance}")
            }
        };
        Self::named(env, user, &suffix)
    }

    #[cfg(unix)]
    fn named(
        env: impl Fn(&str) -> Option<OsString>,
        _user: &str,
        suffix: &str,
    ) -> io::Result<Self> {
        let absolute = |name| {
            env(name)
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
        };
        let dir = absolute("XDG_RUNTIME_DIR")
            .map(|dir| dir.join("gateinto"))
            .or_else(|| absolute("HOME").map(|home| home.join(".local/state/gateinto")))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "neither XDG_RUNTIME_DIR nor HOME names an absolute directory for the agent \
                     socket",
                )
            })?;
        Ok(Self(dir.join(format!("agent{suffix}.sock")).into()))
    }

    #[cfg(windows)]
    fn named(
        _env: impl Fn(&str) -> Option<OsString>,
        user: &str,
        suffix: &str,
    ) -> io::Result<Self> {
        Ok(Self(
            format!(r"\\.\pipe\gateinto-agent-{user}{suffix}").into(),
        ))
    }

    #[cfg(unix)]
    pub fn unix(path: PathBuf) -> Self {
        Self(path.into())
    }

    #[cfg(windows)]
    pub fn pipe(name: &str) -> Self {
        Self(format!(r"\\.\pipe\{name}").into())
    }

    pub fn path(&self) -> PathBuf {
        PathBuf::from(&self.0)
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.display().fmt(f)
    }
}

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

pub type Connection = Box<dyn Stream>;

#[derive(Debug)]
pub enum BindError {
    AlreadyRunning(Endpoint),
    Io(Endpoint, io::Error),
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyRunning(endpoint) => {
                write!(f, "an agent is already running for this user at {endpoint}")
            }
            Self::Io(endpoint, error) => write!(f, "listening on {endpoint} failed: {error}"),
        }
    }
}

impl std::error::Error for BindError {}

#[derive(Debug)]
pub enum RequestError {
    NotRunning,
    Io(io::Error),
    Protocol(ProtocolError),
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRunning => f.write_str("no agent is running"),
            Self::Io(error) => write!(f, "talking to the agent failed: {error}"),
            Self::Protocol(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for RequestError {}

impl From<io::Error> for RequestError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub async fn send(endpoint: &Endpoint, request: &Request) -> Result<Response, RequestError> {
    let mut stream = connect(endpoint).await?;
    stream.write_all(format!("{request}\n").as_bytes()).await?;
    stream.flush().await?;
    let mut response = Vec::new();
    (&mut stream)
        .take(MAX_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut response)
        .await?;
    if response.len() > MAX_RESPONSE_BYTES {
        return Err(RequestError::Protocol(ProtocolError(
            "the agent's response is too long",
        )));
    }
    let response = String::from_utf8(response)
        .map_err(|_| RequestError::Protocol(ProtocolError("invalid response from the agent")))?;
    Response::decode(&response).map_err(RequestError::Protocol)
}

pub async fn read_request(connection: &mut Connection) -> Result<Request, ProtocolError> {
    let mut line = Vec::new();
    let mut reader = BufReader::new(connection).take(MAX_REQUEST_BYTES as u64);
    reader
        .read_until(b'\n', &mut line)
        .await
        .map_err(|_| ProtocolError("reading the request failed"))?;
    let line = line
        .strip_suffix(b"\n")
        .ok_or(ProtocolError("request too long or incomplete"))?;
    std::str::from_utf8(line)
        .map_err(|_| ProtocolError("invalid request"))?
        .parse()
}

pub async fn write_response(connection: &mut Connection, response: &Response) -> io::Result<()> {
    connection.write_all(response.encode().as_bytes()).await?;
    connection.shutdown().await
}

#[cfg(unix)]
pub use unix::{Server, connect};
#[cfg(windows)]
pub use windows::{Server, connect};

#[cfg(unix)]
mod unix {
    use std::fs::DirBuilder;
    use std::io;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::path::PathBuf;

    use tokio::net::{UnixListener, UnixStream};

    use super::{BindError, Connection, Endpoint, RequestError};

    #[derive(Debug)]
    pub struct Server {
        listener: UnixListener,
        path: PathBuf,
    }

    fn private_dir(path: &std::path::Path) -> io::Result<()> {
        let dir = path.parent().unwrap_or(path);
        DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        let metadata = std::fs::symlink_metadata(dir)?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} must be a directory that only its owner can access",
                    dir.display()
                ),
            ));
        }
        Ok(())
    }

    impl Server {
        pub fn bind(endpoint: &Endpoint) -> Result<Self, BindError> {
            let path = endpoint.path();
            let io_error = |error| BindError::Io(endpoint.clone(), error);
            private_dir(&path).map_err(io_error)?;
            let listener = match UnixListener::bind(&path) {
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                    if std::os::unix::net::UnixStream::connect(&path).is_ok() {
                        return Err(BindError::AlreadyRunning(endpoint.clone()));
                    }
                    std::fs::remove_file(&path).map_err(io_error)?;
                    UnixListener::bind(&path).map_err(io_error)?
                }
                result => result.map_err(io_error)?,
            };
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .map_err(io_error)?;
            Ok(Self { listener, path })
        }

        pub async fn accept(&mut self) -> io::Result<Connection> {
            let (stream, _) = self.listener.accept().await?;
            Ok(Box::new(stream))
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    pub async fn connect(endpoint: &Endpoint) -> Result<Connection, RequestError> {
        match UnixStream::connect(endpoint.path()).await {
            Ok(stream) => Ok(Box::new(stream)),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ) =>
            {
                Err(RequestError::NotRunning)
            }
            Err(error) => Err(RequestError::Io(error)),
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::io;
    use std::ptr::null_mut;
    use std::time::Duration;

    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, HANDLE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use super::{BindError, Connection, Endpoint, RequestError};

    const BUSY_RETRIES: u32 = 100;
    const BUSY_DELAY: Duration = Duration::from_millis(20);

    #[derive(Debug)]
    pub struct Server {
        endpoint: Endpoint,
        next: NamedPipeServer,
    }

    impl Server {
        pub fn bind(endpoint: &Endpoint) -> Result<Self, BindError> {
            let next = ServerOptions::new()
                .first_pipe_instance(true)
                .reject_remote_clients(true)
                .create(endpoint.path())
                .map_err(|error| match error.kind() {
                    io::ErrorKind::PermissionDenied => BindError::AlreadyRunning(endpoint.clone()),
                    _ => BindError::Io(endpoint.clone(), error),
                })?;
            Ok(Self {
                endpoint: endpoint.clone(),
                next,
            })
        }

        pub async fn accept(&mut self) -> io::Result<Connection> {
            self.next.connect().await?;
            let next = ServerOptions::new()
                .reject_remote_clients(true)
                .create(self.endpoint.path())?;
            Ok(Box::new(std::mem::replace(&mut self.next, next)))
        }
    }

    pub async fn connect(endpoint: &Endpoint) -> Result<Connection, RequestError> {
        for _ in 0..BUSY_RETRIES {
            match ClientOptions::new().open(endpoint.path()) {
                Ok(client) => return Ok(Box::new(client)),
                Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                    tokio::time::sleep(BUSY_DELAY).await;
                }
                Err(error) if error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) => {
                    return Err(RequestError::NotRunning);
                }
                Err(error) => return Err(RequestError::Io(error)),
            }
        }
        Err(RequestError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "the agent's pipe stayed busy",
        )))
    }

    struct Token(HANDLE);

    impl Drop for Token {
        fn drop(&mut self) {
            // SAFETY: the handle came from OpenProcessToken and is closed once.
            unsafe { CloseHandle(self.0) };
        }
    }

    pub fn user_sid() -> io::Result<String> {
        let mut token = null_mut();
        // SAFETY: GetCurrentProcess returns a pseudo handle; token receives an owned handle.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = Token(token);
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
        // SAFETY: GetTokenInformation wrote a TOKEN_USER at the start of the aligned buffer.
        let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        let mut string = null_mut();
        // SAFETY: the SID points into buffer, which outlives this call.
        if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut string) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: ConvertSidToStringSidW returned a NUL-terminated string that LocalFree releases.
        let sid = unsafe {
            let len = (0..).take_while(|&i| *string.add(i) != 0).count();
            let sid = String::from_utf16_lossy(std::slice::from_raw_parts(string, len));
            LocalFree(string.cast());
            sid
        };
        Ok(sid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn launch(profile: &str) -> Request {
        Request::Launch(LaunchRequest::new(profile, "basic_tofu").unwrap())
    }

    #[test]
    fn requests_round_trip_as_single_lines() {
        for (request, line) in [
            (launch("office"), "launch office basic_tofu"),
            (Request::List, "list"),
            (Request::Close(SessionId(12)), "close 12"),
            (Request::Stop, "stop"),
        ] {
            assert_eq!(request.to_string(), line);
            assert_eq!(line.parse::<Request>(), Ok(request));
        }
    }

    #[test]
    fn malformed_requests_are_rejected() {
        let long = format!("launch {} basic_tofu", "a".repeat(65));
        for line in [
            "",
            " ",
            "LIST",
            "list ",
            " list",
            "list\r",
            "list\n",
            "stop now",
            "launch",
            "launch office",
            "launch office basic_tofu extra",
            "launch  office basic_tofu",
            "launch office none",
            "launch ../office basic_tofu",
            "launch -office basic_tofu",
            "launch --config basic_tofu",
            "launch off\"ice basic_tofu",
            "launch office%20x basic_tofu",
            "launch caf\u{e9} basic_tofu",
            long.as_str(),
            "close",
            "close x",
            "close -1",
            "close 1 2",
            "close 99999999999999999999999",
            "open gateinto://connect?profile=office",
        ] {
            assert!(line.parse::<Request>().is_err(), "{line:?}");
        }
    }

    #[test]
    fn responses_round_trip() {
        for response in [
            Response::Ok(Vec::new()),
            Response::Ok(vec![
                "session: 1".to_owned(),
                "listen: 127.0.0.1:1".to_owned(),
            ]),
            Response::Error("unknown gateway \"x\"".to_owned()),
        ] {
            assert_eq!(Response::decode(&response.encode()), Ok(response));
        }
        assert_eq!(Response::Ok(vec!["a".to_owned()]).encode(), "ok\na\n");
        assert_eq!(Response::Error("bad".to_owned()).encode(), "error: bad\n");
    }

    #[test]
    fn line_breaks_inside_responses_cannot_forge_lines() {
        let response = Response::Error("first\nok\rsecond".to_owned());
        assert_eq!(response.encode(), "error: first ok second\n");
        let response = Response::Ok(vec!["a\nerror: x".to_owned()]);
        assert_eq!(response.encode(), "ok\na error: x\n");
    }

    #[test]
    fn malformed_responses_are_rejected() {
        for text in ["", "ok", "fine\n", "error:x\n", "error: \n"] {
            assert!(Response::decode(text).is_err(), "{text:?}");
        }
    }

    fn env(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let vars: HashMap<String, OsString> = vars
            .iter()
            .map(|(name, value)| (name.to_string(), OsString::from(value)))
            .collect();
        move |name| vars.get(name).cloned()
    }

    #[cfg(unix)]
    #[test]
    fn the_unix_socket_lives_in_the_per_user_runtime_directory() {
        let endpoint = |vars: &[(&str, &str)]| Endpoint::from_env_with(env(vars), "ignored");
        assert_eq!(
            endpoint(&[("XDG_RUNTIME_DIR", "/run/user/1000"), ("HOME", "/home/me")])
                .unwrap()
                .path(),
            PathBuf::from("/run/user/1000/gateinto/agent.sock")
        );
        assert_eq!(
            endpoint(&[("HOME", "/home/me")]).unwrap().path(),
            PathBuf::from("/home/me/.local/state/gateinto/agent.sock")
        );
        assert_eq!(
            endpoint(&[("HOME", "/home/me"), (INSTANCE_VARIABLE, "test-1")])
                .unwrap()
                .path(),
            PathBuf::from("/home/me/.local/state/gateinto/agent-test-1.sock")
        );
        assert!(endpoint(&[]).is_err());
        assert!(endpoint(&[("HOME", "relative")]).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn the_named_pipe_is_named_after_the_user() {
        let endpoint = |vars: &[(&str, &str)]| Endpoint::from_env_with(env(vars), "S-1-5-21-1");
        assert_eq!(
            endpoint(&[]).unwrap().path(),
            PathBuf::from(r"\\.\pipe\gateinto-agent-S-1-5-21-1")
        );
        assert_eq!(
            endpoint(&[(INSTANCE_VARIABLE, "test-1")]).unwrap().path(),
            PathBuf::from(r"\\.\pipe\gateinto-agent-S-1-5-21-1-test-1")
        );
    }

    #[test]
    fn instance_names_are_restricted() {
        let home: &[(&str, &str)] = &[("HOME", "/home/me")];
        for instance in ["", "a b", "../x", "a\\b", "a/b", &"a".repeat(33)] {
            let mut vars = home.to_vec();
            vars.push((INSTANCE_VARIABLE, instance));
            assert!(
                Endpoint::from_env_with(env(&vars), "S-1-5-21-1").is_err(),
                "{instance:?}"
            );
        }
    }
}
