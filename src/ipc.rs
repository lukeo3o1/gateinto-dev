use std::ffi::OsString;
use std::fmt;
use std::io;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::proxy::SessionCredentials;
use crate::sessions::SessionId;
use crate::uri::LaunchRequest;

pub const MAX_REQUEST_BYTES: usize = 8192;
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;
pub const INSTANCE_VARIABLE: &str = "GATEINTO_INSTANCE";
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const BUSY_RETRY_DELAY: Duration = Duration::from_millis(20);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Launch(LaunchRequest),
    Approve(ConfirmToken),
    Deny(ConfirmToken),
    List,
    Close(SessionId),
    Credentials(SessionId),
    Stop,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ConfirmToken([u8; 16]);

impl ConfirmToken {
    pub fn random() -> io::Result<Self> {
        use aws_lc_rs::rand::{SecureRandom, SystemRandom};

        let mut bytes = [0; 16];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| io::Error::other("the system random number generator failed"))?;
        Ok(Self(bytes))
    }
}

impl fmt::Debug for ConfirmToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConfirmToken(..)")
    }
}

impl fmt::Display for ConfirmToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

impl FromStr for ConfirmToken {
    type Err = ProtocolError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid = ProtocolError("invalid confirmation token");
        let digit = |byte: u8| match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(invalid.clone()),
        };
        if text.len() != 32 {
            return Err(invalid);
        }
        let mut bytes = [0; 16];
        for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().chunks(2)) {
            *byte = digit(pair[0])? << 4 | digit(pair[1])?;
        }
        Ok(Self(bytes))
    }
}

pub const CONFIRM: &str = "confirm: ";

pub fn confirm_line(token: &ConfirmToken) -> String {
    format!("{CONFIRM}{token}")
}

pub fn confirm_token(lines: &[String]) -> Option<ConfirmToken> {
    lines
        .iter()
        .find_map(|line| line.strip_prefix(CONFIRM)?.parse().ok())
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
            Self::Launch(request) => {
                f.write_str("launch ")?;
                if let Some(profile) = &request.profile {
                    write!(f, "{profile} ")?;
                }
                write!(f, "{}", request.auth)?;
                if request.route != crate::proxy::Route::Gateway {
                    write!(f, " route={}", request.route)?;
                }
                if let Some(url) = &request.url {
                    write!(f, " url={url}")?;
                }
                if let Some(gateway) = &request.gateway {
                    write!(f, " gateway={gateway}")?;
                }
                if let Some(portal) = &request.portal {
                    write!(f, " portal={portal}")?;
                }
                Ok(())
            }
            Self::Approve(token) => write!(f, "approve {token}"),
            Self::Deny(token) => write!(f, "deny {token}"),
            Self::List => f.write_str("list"),
            Self::Close(id) => write!(f, "close {id}"),
            Self::Credentials(id) => write!(f, "credentials {id}"),
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
            ["launch", profile, auth @ "session_credentials", link @ ..] => {
                let request = launch(Some(profile), auth, link)
                    .filter(|request| request.to_string() == line)
                    .ok_or(ProtocolError("invalid launch request"))?;
                Ok(request)
            }
            ["launch", auth @ "session_credentials", link @ ..] => {
                let request = launch(None, auth, link)
                    .filter(|request| request.to_string() == line)
                    .ok_or(ProtocolError("invalid launch request"))?;
                Ok(request)
            }
            ["launch", "basic_tofu", ..] | ["launch", _, "basic_tofu", ..] => Err(ProtocolError(
                "the basic_tofu local proxy authentication was removed; use session_credentials",
            )),
            ["approve", token] => token.parse().map(Self::Approve),
            ["deny", token] => token.parse().map(Self::Deny),
            ["list"] => Ok(Self::List),
            ["close", id] => id.parse().map(Self::Close).map_err(|_| invalid),
            ["credentials", id] => id.parse().map(Self::Credentials).map_err(|_| invalid),
            ["stop"] => Ok(Self::Stop),
            _ => Err(invalid),
        }
    }
}

fn launch(profile: Option<&str>, auth: &str, link: &[&str]) -> Option<Request> {
    let mut values = [None; 4];
    let mut next = 0;
    for word in link {
        let (key, value) = word.split_once('=')?;
        let index = ["route", "url", "gateway", "portal"]
            .iter()
            .position(|name| *name == key)
            .filter(|&index| index >= next)?;
        values[index] = Some(value);
        next = index + 1;
    }
    let [route, url, gateway, portal] = values;
    LaunchRequest::from_fields(profile, auth, url, gateway, portal)
        .ok()?
        .with_route(route.unwrap_or("gateway"))
        .ok()
        .map(Request::Launch)
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

const USERNAME: &str = "username: ";
const PASSWORD: &str = "password: ";

pub fn credential_lines(credentials: &SessionCredentials) -> [String; 2] {
    [
        format!("{USERNAME}{}", credentials.username()),
        format!("{PASSWORD}{}", credentials.password()),
    ]
}

pub fn issued_credentials(lines: &[String]) -> Option<SessionCredentials> {
    let value = |prefix: &str| lines.iter().find_map(|line| line.strip_prefix(prefix));
    SessionCredentials::parse(value(USERNAME)?, value(PASSWORD)?)
}

pub fn without_credentials(lines: Vec<String>) -> Vec<String> {
    lines
        .into_iter()
        .filter(|line| !line.starts_with(USERNAME) && !line.starts_with(PASSWORD))
        .collect()
}

pub const AGENT_PID: &str = "agent-pid: ";

pub fn agent_pid_line() -> String {
    format!("{AGENT_PID}{}", std::process::id())
}

pub fn agent_pid(lines: &[String]) -> Option<u32> {
    lines
        .iter()
        .find_map(|line| line.strip_prefix(AGENT_PID)?.parse().ok())
}

pub fn instance_from(env: impl Fn(&str) -> Option<OsString>) -> io::Result<Option<String>> {
    let Some(instance) = env(INSTANCE_VARIABLE) else {
        return Ok(None);
    };
    let instance = instance.into_string().unwrap_or_default();
    let valid = (1..=32).contains(&instance.len())
        && instance
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-');
    if valid {
        Ok(Some(instance))
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{INSTANCE_VARIABLE} must have 1 to 32 characters from A-Z, a-z, 0-9, _ and -"),
        ))
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
        let suffix = instance_from(&env)?
            .map(|instance| format!("-{instance}"))
            .unwrap_or_default();
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
    HeldByAnotherUser(Endpoint),
    Io(Endpoint, io::Error),
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyRunning(endpoint) => {
                write!(f, "an agent is already running for this user at {endpoint}")
            }
            Self::HeldByAnotherUser(endpoint) => {
                write!(f, "the agent endpoint {endpoint} is held by another user")
            }
            Self::Io(endpoint, error) => write!(f, "listening on {endpoint} failed: {error}"),
        }
    }
}

impl std::error::Error for BindError {}

pub fn busy_retry_delay(deadline: Instant, now: Instant) -> Option<Duration> {
    let remaining = deadline
        .checked_duration_since(now)
        .filter(|r| !r.is_zero())?;
    Some(remaining.min(BUSY_RETRY_DELAY))
}

pub fn retry_while_busy<T>(
    deadline: Instant,
    mut attempt: impl FnMut() -> io::Result<T>,
    is_busy: impl Fn(&io::Error) -> bool,
    mut wait: impl FnMut(Duration),
) -> io::Result<T> {
    loop {
        match attempt() {
            Err(error) if is_busy(&error) => match busy_retry_delay(deadline, Instant::now()) {
                Some(delay) => wait(delay),
                None => return Err(error),
            },
            result => return result,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstanceState {
    Listening,
    Connected,
    Spent,
}

#[derive(Debug)]
pub struct Instances<P> {
    current: P,
    state: InstanceState,
}

impl<P> Instances<P> {
    pub fn new(first: P) -> Self {
        Self {
            current: first,
            state: InstanceState::Listening,
        }
    }

    pub fn replace_spent(&mut self, create: impl FnOnce() -> io::Result<P>) -> io::Result<()> {
        if self.state == InstanceState::Spent {
            self.current = create()?;
            self.state = InstanceState::Listening;
        }
        Ok(())
    }

    pub async fn connect(
        &mut self,
        connect: impl AsyncFnOnce(&P) -> io::Result<()>,
    ) -> io::Result<()> {
        if self.state == InstanceState::Listening {
            if let Err(error) = connect(&self.current).await {
                self.state = InstanceState::Spent;
                return Err(error);
            }
            self.state = InstanceState::Connected;
        }
        Ok(())
    }

    pub fn hand_off(&mut self, create: impl FnOnce() -> io::Result<P>) -> io::Result<P> {
        let next = create()?;
        self.state = InstanceState::Listening;
        Ok(std::mem::replace(&mut self.current, next))
    }
}

pub fn taken_pipe(endpoint: &Endpoint, owned_by_user: io::Result<bool>) -> BindError {
    match owned_by_user {
        Ok(true) => BindError::AlreadyRunning(endpoint.clone()),
        Ok(false) => BindError::HeldByAnotherUser(endpoint.clone()),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            BindError::HeldByAnotherUser(endpoint.clone())
        }
        Err(error) => BindError::Io(endpoint.clone(), error),
    }
}

#[derive(Debug)]
pub enum RequestError {
    NotRunning,
    Closed,
    TimedOut,
    UntrustedServer(String),
    Io(io::Error),
    Protocol(ProtocolError),
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRunning => f.write_str("no agent is running"),
            Self::Closed => f.write_str("the agent closed the connection without an answer"),
            Self::TimedOut => write!(
                f,
                "the agent did not answer within {} seconds",
                REQUEST_TIMEOUT.as_secs()
            ),
            Self::UntrustedServer(reason) => write!(
                f,
                "refusing to talk to the agent endpoint because {reason}; another user may have \
                 created it"
            ),
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
    send_with_timeout(endpoint, request, REQUEST_TIMEOUT).await
}

pub async fn send_with_timeout(
    endpoint: &Endpoint,
    request: &Request,
    limit: Duration,
) -> Result<Response, RequestError> {
    tokio::time::timeout(limit, exchange(endpoint, request))
        .await
        .unwrap_or(Err(RequestError::TimedOut))
}

fn closed_or_io(error: io::Error) -> RequestError {
    match error.kind() {
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset => RequestError::Closed,
        _ => RequestError::Io(error),
    }
}

async fn exchange(endpoint: &Endpoint, request: &Request) -> Result<Response, RequestError> {
    let mut stream = connect(endpoint).await?;
    stream
        .write_all(format!("{request}\n").as_bytes())
        .await
        .map_err(closed_or_io)?;
    stream.flush().await.map_err(closed_or_io)?;
    let response = read_to_close(&mut stream, MAX_RESPONSE_BYTES)
        .await
        .map_err(closed_or_io)?;
    if response.is_empty() {
        return Err(RequestError::Closed);
    }
    if response.len() > MAX_RESPONSE_BYTES {
        return Err(RequestError::Protocol(ProtocolError(
            "the agent's response is too long",
        )));
    }
    let response = String::from_utf8(response)
        .map_err(|_| RequestError::Protocol(ProtocolError("invalid response from the agent")))?;
    Response::decode(&response).map_err(RequestError::Protocol)
}

pub async fn read_to_close(
    stream: &mut (impl AsyncRead + Unpin),
    limit: usize,
) -> io::Result<Vec<u8>> {
    let mut received = Vec::new();
    let mut buffer = [0; 4096];
    while received.len() <= limit {
        match stream.read(&mut buffer).await {
            Ok(0) => break,
            Ok(n) => received.extend_from_slice(&buffer[..n]),
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => break,
            Err(error) => return Err(error),
        }
    }
    Ok(received)
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
    use std::fs::{DirBuilder, OpenOptions};
    use std::io;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use tokio::net::{UnixListener, UnixStream};

    use super::{BindError, Connection, Endpoint, RequestError};

    #[derive(Debug)]
    pub struct Server {
        listener: UnixListener,
        path: PathBuf,
    }

    const LOCK_STALE_AFTER: Duration = Duration::from_secs(10);
    const LOCK_WAIT: Duration = Duration::from_secs(15);
    const LOCK_POLL: Duration = Duration::from_millis(20);

    fn private_dir(dir: &Path) -> io::Result<u32> {
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
        Ok(metadata.uid())
    }

    struct BindLock(PathBuf);

    impl BindLock {
        fn acquire(path: &Path) -> io::Result<(Self, u32)> {
            let mut name = path.file_name().unwrap_or_default().to_owned();
            name.push(".lock");
            let lock = path.with_file_name(name);
            let deadline = Instant::now() + LOCK_WAIT;
            loop {
                match OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&lock)
                {
                    Ok(file) => return Ok((Self(lock), file.metadata()?.uid())),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        let stale = std::fs::symlink_metadata(&lock)
                            .and_then(|metadata| metadata.modified())
                            .is_ok_and(|at| at.elapsed().unwrap_or_default() >= LOCK_STALE_AFTER);
                        if stale {
                            let _ = std::fs::remove_file(&lock);
                            continue;
                        }
                        if Instant::now() >= deadline {
                            return Err(io::Error::new(
                                io::ErrorKind::WouldBlock,
                                format!(
                                    "another agent kept {} for {} seconds",
                                    lock.display(),
                                    LOCK_WAIT.as_secs()
                                ),
                            ));
                        }
                        std::thread::sleep(LOCK_POLL);
                    }
                    Err(error) => return Err(error),
                }
            }
        }
    }

    impl Drop for BindLock {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    impl Server {
        pub fn bind(endpoint: &Endpoint) -> Result<Self, BindError> {
            let path = endpoint.path();
            let io_error = |error| BindError::Io(endpoint.clone(), error);
            let dir = path.parent().unwrap_or(&path);
            let owner = private_dir(dir).map_err(io_error)?;
            let (_lock, me) = BindLock::acquire(&path).map_err(io_error)?;
            if owner != me {
                return Err(io_error(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("{} is owned by another user", dir.display()),
                )));
            }
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

pub fn owner_only_sddl(user_sid: &str) -> String {
    format!("O:{user_sid}D:P(A;;GA;;;{user_sid})(A;;GA;;;SY)")
}

#[cfg(windows)]
pub use windows::user_sid;

#[cfg(windows)]
mod windows {
    use std::io;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::ptr::null_mut;
    use std::time::{Duration, Instant};

    use tokio::net::windows::named_pipe::{
        ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
    };
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, ERROR_SUCCESS, HANDLE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetSecurityInfo, SDDL_REVISION_1, SE_KERNEL_OBJECT,
    };
    use windows_sys::Win32::Security::{
        EqualSid, GetTokenInformation, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{READ_CONTROL, SECURITY_IDENTIFICATION};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use super::{
        BindError, Connection, Endpoint, Instances, REQUEST_TIMEOUT, RequestError,
        busy_retry_delay, owner_only_sddl, retry_while_busy, taken_pipe,
    };

    const BIND_PROBE_TIMEOUT: Duration = Duration::from_secs(1);

    #[derive(Debug)]
    struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

    // SAFETY: the descriptor is a LocalAlloc block owned by this value and only read by Windows.
    unsafe impl Send for SecurityDescriptor {}

    impl SecurityDescriptor {
        fn owner_only() -> io::Result<Self> {
            let sddl: Vec<u16> = owner_only_sddl(&user_sid()?)
                .encode_utf16()
                .chain(Some(0))
                .collect();
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

        fn create(&self, endpoint: &Endpoint, first: bool) -> io::Result<NamedPipeServer> {
            let mut attributes = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.0,
                bInheritHandle: 0,
            };
            // SAFETY: attributes and the descriptor it points to outlive the call.
            unsafe {
                ServerOptions::new()
                    .first_pipe_instance(first)
                    .reject_remote_clients(true)
                    .create_with_security_attributes_raw(
                        endpoint.path(),
                        (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
                    )
            }
        }
    }

    impl Drop for SecurityDescriptor {
        fn drop(&mut self) {
            // SAFETY: the block was allocated by Windows with LocalAlloc and is freed once.
            unsafe { LocalFree(self.0) };
        }
    }

    #[derive(Debug)]
    pub struct Server {
        endpoint: Endpoint,
        descriptor: SecurityDescriptor,
        instances: Instances<NamedPipeServer>,
    }

    impl Server {
        pub fn bind(endpoint: &Endpoint) -> Result<Self, BindError> {
            let io_error = |error| BindError::Io(endpoint.clone(), error);
            let descriptor = SecurityDescriptor::owner_only().map_err(io_error)?;
            let listening =
                descriptor
                    .create(endpoint, true)
                    .map_err(|error| match error.kind() {
                        io::ErrorKind::PermissionDenied => {
                            taken_pipe(endpoint, pipe_owned_by_current_user(endpoint))
                        }
                        _ => io_error(error),
                    })?;
            Ok(Self {
                endpoint: endpoint.clone(),
                descriptor,
                instances: Instances::new(listening),
            })
        }

        pub async fn accept(&mut self) -> io::Result<Connection> {
            let create = || self.descriptor.create(&self.endpoint, false);
            self.instances.replace_spent(create)?;
            self.instances.connect(NamedPipeServer::connect).await?;
            let create = || self.descriptor.create(&self.endpoint, false);
            Ok(Box::new(self.instances.hand_off(create)?))
        }
    }

    pub async fn connect(endpoint: &Endpoint) -> Result<Connection, RequestError> {
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        loop {
            match ClientOptions::new().open(endpoint.path()) {
                Ok(client) => {
                    verify_server(&client)?;
                    return Ok(Box::new(client));
                }
                Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                    match busy_retry_delay(deadline, Instant::now()) {
                        Some(delay) => tokio::time::sleep(delay).await,
                        None => return Err(RequestError::TimedOut),
                    }
                }
                Err(error) if error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) => {
                    return Err(RequestError::NotRunning);
                }
                Err(error) => return Err(RequestError::Io(error)),
            }
        }
    }

    fn verify_server(client: &NamedPipeClient) -> Result<(), RequestError> {
        match owned_by_current_user(client.as_raw_handle()) {
            Ok(true) => Ok(()),
            Ok(false) => Err(RequestError::UntrustedServer(
                "it is owned by another user".to_owned(),
            )),
            Err(error) => Err(RequestError::UntrustedServer(format!(
                "its owner is unknown: {error}"
            ))),
        }
    }

    fn pipe_owned_by_current_user(endpoint: &Endpoint) -> io::Result<bool> {
        let pipe = retry_while_busy(
            Instant::now() + BIND_PROBE_TIMEOUT,
            || {
                std::fs::OpenOptions::new()
                    .access_mode(READ_CONTROL)
                    .security_qos_flags(SECURITY_IDENTIFICATION)
                    .open(endpoint.path())
            },
            |error| error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32),
            std::thread::sleep,
        )?;
        owned_by_current_user(pipe.as_raw_handle())
    }

    pub(super) fn owned_by_current_user(handle: HANDLE) -> io::Result<bool> {
        let mut owner = null_mut();
        let mut descriptor = null_mut();
        // SAFETY: handle is open; owner points into descriptor, a LocalAlloc block freed on drop.
        let status = unsafe {
            GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let _descriptor = SecurityDescriptor(descriptor);
        let me = TokenUserInfo::current()?;
        // SAFETY: owner points into _descriptor and the user SID into me; both are alive.
        Ok(!owner.is_null() && unsafe { EqualSid(owner, me.sid()) } != 0)
    }

    struct Handle(HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: the handle is owned by this value and closed once.
            unsafe { CloseHandle(self.0) };
        }
    }

    struct TokenUserInfo(Vec<u64>);

    impl TokenUserInfo {
        fn current() -> io::Result<Self> {
            let mut token = null_mut();
            // SAFETY: the current process pseudo handle needs no closing; token receives an owned
            // handle.
            if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let token = Handle(token);
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

        fn sid(&self) -> windows_sys::Win32::Security::PSID {
            // SAFETY: GetTokenInformation wrote a TOKEN_USER at the start of the aligned buffer.
            unsafe { (*self.0.as_ptr().cast::<TOKEN_USER>()).User.Sid }
        }
    }

    pub fn user_sid() -> io::Result<String> {
        let user = TokenUserInfo::current()?;
        let mut string = null_mut();
        // SAFETY: the SID points into user's buffer, which outlives this call.
        if unsafe { ConvertSidToStringSidW(user.sid(), &mut string) } == 0 {
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
        Request::Launch(LaunchRequest::new(profile, "session_credentials").unwrap())
    }

    #[test]
    fn the_agent_pid_is_read_from_its_line() {
        assert_eq!(agent_pid(&["agent-pid: 42".to_owned()]), Some(42));
        assert_eq!(
            agent_pid(&["other".to_owned(), agent_pid_line()]),
            Some(std::process::id())
        );
        for line in ["agent-pid: x", "agent-pid:42", "agent-pid: -1", ""] {
            assert_eq!(agent_pid(&[line.to_owned()]), None, "{line}");
        }
        assert_eq!(agent_pid(&[]), None);
    }

    #[test]
    fn gateway_only_launches_round_trip_without_a_profile_or_portal() {
        for line in [
            "launch session_credentials gateway=proxy.example:443",
            "launch session_credentials route=mixed gateway=[::1]:8443",
        ] {
            let request: Request = line.parse().unwrap();
            assert_eq!(request.to_string(), line);
            let Request::Launch(launch) = request else {
                panic!("not launch")
            };
            assert!(!launch.to_string().contains("profile="));
            assert!(!launch.to_string().contains("portal="));
        }
    }

    #[test]
    fn a_legacy_profile_named_session_credentials_remains_unambiguous() {
        let line = "launch session_credentials session_credentials";
        let request: Request = line.parse().unwrap();
        assert_eq!(request.to_string(), line);
        let Request::Launch(launch) = request else {
            panic!("not launch")
        };
        assert_eq!(launch.profile.unwrap().as_str(), "session_credentials");
        for line in [
            "launch session_credentials",
            "launch session_credentials gateway=proxy.example:443 gateway=other.example:443",
            "launch session_credentials gateway=proxy.example:443 profile=corp",
            "launch session_credentials auth=session_credentials gateway=proxy.example:443",
        ] {
            assert!(line.parse::<Request>().is_err());
        }
    }

    #[test]
    fn the_removed_basic_tofu_auth_fails_closed_naming_its_replacement() {
        for line in [
            "launch corp basic_tofu",
            "launch basic_tofu",
            "launch basic_tofu gateway=proxy.example:443",
            "launch corp basic_tofu url=https://p.example/",
        ] {
            let error = line.parse::<Request>().unwrap_err().to_string();
            assert!(error.contains("basic_tofu"), "{error}");
            assert!(error.contains("session_credentials"), "{error}");
        }
        let line = "launch basic_tofu session_credentials";
        let Request::Launch(launch) = line.parse().unwrap() else {
            panic!("not launch")
        };
        assert_eq!(launch.profile.unwrap().as_str(), "basic_tofu");
    }

    #[test]
    fn mixed_launch_route_round_trips_without_changing_legacy_requests() {
        let line = "launch corp session_credentials route=mixed";
        let parsed: Request = line.parse().unwrap();
        assert_eq!(parsed.to_string(), line);
        let Request::Launch(link) = parsed else {
            panic!("not a launch")
        };
        assert!(link.to_string().contains("&route=mixed"));
        assert_eq!(
            "launch corp session_credentials"
                .parse::<Request>()
                .unwrap()
                .to_string(),
            "launch corp session_credentials"
        );
        for invalid in [
            "launch corp session_credentials route=direct",
            "launch corp session_credentials route=mixed route=mixed",
            "launch corp session_credentials route=gateway",
        ] {
            assert!(invalid.parse::<Request>().is_err());
        }
    }

    #[test]
    fn requests_round_trip_as_single_lines() {
        for (request, line) in [
            (launch("office"), "launch office session_credentials"),
            (Request::List, "list"),
            (Request::Close(SessionId(12)), "close 12"),
            (Request::Credentials(SessionId(7)), "credentials 7"),
            (Request::Stop, "stop"),
        ] {
            assert_eq!(request.to_string(), line);
            assert_eq!(line.parse::<Request>(), Ok(request));
        }
    }

    fn linked_launch() -> Request {
        Request::Launch(
            LaunchRequest::new("corp", "session_credentials")
                .unwrap()
                .with_link(
                    Some("https://p.example/app?a=b&c=d"),
                    Some("Proxy.Example"),
                    Some("https://p.example/"),
                )
                .unwrap(),
        )
    }

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn launch_link_fields_and_answers_round_trip_as_single_lines() {
        let start = Request::Launch(
            LaunchRequest::new("corp", "session_credentials")
                .unwrap()
                .with_link(Some("https://p.example/"), None, None)
                .unwrap(),
        );
        for (request, line) in [
            (
                linked_launch(),
                "launch corp session_credentials url=https://p.example/app?a=b&c=d \
                 gateway=proxy.example:443 portal=https://p.example/",
            ),
            (
                start,
                "launch corp session_credentials url=https://p.example/",
            ),
            (
                Request::Approve(TOKEN.parse().unwrap()),
                "approve 0123456789abcdef0123456789abcdef",
            ),
            (
                Request::Deny(TOKEN.parse().unwrap()),
                "deny 0123456789abcdef0123456789abcdef",
            ),
        ] {
            assert_eq!(request.to_string(), line);
            assert_eq!(line.parse::<Request>(), Ok(request));
        }
    }

    #[test]
    fn malformed_launch_link_fields_are_rejected() {
        for line in [
            "launch corp session_credentials url=",
            "launch corp session_credentials url=http://p.example/",
            "launch corp session_credentials url=https://p.example/ x",
            "launch corp session_credentials url=https://p.example/  ",
            "launch corp session_credentials  url=https://p.example/",
            "launch corp session_credentials url=https://p.example/\r",
            "launch corp session_credentials url=https://p.example/ url=https://p.example/",
            "launch corp session_credentials URL=https://p.example/",
            "launch corp session_credentials ca_file=/tmp/ca.pem",
            "launch corp session_credentials url",
            "launch corp session_credentials gateway=user@proxy.example portal=https://p.example/",
            "launch corp session_credentials gateway=proxy.example portal=https://p.example/",
            "launch corp session_credentials portal=https://p.example/ gateway=proxy.example:443",
            "launch corp session_credentials gateway=proxy.example:443 portal=https://p.example/ \
             url=https://p.example/",
            "launch corp session_credentials url=https://evil.example/ gateway=proxy.example:443 \
             portal=https://p.example/",
            "launch corp session_credentials url=https://p.example/ gateway=proxy.example:443 \
             portal=https://p.example/ extra",
            "approve",
            "approve 0123456789ABCDEF0123456789ABCDEF",
            "approve 0123456789abcdef0123456789abcde",
            "approve 0123456789abcdef0123456789abcdef0",
            "approve 0123456789abcdef0123456789abcdeg",
            "approve 0123456789abcdef0123456789abcdef x",
            "deny",
            "deny x",
        ] {
            assert!(line.parse::<Request>().is_err(), "{line:?}");
        }
    }

    #[test]
    fn the_longest_launch_request_fits_the_request_limit() {
        let path = |len: usize| "a".repeat(len - "https://p.example/".len());
        let url = format!("https://p.example/{}", path(2048));
        let host = format!("{}example", format!("{}.", "a".repeat(63)).repeat(3));
        let request = Request::Launch(
            LaunchRequest::new(&"a".repeat(64), "session_credentials")
                .unwrap()
                .with_link(Some(&url), Some(&format!("{host}:65535")), Some(&url))
                .unwrap(),
        );
        let line = request.to_string();
        assert!(line.len() + 1 < MAX_REQUEST_BYTES, "{}", line.len());
        assert_eq!(line.parse::<Request>(), Ok(request));
    }

    #[test]
    fn confirmation_tokens_are_random_and_read_from_their_line() {
        let (a, b) = (
            ConfirmToken::random().unwrap(),
            ConfirmToken::random().unwrap(),
        );
        assert_ne!(a, b);
        assert_eq!(a.to_string().len(), 32);
        let lines = vec!["other".to_owned(), confirm_line(&a)];
        assert_eq!(confirm_token(&lines), Some(a));
        for line in ["confirm: x", "confirm:0123456789abcdef0123456789abcdef", ""] {
            assert_eq!(confirm_token(&[line.to_owned()]), None, "{line}");
        }
    }

    fn issued() -> SessionCredentials {
        SessionCredentials::generate(&aws_lc_rs::rand::SystemRandom::new()).unwrap()
    }

    #[test]
    fn issued_credentials_are_read_from_their_lines() {
        let credentials = issued();
        let mut lines = vec!["session: 1".to_owned()];
        lines.extend(credential_lines(&credentials));
        lines.push("listen: 127.0.0.1:1".to_owned());
        assert_eq!(issued_credentials(&lines), Some(credentials.clone()));
        let [username, password] = credential_lines(&credentials);
        assert_eq!(username, format!("username: {}", credentials.username()));
        assert_eq!(password, format!("password: {}", credentials.password()));
        for lines in [
            vec![username.clone()],
            vec![password.clone()],
            vec![username.to_uppercase(), password.clone()],
            vec![username.clone(), password.replace('-', "")],
            vec![format!("{username}x"), password.clone()],
            vec!["username: k7mp-2xqa".to_owned(), password.clone()],
            vec![username.clone(), format!("{password} ")],
            vec![password.replace("password", "username"), password.clone()],
            vec![],
        ] {
            assert_eq!(issued_credentials(&lines), None, "{lines:?}");
        }
    }

    #[test]
    fn credential_lines_are_stripped_from_what_is_shown() {
        let credentials = issued();
        let mut lines = vec!["session: 1".to_owned()];
        lines.extend(credential_lines(&credentials));
        lines.push("listen: 127.0.0.1:1".to_owned());
        lines.push("username: anything".to_owned());
        assert_eq!(
            without_credentials(lines),
            ["session: 1", "listen: 127.0.0.1:1"]
        );
    }

    #[test]
    fn malformed_requests_are_rejected() {
        let long = format!("launch {} session_credentials", "a".repeat(65));
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
            "launch office session_credentials extra",
            "launch  office session_credentials",
            "launch office none",
            "launch ../office session_credentials",
            "launch -office session_credentials",
            "launch --config session_credentials",
            "launch off\"ice session_credentials",
            "launch office%20x session_credentials",
            "launch caf\u{e9} session_credentials",
            long.as_str(),
            "close",
            "close x",
            "close -1",
            "close 1 2",
            "close 99999999999999999999999",
            "credentials",
            "credentials x",
            "credentials 1 2",
            "credentials  1",
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

    struct ClosedPipe(Option<&'static [u8]>);

    impl AsyncRead for ClosedPipe {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(match self.0.take() {
                Some(data) => {
                    buf.put_slice(data);
                    Ok(())
                }
                None => Err(io::ErrorKind::BrokenPipe.into()),
            })
        }
    }

    #[tokio::test]
    async fn a_pipe_closed_after_the_response_ends_it() {
        let mut pipe = ClosedPipe(Some(b"ok\nsession: 1\n"));
        assert_eq!(
            read_to_close(&mut pipe, MAX_RESPONSE_BYTES).await.unwrap(),
            b"ok\nsession: 1\n"
        );
    }

    #[tokio::test]
    async fn reading_stops_past_the_limit() {
        let mut long: &[u8] = &[b'a'; 10_000];
        let read = read_to_close(&mut long, 100).await.unwrap();
        assert!(
            read.len() > 100 && read.len() <= 100 + 4096,
            "{}",
            read.len()
        );
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
    fn the_pipe_is_owned_by_its_user_and_grants_access_only_to_it_and_system() {
        assert_eq!(
            owner_only_sddl("S-1-5-21-1-2-3-1001"),
            "O:S-1-5-21-1-2-3-1001D:P(A;;GA;;;S-1-5-21-1-2-3-1001)(A;;GA;;;SY)"
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn a_pipe_bound_by_the_agent_is_owned_by_the_current_user() {
        use std::os::windows::io::AsRawHandle;

        let endpoint = Endpoint::pipe(&format!("gateinto-owner-{}", std::process::id()));
        let _server = Server::bind(&endpoint).unwrap();
        let client = tokio::net::windows::named_pipe::ClientOptions::new()
            .open(endpoint.path())
            .unwrap();

        assert!(windows::owned_by_current_user(client.as_raw_handle()).unwrap());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn the_agent_pipe_accepts_again_after_a_client_leaves() {
        let endpoint = Endpoint::pipe(&format!("gateinto-reaccept-{}", std::process::id()));
        let mut server = Server::bind(&endpoint).unwrap();
        drop(
            tokio::net::windows::named_pipe::ClientOptions::new()
                .open(endpoint.path())
                .unwrap(),
        );
        let _ = server.accept().await;

        let accepted = tokio::spawn(async move { server.accept().await.map(drop) });
        let connected = tokio::time::timeout(REQUEST_TIMEOUT, connect(&endpoint)).await;

        assert!(matches!(connected, Ok(Ok(_))));
        assert!(accepted.await.unwrap().is_ok());
    }

    #[test]
    fn a_taken_pipe_name_is_a_running_agent_only_when_the_user_owns_the_pipe() {
        let endpoint = Endpoint(OsString::from(r"\\.\pipe\gateinto-agent-S-1-5-21-1"));
        let taken = |owner| taken_pipe(&endpoint, owner);

        assert!(matches!(taken(Ok(true)), BindError::AlreadyRunning(_)));
        assert!(matches!(taken(Ok(false)), BindError::HeldByAnotherUser(_)));
        assert!(matches!(
            taken(Err(io::ErrorKind::PermissionDenied.into())),
            BindError::HeldByAnotherUser(_)
        ));
        assert!(matches!(
            taken(Err(io::ErrorKind::NotFound.into())),
            BindError::Io(..)
        ));
        assert_eq!(
            taken(Ok(false)).to_string(),
            r"the agent endpoint \\.\pipe\gateinto-agent-S-1-5-21-1 is held by another user"
        );
    }

    struct FakePipes {
        names: std::vec::IntoIter<io::Result<&'static str>>,
        connects: Vec<io::Result<()>>,
        connected: Vec<&'static str>,
    }

    impl FakePipes {
        fn new(names: Vec<io::Result<&'static str>>, connects: Vec<io::Result<()>>) -> Self {
            Self {
                names: names.into_iter(),
                connects,
                connected: Vec::new(),
            }
        }

        async fn accept(
            &mut self,
            instances: &mut Instances<&'static str>,
        ) -> io::Result<&'static str> {
            let names = &mut self.names;
            instances.replace_spent(|| names.next().expect("an instance was created"))?;
            instances
                .connect(async |pipe: &&'static str| {
                    self.connected.push(*pipe);
                    self.connects.remove(0)
                })
                .await?;
            instances.hand_off(|| self.names.next().expect("an instance was created"))
        }
    }

    #[tokio::test]
    async fn a_connected_pipe_is_handed_off_only_once_its_successor_listens() {
        let mut pipes = FakePipes::new(vec![Ok("second")], vec![Ok(())]);
        let mut instances = Instances::new("first");

        assert_eq!(pipes.accept(&mut instances).await.unwrap(), "first");
        assert_eq!(pipes.connected, ["first"]);
        assert_eq!(instances.current, "second");
    }

    #[tokio::test]
    async fn a_connected_pipe_without_a_successor_waits_to_be_handed_off_later() {
        let mut pipes = FakePipes::new(
            vec![Err(io::Error::other("no instance")), Ok("second")],
            vec![Ok(())],
        );
        let mut instances = Instances::new("first");

        let failed = pipes.accept(&mut instances).await.unwrap_err();
        assert_eq!(failed.to_string(), "no instance");
        assert_eq!(instances.current, "first");

        assert_eq!(pipes.accept(&mut instances).await.unwrap(), "first");
        assert_eq!(pipes.connected, ["first"]);
        assert_eq!(instances.current, "second");
    }

    #[tokio::test]
    async fn a_pipe_that_failed_to_connect_is_replaced_before_listening_again() {
        let mut pipes = FakePipes::new(
            vec![Ok("second"), Ok("third")],
            vec![Err(io::Error::other("client left")), Ok(())],
        );
        let mut instances = Instances::new("first");

        let failed = pipes.accept(&mut instances).await.unwrap_err();
        assert_eq!(failed.to_string(), "client left");
        assert_eq!(instances.current, "first");

        assert_eq!(pipes.accept(&mut instances).await.unwrap(), "second");
        assert_eq!(pipes.connected, ["first", "second"]);
        assert_eq!(instances.current, "third");
    }

    #[tokio::test]
    async fn a_pipe_that_failed_to_connect_is_kept_until_it_can_be_replaced() {
        let mut pipes = FakePipes::new(
            vec![
                Err(io::Error::other("no instance")),
                Ok("second"),
                Ok("third"),
            ],
            vec![Err(io::Error::other("client left")), Ok(())],
        );
        let mut instances = Instances::new("first");

        pipes.accept(&mut instances).await.unwrap_err();
        let failed = pipes.accept(&mut instances).await.unwrap_err();
        assert_eq!(failed.to_string(), "no instance");
        assert_eq!(instances.current, "first");

        assert_eq!(pipes.accept(&mut instances).await.unwrap(), "second");
        assert_eq!(pipes.connected, ["first", "second"]);
    }

    #[test]
    fn a_busy_probe_is_retried_until_it_is_answered() {
        let busy = || io::Error::from(io::ErrorKind::WouldBlock);
        let mut answers = vec![Ok(true), Err(busy()), Err(busy())];
        let mut waits = Vec::new();
        let probed = retry_while_busy(
            Instant::now() + REQUEST_TIMEOUT,
            || answers.pop().unwrap(),
            |error| error.kind() == io::ErrorKind::WouldBlock,
            |delay| waits.push(delay),
        );

        assert!(probed.unwrap());
        assert_eq!(waits, [Duration::from_millis(20); 2]);
    }

    #[test]
    fn a_busy_probe_fails_once_its_deadline_has_passed() {
        let mut attempts = 0;
        let probed: io::Result<bool> = retry_while_busy(
            Instant::now(),
            || {
                attempts += 1;
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            },
            |error| error.kind() == io::ErrorKind::WouldBlock,
            |_| panic!("waited"),
        );

        assert_eq!(probed.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert_eq!(attempts, 1);
    }

    #[test]
    fn a_probe_that_fails_otherwise_is_not_retried() {
        let probed: io::Result<bool> = retry_while_busy(
            Instant::now() + REQUEST_TIMEOUT,
            || Err(io::Error::from(io::ErrorKind::PermissionDenied)),
            |error| error.kind() == io::ErrorKind::WouldBlock,
            |_| panic!("waited"),
        );

        assert_eq!(probed.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn a_busy_pipe_is_retried_only_until_the_deadline() {
        let start = std::time::Instant::now();
        let deadline = start + REQUEST_TIMEOUT;
        let delay = |now| busy_retry_delay(deadline, now);

        assert_eq!(delay(start), Some(Duration::from_millis(20)));
        assert_eq!(
            delay(deadline - Duration::from_millis(5)),
            Some(Duration::from_millis(5))
        );
        assert_eq!(delay(deadline), None);
        assert_eq!(delay(deadline + Duration::from_secs(1)), None);
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
