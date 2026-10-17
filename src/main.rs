use std::net::{Ipv4Addr, SocketAddr};
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};
use std::time::{Duration, Instant};

use clap::{Args, Parser, Subcommand, ValueEnum};
use gateinto::agent::{Agent, AgentLimits, AgentOptions, BrowserSessionPlan, Profiles};
use gateinto::browser;
use gateinto::check::{self, CheckOptions};
use gateinto::config::{self, ConfigFile, DeviceKeySettings, GatewayName, Overrides, Settings};
use gateinto::http::Authority;
use gateinto::identity::client_cert::{
    self, CertificateSource, ClientCertificate, ClientCertificateMode, ClientCertificateOptions,
    ClientIdentityStore,
};
use gateinto::identity::device_key::{self, Backend, InitOptions, KeyName, KeyStore, Provenance};
use gateinto::ipc::{self, Endpoint, Request, RequestError, Response, Server};
use gateinto::proxy::{Config, Limits, LocalAuth, Upstream};
use gateinto::registration;
use gateinto::sessions::{SessionConfig, SessionId, SessionKind, SessionManager};
use gateinto::tls::{self, TlsMode};
use gateinto::uri::LaunchRequest;
use rustls::pki_types::{ServerName, UnixTime};
use tracing_subscriber::EnvFilter;

type Result<T = (), E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the local CONNECT proxy
    Proxy(ProxyArgs),
    /// Connect to the upstream once and print the negotiated TLS parameters
    CheckUpstream(CheckUpstreamArgs),
    /// Manage the device key held by Windows CNG
    #[command(subcommand)]
    Key(KeyCommand),
    /// Run or manage sessions
    #[command(subcommand)]
    Session(SessionCommand),
    /// Run the agent: the device session named by [device_session] gateway, if any, and the
    /// per-user endpoint that starts browser sessions for `gateinto open`
    Agent(ConfigArg),
    /// Ask the agent to start a browser session for a gateinto:// launch URI, starting the agent
    /// first if none is running
    Open(OpenArgs),
    /// Stop the running agent after closing all of its sessions
    Stop,
    /// Register or remove the per-user gateinto:// URI handler (Windows, development use)
    #[command(subcommand)]
    Uri(UriCommand),
}

#[derive(Subcommand)]
enum SessionCommand {
    /// Start a browser session with basic_tofu proxy authentication on an ephemeral loopback port
    /// and run it until interrupted
    Browser(BrowserSessionArgs),
    /// List the sessions of the running agent
    List,
    /// Close a session of the running agent, stopping its browser and deleting its profile
    Close {
        /// Session id as shown by `gateinto session list`
        id: SessionId,
    },
}

#[derive(Args)]
struct OpenArgs {
    #[command(flatten)]
    config: ConfigArg,

    /// Launch URI such as gateinto://connect?profile=<gateway>; put -- before it
    uri: String,
}

#[derive(Subcommand)]
enum UriCommand {
    /// Write HKCU\Software\Classes\gateinto so that gateinto:// links run `gateinto open`
    Register(ConfigArg),
    /// Remove HKCU\Software\Classes\gateinto if it runs a Gateinto executable
    Unregister,
}

#[derive(Args)]
struct BrowserSessionArgs {
    #[command(flatten)]
    upstream: UpstreamArgs,

    /// Gateway from --config to relay through [default: the device session's gateway, or the only gateway]
    #[arg(long)]
    gateway: Option<GatewayName>,
}

#[derive(Subcommand)]
enum KeyCommand {
    /// Open the device key, creating it only if none exists
    Init(KeyInitArgs),
    /// Show the existing device key without creating one
    Info(KeyInfoArgs),
}

#[derive(Args)]
struct ConfigArg {
    /// TOML configuration file; command line flags override its values
    #[arg(long)]
    config: Option<PathBuf>,
}

impl ConfigArg {
    fn load(&self) -> Result<ConfigFile, config::ConfigError> {
        self.config
            .as_deref()
            .map_or_else(|| Ok(ConfigFile::default()), ConfigFile::load)
    }
}

#[derive(Args)]
struct KeyInitArgs {
    #[command(flatten)]
    config: ConfigArg,

    /// Name of the persisted CNG key [default: gateinto-device-v1]
    #[arg(long)]
    name: Option<KeyName>,

    /// Backend for a new key; an existing key is reused wherever it is [default: tpm]
    #[arg(long, value_enum)]
    backend: Option<BackendArg>,

    /// Create a software key when the TPM cannot be used, even if the config file disables it
    #[arg(long, conflicts_with = "no_software_fallback")]
    software_fallback: bool,

    /// Fail instead of creating a software key when the TPM cannot be used
    #[arg(long)]
    no_software_fallback: bool,
}

impl KeyInitArgs {
    fn settings(&self) -> Result<DeviceKeySettings> {
        let mut settings = device_key_settings(&self.config, self.name.clone())?;
        if let Some(backend) = self.backend {
            settings.preferred = backend.into();
        }
        if self.software_fallback {
            settings.software_fallback_on_first_create = true;
        }
        if self.no_software_fallback {
            settings.software_fallback_on_first_create = false;
        }
        Ok(settings)
    }
}

#[derive(Args)]
struct KeyInfoArgs {
    #[command(flatten)]
    config: ConfigArg,

    /// Name of the persisted CNG key [default: gateinto-device-v1]
    #[arg(long)]
    name: Option<KeyName>,

    /// Write the DER SubjectPublicKeyInfo of the public key to this file
    #[arg(long)]
    spki_out: Option<PathBuf>,

    /// Check this PEM client certificate against the key instead of searching CurrentUser\My
    #[arg(long)]
    client_cert_file: Option<PathBuf>,
}

#[derive(Clone, Copy, ValueEnum)]
enum BackendArg {
    Tpm,
    Software,
}

#[derive(Clone, Copy, ValueEnum)]
enum ClientCertificateArg {
    Optional,
    Required,
    Off,
}

impl From<ClientCertificateArg> for ClientCertificateMode {
    fn from(mode: ClientCertificateArg) -> Self {
        match mode {
            ClientCertificateArg::Optional => Self::Optional,
            ClientCertificateArg::Required => Self::Required,
            ClientCertificateArg::Off => Self::Off,
        }
    }
}

impl From<BackendArg> for Backend {
    fn from(backend: BackendArg) -> Self {
        match backend {
            BackendArg::Tpm => Self::Tpm,
            BackendArg::Software => Self::Software,
        }
    }
}

#[derive(Args)]
struct ProxyArgs {
    /// Local address to listen on [default: 127.0.0.1:18736]
    #[arg(long)]
    listen: Option<SocketAddr>,

    /// Allow listening on a non-loopback address, exposing the proxy to the network
    #[arg(long)]
    unsafe_allow_non_loopback_listen: bool,

    #[command(flatten)]
    upstream: UpstreamArgs,

    /// Maximum number of concurrent connections [default: 64]
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    max_tunnels: Option<u32>,

    /// Maximum size of a CONNECT request or response header block [default: 16384]
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    max_header_bytes: Option<u32>,

    /// Timeout for reading the request and opening the upstream tunnel [default: 10]
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    connect_timeout_secs: Option<u64>,

    /// Close a tunnel after this many seconds without traffic [default: 300]
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    idle_timeout_secs: Option<u64>,
}

#[derive(Args)]
struct CheckUpstreamArgs {
    #[command(flatten)]
    upstream: UpstreamArgs,

    /// Gateway from --config to check [default: the device session's gateway, or the only gateway]
    #[arg(long)]
    gateway: Option<GatewayName>,

    /// Also send CONNECT for this host:port and print the upstream status line
    #[arg(long)]
    target: Option<Authority>,
}

#[derive(Args)]
struct UpstreamArgs {
    #[command(flatten)]
    config: ConfigArg,

    /// Upstream HTTPS proxy host name or IP address [required here or in --config]
    #[arg(long)]
    upstream_host: Option<String>,

    /// Upstream HTTPS proxy port [required here or in --config]
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    upstream_port: Option<u16>,

    /// Name to verify in the upstream certificate [default: the upstream host]
    #[arg(long)]
    upstream_server_name: Option<String>,

    /// PEM file with the CA certificates trusted for the upstream [default: Mozilla roots]
    #[arg(long)]
    ca_file: Option<PathBuf>,

    /// Key exchange policy for the upstream TLS connection [default: hybrid_preferred]
    #[arg(long, value_parser = tls_mode_parser())]
    tls_mode: Option<TlsMode>,

    /// Authenticate to the upstream with a client certificate bound to the device key [default: optional]
    #[arg(long, value_enum)]
    client_certificate: Option<ClientCertificateArg>,

    /// PEM file with the client certificate and optional intermediates [default: search CurrentUser\My]
    #[arg(long)]
    client_cert_file: Option<PathBuf>,

    /// Issue a short-lived self-signed client certificate with the device key at startup
    #[arg(long, conflicts_with = "client_cert_file")]
    self_signed_client_cert: bool,

    /// Name of the persisted CNG device key that signs for the client certificate [default: gateinto-device-v1]
    #[arg(long)]
    key_name: Option<KeyName>,
}

impl UpstreamArgs {
    fn overrides(&self) -> Overrides {
        let mut overrides = Overrides::default();
        let gateway = &mut overrides.gateway_settings;
        gateway.host = self.upstream_host.clone();
        gateway.port = self.upstream_port.and_then(NonZeroU16::new);
        gateway.server_name = self.upstream_server_name.clone();
        gateway.ca_file = self.ca_file.clone();
        gateway.tls_mode = self.tls_mode;
        gateway.client_certificate = self.client_certificate.map(Into::into);
        gateway.client_cert_file = self.client_cert_file.clone();
        gateway.self_signed_client_cert = self.self_signed_client_cert.then_some(true);
        overrides.device_key.name = self.key_name.clone();
        overrides
    }

    fn settings(&self, extra: impl FnOnce(&mut Overrides)) -> Result<Settings> {
        let mut overrides = self.overrides();
        extra(&mut overrides);
        Ok(self.config.load()?.settings(&overrides)?)
    }
}

fn tls_mode_parser() -> impl clap::builder::TypedValueParser<Value = TlsMode> {
    use clap::builder::TypedValueParser;
    clap::builder::PossibleValuesParser::new(TlsMode::NAMES)
        .map(|name| name.parse().expect("possible values are valid TLS modes"))
}

#[tokio::main]
async fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Proxy(args) => proxy(args).await,
        Command::CheckUpstream(args) => check_upstream(args).await,
        Command::Key(command) => key(command),
        Command::Session(SessionCommand::Browser(args)) => browser_session(args).await,
        Command::Session(SessionCommand::List) => agent_request(Request::List).await,
        Command::Session(SessionCommand::Close { id }) => agent_request(Request::Close(id)).await,
        Command::Agent(args) => agent(args).await,
        Command::Open(args) => open(args).await,
        Command::Stop => agent_request(Request::Stop).await,
        Command::Uri(command) => uri(command),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn device_key_settings(config: &ConfigArg, name: Option<KeyName>) -> Result<DeviceKeySettings> {
    let mut file = config.load()?;
    file.device_key.name = name.or(file.device_key.name);
    Ok(file.device_key_settings())
}

fn key(command: KeyCommand) -> Result {
    match command {
        KeyCommand::Init(args) => {
            let settings = args.settings()?;
            key_init(&gateinto::identity::system_store()?, settings)
        }
        KeyCommand::Info(args) => {
            let settings = device_key_settings(&args.config, args.name.clone())?;
            key_info(&gateinto::identity::system_store()?, &settings.name, args)
        }
    }
}

fn key_init<S: KeyStore>(store: &S, settings: DeviceKeySettings) -> Result {
    let options = InitOptions {
        backend: settings.preferred,
        allow_software_fallback: settings.software_fallback_on_first_create,
    };
    let name = &settings.name;
    let (key, provenance) = device_key::init(store, name, options)?;
    match provenance {
        Provenance::Reused => println!("using existing device key \"{name}\""),
        Provenance::Created => println!("created device key \"{name}\""),
        Provenance::CreatedAfterFallback(problem) => {
            eprintln!("warning: {problem}");
            println!("created software device key \"{name}\" because the TPM could not be used");
        }
    }
    print!("{}", key.summary());
    Ok(())
}

fn key_info<S: ClientIdentityStore>(store: &S, name: &KeyName, args: KeyInfoArgs) -> Result {
    let (key, duplicate) = device_key::info(store, name)?;
    if let Some(duplicate) = duplicate {
        eprintln!("{}", duplicate.info_warning());
    }
    print!("{}", key.summary());
    if let Some(path) = args.spki_out {
        std::fs::write(&path, key.spki_der())
            .map_err(|error| format!("writing {}: {error}", path.display()))?;
    }
    print!(
        "{}",
        client_cert::describe_binding(
            store,
            &key.spki_der(),
            args.client_cert_file.as_deref(),
            UnixTime::now()
        )?
    );
    Ok(())
}

fn init_logging(default_filter: &str) {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter)),
        )
        .with_writer(std::io::stderr)
        // Otherwise a closed stderr makes tracing-subscriber panic inside connection tasks.
        .log_internal_errors(false)
        .init();
}

fn upstream(settings: &Settings) -> Result<Upstream> {
    let upstream = &settings.gateway.upstream;
    let server_name = ServerName::try_from(upstream.server_name.clone())
        .map_err(|error| format!("invalid upstream server name: {error}"))?;
    let roots = match &upstream.ca_file {
        Some(path) => tls::load_pem_roots(path)?,
        None => tls::webpki_roots(),
    };
    Ok(Upstream {
        host: upstream.host.clone(),
        port: upstream.port,
        server_name,
        roots,
    })
}

fn client_certificate(settings: &Settings) -> Result<Option<ClientCertificate>> {
    let gateway = &settings.gateway;
    let options = ClientCertificateOptions {
        mode: gateway.client_certificate,
        key_name: settings.device_key.name.clone(),
        source: match &gateway.client_cert_file {
            _ if gateway.self_signed_client_cert => CertificateSource::SelfSigned,
            Some(path) => CertificateSource::File(path.clone()),
            None => CertificateSource::Store,
        },
    };
    let store = gateinto::identity::system_store();
    let client_auth =
        client_cert::configure(&options, store.as_ref().map_err(|&e| e), UnixTime::now())?;
    Ok(client_auth.into_client_certificate())
}

async fn check_upstream(args: CheckUpstreamArgs) -> Result {
    let settings = args.upstream.settings(|overrides| {
        overrides.gateway = args.gateway.clone();
    })?;
    init_logging("warn");
    let options = CheckOptions {
        upstream: upstream(&settings)?,
        tls_mode: settings.gateway.tls_mode,
        client_certificate: client_certificate(&settings)?,
        target: args.target,
        timeout: Duration::from_secs(settings.limits.connect_timeout_seconds),
        max_header_bytes: settings.limits.header_max_bytes as usize,
    };
    let report = check::check_upstream(options).await?;
    print!("{report}");
    match report.connect_refused() {
        Some(status) => Err(format!("upstream refused CONNECT with status {status}").into()),
        None => Ok(()),
    }
}

async fn proxy(args: ProxyArgs) -> Result {
    let shutdown = shutdown_signal();
    let settings = args.upstream.settings(|overrides| {
        overrides.listen = args.listen;
        let limits = &mut overrides.limits;
        limits.max_concurrent_tunnels = args.max_tunnels.and_then(NonZeroU32::new);
        limits.header_max_bytes = args.max_header_bytes.and_then(NonZeroU32::new);
        limits.connect_timeout_seconds = args.connect_timeout_secs.and_then(NonZeroU64::new);
        limits.idle_timeout_seconds = args.idle_timeout_secs.and_then(NonZeroU64::new);
    })?;
    init_logging("info");
    let config = Config {
        listen: settings.listen,
        allow_non_loopback: args.unsafe_allow_non_loopback_listen,
        local_auth: settings.device_session_auth,
        ..proxy_config(&settings)?
    };
    let mut sessions = SessionManager::new();
    sessions
        .start(SessionConfig {
            kind: SessionKind::Device,
            gateway: settings.gateway.name,
            proxy: config,
        })
        .await?;
    shutdown.await;
    sessions.close_all().await;
    Ok(())
}

fn proxy_config(settings: &Settings) -> Result<Config> {
    let limits = &settings.limits;
    Ok(Config {
        listen: settings.listen,
        allow_non_loopback: false,
        local_auth: LocalAuth::None,
        upstream: upstream(settings)?,
        tls_mode: settings.gateway.tls_mode,
        client_certificate: client_certificate(settings)?,
        limits: Limits {
            max_header_bytes: limits.header_max_bytes as usize,
            max_tunnels: limits.max_concurrent_tunnels as usize,
            handshake_timeout: Duration::from_secs(limits.connect_timeout_seconds),
            idle_timeout: Duration::from_secs(limits.idle_timeout_seconds),
            ..Limits::default()
        },
    })
}

async fn browser_session(args: BrowserSessionArgs) -> Result {
    let shutdown = shutdown_signal();
    let settings = args.upstream.settings(|overrides| {
        overrides.gateway = args.gateway.clone();
    })?;
    init_logging("warn");
    let config = Config {
        listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        local_auth: LocalAuth::BasicTofu,
        ..proxy_config(&settings)?
    };
    let mut sessions = SessionManager::new();
    let id = sessions
        .start(SessionConfig {
            kind: SessionKind::Browser,
            gateway: settings.gateway.name,
            proxy: config,
        })
        .await?;
    let session = sessions.session(id).expect("the session just started");
    println!("session: {id}");
    println!("kind: {}", session.kind());
    println!("gateway: {}", session.gateway());
    println!("listen: {}", session.local_addr());
    println!("realm: {}", session.realm().unwrap_or_default());
    println!("Press Ctrl-C to close the session.");
    shutdown.await;
    sessions.close_all().await;
    Ok(())
}

fn shutdown_signal() -> impl std::future::Future<Output = ()> {
    #[cfg(unix)]
    let (mut interrupt, mut terminate) = {
        use tokio::signal::unix::{SignalKind, signal};
        (
            signal(SignalKind::interrupt()).ok(),
            signal(SignalKind::terminate()).ok(),
        )
    };
    #[cfg(windows)]
    let (mut ctrl_c, mut ctrl_break, mut ctrl_close, mut ctrl_shutdown, mut ctrl_logoff) = {
        use tokio::signal::windows;
        (
            windows::ctrl_c().ok(),
            windows::ctrl_break().ok(),
            windows::ctrl_close().ok(),
            windows::ctrl_shutdown().ok(),
            windows::ctrl_logoff().ok(),
        )
    };
    async move {
        #[cfg(unix)]
        tokio::select! {
            Some(()) = async { interrupt.as_mut()?.recv().await } => {}
            Some(()) = async { terminate.as_mut()?.recv().await } => {}
            else => std::future::pending().await,
        }
        #[cfg(windows)]
        tokio::select! {
            Some(()) = async { ctrl_c.as_mut()?.recv().await } => {}
            Some(()) = async { ctrl_break.as_mut()?.recv().await } => {}
            Some(()) = async { ctrl_close.as_mut()?.recv().await } => {}
            Some(()) = async { ctrl_shutdown.as_mut()?.recv().await } => {}
            Some(()) = async { ctrl_logoff.as_mut()?.recv().await } => {}
            else => std::future::pending().await,
        }
    }
}

struct ConfigProfiles(ConfigFile);

impl Profiles for ConfigProfiles {
    fn browser_session(&self, gateway: &GatewayName) -> Result<BrowserSessionPlan, String> {
        self.0.gateway(gateway).map_err(|error| error.to_string())?;
        let overrides = Overrides {
            gateway: Some(gateway.clone()),
            ..Overrides::default()
        };
        let settings = self
            .0
            .settings(&overrides)
            .map_err(|error| error.to_string())?;
        Ok(BrowserSessionPlan {
            proxy: proxy_config(&settings).map_err(|error| error.to_string())?,
            portal_url: settings.gateway.portal_url,
        })
    }
}

async fn agent(args: ConfigArg) -> Result {
    let shutdown = shutdown_signal();
    let file = args.load()?;
    init_logging("info");
    let endpoint = Endpoint::for_current_user()?;
    let server = Server::bind(&endpoint)?;
    let profiles_root = browser::profiles_root()
        .ok_or("cannot find the per-user application data directory for browser profiles")?;
    let options = AgentOptions {
        browser: file.browser.executable.clone(),
        profiles_root,
        limits: AgentLimits::default(),
    };
    let device_session = file.device_session.gateway.is_some();
    let agent = Agent::new(options, ConfigProfiles(file.clone()));
    if device_session {
        let settings = file.settings(&Overrides::default())?;
        let config = Config {
            listen: settings.listen,
            local_auth: settings.device_session_auth,
            ..proxy_config(&settings)?
        };
        agent
            .start_session(SessionConfig {
                kind: SessionKind::Device,
                gateway: settings.gateway.name,
                proxy: config,
            })
            .await?;
    }
    tracing::info!(%endpoint, "agent ready");
    agent.serve(server, shutdown).await;
    Ok(())
}

const AGENT_START_TIMEOUT: Duration = Duration::from_secs(30);

async fn open(args: OpenArgs) -> Result {
    let request = Request::Launch(args.uri.parse::<LaunchRequest>()?);
    let endpoint = Endpoint::for_current_user()?;
    let response = match ipc::send(&endpoint, &request).await {
        Err(RequestError::NotRunning) => {
            let mut child = spawn_agent(args.config.config.as_deref())?;
            wait_for_agent(&endpoint, &request, &mut child).await?
        }
        result => result?,
    };
    print_response(response)
}

fn spawn_agent(config: Option<&Path>) -> Result<std::process::Child> {
    let mut command = std::process::Command::new(std::env::current_exe()?);
    command.arg("agent");
    if let Some(config) = config {
        command.arg("--config").arg(config);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS};
        std::os::windows::process::CommandExt::creation_flags(
            &mut command,
            DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
        );
        stop_inheriting_standard_handles();
    }
    Ok(command.spawn()?)
}

#[cfg(windows)]
fn stop_inheriting_standard_handles() {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};

    for handle in [
        std::io::stdin().as_raw_handle(),
        std::io::stdout().as_raw_handle(),
        std::io::stderr().as_raw_handle(),
    ] {
        // SAFETY: the standard handles stay open for the life of the process; a null or
        // invalid handle only makes the call fail.
        unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) };
    }
}

async fn wait_for_agent(
    endpoint: &Endpoint,
    request: &Request,
    child: &mut std::process::Child,
) -> Result<Response> {
    let deadline = Instant::now() + AGENT_START_TIMEOUT;
    let mut delay = Duration::from_millis(25);
    loop {
        tokio::time::sleep(delay).await;
        let exited = child.try_wait()?;
        match ipc::send(endpoint, request).await {
            Err(RequestError::NotRunning) => {}
            result => return Ok(result?),
        }
        if let Some(status) = exited {
            return Err(format!(
                "the agent exited ({status}) before accepting requests; run `gateinto agent` \
                 to see why"
            )
            .into());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "the agent did not accept requests within {} seconds",
                AGENT_START_TIMEOUT.as_secs()
            )
            .into());
        }
        delay = (delay * 2).min(Duration::from_secs(1));
    }
}

fn print_response(response: Response) -> Result {
    match response {
        Response::Ok(lines) => {
            for line in lines {
                println!("{line}");
            }
            Ok(())
        }
        Response::Error(message) => Err(message.into()),
    }
}

async fn agent_request(request: Request) -> Result {
    let endpoint = Endpoint::for_current_user()?;
    print_response(ipc::send(&endpoint, &request).await?)
}

fn uri(command: UriCommand) -> Result {
    match command {
        UriCommand::Register(args) => {
            let config = args
                .config
                .as_deref()
                .map(std::path::absolute)
                .transpose()?;
            if let Some(config) = &config {
                ConfigFile::load(config)?;
            }
            let command =
                registration::handler_command(&std::env::current_exe()?, config.as_deref())?;
            registration::register(registration::SCHEME, &command)?;
            println!("registered gateinto:// for the current user: {command}");
        }
        UriCommand::Unregister => {
            if registration::unregister(registration::SCHEME)? {
                println!("removed the gateinto:// handler of the current user");
            } else {
                println!("no gateinto:// handler is registered for the current user");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_init_temp_path() -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!("gateinto-key-init-{}-{n}.toml", std::process::id()))
    }

    fn key_init_settings(file: Option<&str>, flags: &[&str]) -> Result<DeviceKeySettings> {
        key_init_settings_at(&key_init_temp_path(), file, flags)
    }

    fn key_init_settings_at(
        path: &std::path::Path,
        file: Option<&str>,
        flags: &[&str],
    ) -> Result<DeviceKeySettings> {
        let mut args = vec!["gateinto", "key", "init"];
        let path_arg = path.display().to_string();
        if let Some(text) = file {
            std::fs::write(path, text).unwrap();
            args.extend(["--config", &path_arg]);
        }
        args.extend(flags);
        let settings = Cli::try_parse_from(args)
            .map_err(Into::into)
            .and_then(|cli| match cli.command {
                Command::Key(KeyCommand::Init(args)) => args.settings(),
                _ => unreachable!(),
            });
        let _ = std::fs::remove_file(path);
        settings
    }

    #[test]
    fn key_init_settings_removes_the_config_file_when_parsing_fails() {
        let path = key_init_temp_path();
        let result = key_init_settings_at(
            &path,
            Some(FALLBACK_ON),
            &["--software-fallback", "--no-software-fallback"],
        );
        assert!(result.is_err());
        assert!(!path.exists());
    }

    const FALLBACK_ON: &str = "[device_key]\nsoftware_fallback_on_first_create = true\n";
    const FALLBACK_OFF: &str = "[device_key]\nsoftware_fallback_on_first_create = false\n";

    #[test]
    fn software_fallback_defaults_to_allowed() {
        assert!(
            key_init_settings(None, &[])
                .unwrap()
                .software_fallback_on_first_create
        );
    }

    #[test]
    fn software_fallback_comes_from_the_config_file() {
        for (file, expected) in [(FALLBACK_ON, true), (FALLBACK_OFF, false)] {
            let settings = key_init_settings(Some(file), &[]).unwrap();
            assert_eq!(settings.software_fallback_on_first_create, expected);
        }
    }

    #[test]
    fn software_fallback_flags_override_the_config_file() {
        let disabled = key_init_settings(Some(FALLBACK_ON), &["--no-software-fallback"]).unwrap();
        assert!(!disabled.software_fallback_on_first_create);
        let enabled = key_init_settings(Some(FALLBACK_OFF), &["--software-fallback"]).unwrap();
        assert!(enabled.software_fallback_on_first_create);
    }

    #[test]
    fn software_fallback_flags_are_mutually_exclusive() {
        let error = key_init_settings(None, &["--software-fallback", "--no-software-fallback"])
            .unwrap_err()
            .to_string();
        assert!(error.contains("cannot be used with"), "{error}");
    }
}
