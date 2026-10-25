use std::io::Write;
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
use gateinto::identity::device_key::{
    self, Backend, InitOptions, KeyError, KeyName, KeyStore, Provenance, SpkiConfirmation,
};
use gateinto::ipc::{self, Endpoint, Request, RequestError, Response, Server};
use gateinto::lifecycle::{self, Purge};
use gateinto::link::store::{self, LinkedStore, Loaded, StoreError};
use gateinto::link::{self, Confirmation, Known, KnownGateway, LinkedGateway, Source};
use gateinto::prompt;
use gateinto::proxy::{Config, Limits, LocalAuth, SessionCredentials, Upstream};
use gateinto::registration;
use gateinto::sessions::{SessionConfig, SessionId, SessionKind, SessionManager};
use gateinto::tls::{self, TlsMode};
use gateinto::uri::LaunchRequest;
use rustls::pki_types::{ServerName, UnixTime};
use tracing_subscriber::EnvFilter;

type Result<T = (), E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

const VERSION: &str = match option_env!("GATEINTO_BUILD_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

#[derive(Parser)]
#[command(version = VERSION, about)]
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
    Agent(AgentArgs),
    /// Ask the agent to start a browser session for a gateinto:// launch URI, starting the agent
    /// first if none is running
    Open(OpenArgs),
    /// Stop the running agent after closing all of its sessions
    Stop(StopArgs),
    /// List the gateways, or remove one that was added from a gateinto:// link
    #[command(subcommand)]
    Gateway(GatewayCommand),
    /// Register or remove the per-user gateinto:// URI handler (Windows, development use)
    #[command(subcommand)]
    Uri(UriCommand),
    /// Prepare Gateinto for the current Windows user: check the config, create or reuse the
    /// device key and report the gateinto:// handler
    Setup(KeyInitArgs),
    /// Show the device key, gateways, agent sessions and gateinto:// handler without changing
    /// anything
    Status(StatusArgs),
    /// Permanently delete Gateinto data that an uninstall keeps
    Reset(ResetArgs),
}

#[derive(Args)]
struct AgentArgs {
    #[command(flatten)]
    config: ConfigArg,

    /// Start the agent as a background process without a console, wait until it accepts
    /// requests and return (used by the logon autostart entry)
    #[arg(long)]
    detach: bool,
}

#[derive(Args)]
struct StopArgs {
    /// Succeed when no agent is running, then delete the Gateinto browser profiles left behind
    /// (run by the uninstaller)
    #[arg(long)]
    remove_stale_profiles: bool,
}

#[derive(Args)]
struct StatusArgs {
    #[command(flatten)]
    config: ConfigArg,

    /// Name of the persisted CNG key [default: gateinto-device-v1]
    #[arg(long)]
    name: Option<KeyName>,
}

#[derive(Args)]
struct ResetArgs {
    #[command(flatten)]
    config: ConfigArg,

    /// Name of the persisted CNG key [default: gateinto-device-v1]
    #[arg(long)]
    name: Option<KeyName>,

    /// Delete the device key; the device identity becomes invalid and is not revoked remotely
    #[arg(long, required = true)]
    purge_device_identity: bool,

    /// Also delete the config file named with --config, or else the default
    /// %APPDATA%\Gateinto\gateinto.toml, and the gateways added from gateinto:// links
    /// (the *.toml files in %APPDATA%\Gateinto\gateways)
    #[arg(long)]
    purge_config: bool,

    /// Confirm deleting the config file without a prompt when no device key exists; an
    /// existing key always needs its SPKI confirmed
    #[arg(long, requires = "purge_config")]
    yes: bool,

    /// Confirm without a prompt: the first 16 or more hex digits of the key's spki-sha256
    #[arg(long, value_name = "HEX")]
    confirm_spki: Option<SpkiConfirmation>,
}

#[derive(Subcommand)]
enum SessionCommand {
    /// Start a browser session with session credentials on an ephemeral loopback port, show the
    /// credentials, and run it until interrupted
    Browser(BrowserSessionArgs),
    /// List the sessions of the running agent
    List,
    /// Show the proxy credentials of a session of the running agent again, in a dialog on an
    /// interactive Windows desktop or otherwise on the terminal; never on standard output
    Credentials {
        /// Session id as shown by `gateinto session list`
        id: SessionId,
    },
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
enum GatewayCommand {
    /// Show each gateway with its upstream, portal origin and source: the config file, or a
    /// gateinto:// link you approved
    List(ConfigArg),
    /// Remove a gateway that was added from a gateinto:// link; gateways of the config file are
    /// edited there
    Forget {
        #[command(flatten)]
        config: ConfigArg,

        /// Gateway name as shown by `gateinto gateway list`
        name: GatewayName,
    },
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
    /// TOML configuration file; command line flags override its values [default:
    /// %APPDATA%\Gateinto\gateinto.toml on Windows, $XDG_CONFIG_HOME/gateinto/gateinto.toml
    /// elsewhere, when that file exists]
    #[arg(long)]
    config: Option<PathBuf>,
}

impl ConfigArg {
    fn path(&self) -> Option<(PathBuf, bool)> {
        match &self.config {
            Some(path) => Some((path.clone(), false)),
            None => config::default_path()
                .filter(|path| path.is_file())
                .map(|path| (path, true)),
        }
    }

    fn log_default(&self) {
        if let Some((path, true)) = self.path() {
            tracing::info!(path = %path.display(), "using the default config file");
        }
    }

    fn load(&self) -> Result<ConfigFile, config::ConfigError> {
        self.path().map_or_else(
            || Ok(ConfigFile::default()),
            |(path, _)| ConfigFile::load(&path),
        )
    }
}

fn default_config_display() -> String {
    config::default_path().map_or_else(
        || "no default location".to_owned(),
        |path| path.display().to_string(),
    )
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

fn main() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = writeln!(
                std::io::stderr(),
                "error: starting the runtime failed: {error}"
            );
            return ExitCode::FAILURE;
        }
    };
    let code = runtime.block_on(run());
    // A prompt still open on a blocking thread waits for the user; exiting must not.
    runtime.shutdown_background();
    code
}

async fn run() -> ExitCode {
    let arguments: Vec<_> = std::env::args_os().collect();
    let cli = match Cli::try_parse_from(&arguments) {
        Ok(cli) => cli,
        Err(error) => {
            let _ = error.print();
            if error.use_stderr() && arguments.get(1).is_some_and(|arg| arg == "open") {
                prompt::show_launch_error(&error.to_string());
            }
            return ExitCode::from(error.exit_code() as u8);
        }
    };
    let opening = matches!(&cli.command, Command::Open(_));
    let result = match cli.command {
        Command::Proxy(args) => proxy(args).await,
        Command::CheckUpstream(args) => check_upstream(args).await,
        Command::Key(command) => key(command),
        Command::Session(SessionCommand::Browser(args)) => browser_session(args).await,
        Command::Session(SessionCommand::List) => agent_request(Request::List).await,
        Command::Session(SessionCommand::Credentials { id }) => session_credentials(id).await,
        Command::Session(SessionCommand::Close { id }) => agent_request(Request::Close(id)).await,
        Command::Agent(args) if args.detach => agent_detach(args.config.config.as_deref()).await,
        Command::Agent(args) => agent(args.config).await,
        Command::Open(args) => open(args).await,
        Command::Stop(args) => stop(args).await,
        Command::Gateway(command) => gateway(command),
        Command::Uri(command) => uri(command),
        Command::Setup(args) => setup(args),
        Command::Status(args) => status(args).await,
        Command::Reset(args) => reset(args).await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let message = format!("error: {error}");
            let _ = writeln!(std::io::stderr(), "{message}");
            if opening {
                prompt::show_launch_error(&message);
            }
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
            if let Some(note) = lifecycle::check_current_account()? {
                eprintln!("{note}");
            }
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
    args.upstream.config.log_default();
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
    args.upstream.config.log_default();
    let config = Config {
        listen: settings.listen,
        allow_non_loopback: args.unsafe_allow_non_loopback_listen,
        local_auth: settings.device_session_auth,
        ..proxy_config(&settings)?
    };
    let mut sessions = SessionManager::new();
    let id = sessions
        .start(SessionConfig {
            kind: SessionKind::Device,
            gateway: settings.gateway.name,
            proxy: config,
        })
        .await?;
    let session = sessions.session(id).expect("the session just started");
    let shown = serve_showing(
        session.local_addr(),
        session.credentials().cloned(),
        shutdown,
    );
    let result = shown.await;
    sessions.close_all().await;
    result
}

async fn serve_showing(
    listen: SocketAddr,
    credentials: Option<SessionCredentials>,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result {
    let Some(credentials) = credentials else {
        shutdown.await;
        return Ok(());
    };
    tokio::pin!(shutdown);
    tokio::select! {
        shown = show_credentials(None, listen, credentials) => shown?,
        () = &mut shutdown => return Ok(()),
    }
    shutdown.await;
    Ok(())
}

fn proxy_config(settings: &Settings) -> Result<Config> {
    let limits = &settings.limits;
    Ok(Config {
        listen: settings.listen,
        allow_non_loopback: false,
        local_auth: LocalAuth::NONE,
        route: gateinto::proxy::Route::Gateway,
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
        os_user_job: None,
    })
}

async fn browser_session(args: BrowserSessionArgs) -> Result {
    let shutdown = shutdown_signal();
    let settings = args.upstream.settings(|overrides| {
        overrides.gateway = args.gateway.clone();
    })?;
    init_logging("warn");
    args.upstream.config.log_default();
    let config = Config {
        listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        local_auth: LocalAuth::SESSION_CREDENTIALS,
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
    let shown = serve_showing(
        session.local_addr(),
        session.credentials().cloned(),
        shutdown,
    );
    let result = shown.await;
    sessions.close_all().await;
    result
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

struct ConfigProfiles {
    file: ConfigFile,
    linked: Option<LinkedStore>,
}

fn load_linked(store: Option<&LinkedStore>) -> Result<Loaded, StoreError> {
    store.map_or(Ok(Loaded::default()), LinkedStore::load)
}

impl ConfigProfiles {
    fn linked(&self) -> Result<Vec<LinkedGateway>, String> {
        load_linked(self.linked.as_ref())
            .map(|loaded| loaded.gateways)
            .map_err(|error| error.to_string())
    }
}

#[cfg(feature = "test-hooks")]
fn linked_test_ca() -> Option<PathBuf> {
    std::env::var_os("GATEINTO_TEST_LINKED_CA_FILE").map(PathBuf::from)
}

#[cfg(not(feature = "test-hooks"))]
fn linked_test_ca() -> Option<PathBuf> {
    None
}

impl Profiles for ConfigProfiles {
    fn known(&self) -> Result<Known, String> {
        Ok(Known::new(&self.file, load_linked(self.linked.as_ref())))
    }

    fn link(&self, gateway: &LinkedGateway) -> Result<(), String> {
        self.linked
            .as_ref()
            .ok_or("cannot find the per-user config directory to store the gateway in")?
            .add(gateway)
            .map(drop)
            .map_err(|error| error.to_string())
    }

    fn browser_session(&self, gateway: &GatewayName) -> Result<BrowserSessionPlan, String> {
        let configured = self.file.gateways.iter().any(|(name, _)| name == gateway);
        let file = self.file.with_linked(&self.linked()?);
        file.gateway(gateway).map_err(|error| error.to_string())?;
        let mut overrides = Overrides {
            gateway: Some(gateway.clone()),
            ..Overrides::default()
        };
        if !configured {
            overrides.gateway_settings.ca_file = linked_test_ca();
        }
        let settings = file
            .settings(&overrides)
            .map_err(|error| error.to_string())?;
        Ok(BrowserSessionPlan {
            proxy: proxy_config(&settings).map_err(|error| error.to_string())?,
        })
    }
}

async fn agent(args: ConfigArg) -> Result {
    let shutdown = shutdown_signal();
    let file = args.load()?;
    init_logging("info");
    args.log_default();
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
    let profiles = ConfigProfiles {
        file: file.clone(),
        linked: linked_store(),
    };
    let agent = Agent::new(options, profiles);
    if device_session {
        let settings = file.settings(&Overrides::default())?;
        let config = Config {
            listen: settings.listen,
            local_auth: settings.device_session_auth,
            ..proxy_config(&settings)?
        };
        let id = agent
            .start_session(SessionConfig {
                kind: SessionKind::Device,
                gateway: settings.gateway.name,
                proxy: config,
            })
            .await?;
        if let Some(hint) = device_session_hint(id, settings.device_session_auth) {
            tracing::info!("{hint}");
        }
    }
    tracing::info!(%endpoint, "agent ready");
    agent.serve(server, shutdown).await;
    Ok(())
}

fn device_session_hint(id: SessionId, local_auth: LocalAuth) -> Option<String> {
    local_auth.session_credentials.then(|| {
        format!(
            "device session {id} accepts {local_auth}; run `gateinto session credentials {id}` for the credentials"
        )
    })
}

async fn agent_detach(config: Option<&Path>) -> Result {
    let endpoint = Endpoint::for_current_user()?;
    match ipc::send(&endpoint, &Request::List).await {
        Ok(_) => {
            println!("an agent is already running");
            return Ok(());
        }
        Err(RequestError::NotRunning | RequestError::Closed) => {}
        Err(error) => return Err(error.into()),
    }
    start_agent_and_send(&endpoint, &Request::List, config).await?;
    println!("started the agent");
    Ok(())
}

const AGENT_START_TIMEOUT: Duration = Duration::from_secs(30);
const AGENT_START_ATTEMPTS: u32 = 3;

fn agent_start_help(config: Option<&Path>) -> String {
    match config {
        Some(path) => format!(
            "run `gateinto agent` with `--config` set to {} to see why",
            path.display()
        ),
        None => "run `gateinto agent` to see why".to_owned(),
    }
}

async fn open(args: OpenArgs) -> Result {
    let launch = args.uri.parse::<LaunchRequest>()?;
    let request = Request::Launch(launch.clone());
    let endpoint = Endpoint::for_current_user()?;
    let response = match ipc::send(&endpoint, &request).await {
        Err(RequestError::NotRunning | RequestError::Closed) => {
            start_agent_and_send(&endpoint, &request, args.config.config.as_deref()).await?
        }
        result => result?,
    };
    let lines = match &response {
        Response::Ok(lines) => lines.clone(),
        Response::Error(_) => Vec::new(),
    };
    let Some(token) = ipc::confirm_token(&lines) else {
        return print_launched(response).await;
    };
    let profile = launch
        .proposed_profile()
        .ok_or("the launch has no gateway selector")?;
    let Some(gateway) = launch.gateway else {
        ipc::send(&endpoint, &Request::Deny(token)).await?;
        return Err("the agent asked to confirm a gateway the link does not name".into());
    };
    let confirmation = Confirmation {
        route: launch.route,
        profile: profile.clone(),
        gateway,
        portal: launch.portal,
    };
    if !confirmation.echoed_by(&lines) {
        ipc::send(&endpoint, &Request::Deny(token)).await?;
        return Err(
            "the agent asked to confirm another gateway than the link names; nothing \
                    was stored"
                .into(),
        );
    }
    let answer = tokio::task::spawn_blocking(move || {
        prompt::ask(&confirmation).map_err(|error| error.to_string())
    })
    .await?;
    match answer {
        Ok(true) => print_launched(ipc::send(&endpoint, &Request::Approve(token)).await?).await,
        Ok(false) => {
            ipc::send(&endpoint, &Request::Deny(token)).await?;
            Err(link::LinkError::Denied(profile).into())
        }
        Err(error) => {
            ipc::send(&endpoint, &Request::Deny(token)).await?;
            Err(error.into())
        }
    }
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

async fn start_agent_and_send(
    endpoint: &Endpoint,
    request: &Request,
    config: Option<&Path>,
) -> Result<Response> {
    let deadline = Instant::now() + AGENT_START_TIMEOUT;
    let mut child = spawn_agent(config)?;
    let mut started = 1;
    let mut delay = Duration::from_millis(25);
    loop {
        tokio::time::sleep(delay).await;
        let exited = child.try_wait()?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        let limit = remaining.max(Duration::from_secs(1));
        match ipc::send_with_timeout(endpoint, request, limit).await {
            Err(RequestError::NotRunning | RequestError::Closed) => {}
            result => return Ok(result?),
        }
        if let Some(status) = exited {
            if started == AGENT_START_ATTEMPTS {
                return Err(format!(
                    "the agent exited ({status}) before accepting requests; {}",
                    agent_start_help(config)
                )
                .into());
            }
            child = spawn_agent(config)?;
            started += 1;
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "the agent did not accept requests within {} seconds; {}",
                AGENT_START_TIMEOUT.as_secs(),
                agent_start_help(config)
            )
            .into());
        }
        delay = (delay * 2).min(Duration::from_secs(1));
    }
}

fn print_response(response: Response) -> Result {
    match response {
        Response::Ok(lines) => {
            for line in ipc::without_credentials(lines) {
                println!("{line}");
            }
            Ok(())
        }
        Response::Error(message) => Err(message.into()),
    }
}

async fn print_launched(response: Response) -> Result {
    let issued = match &response {
        Response::Ok(lines) => lines
            .iter()
            .find_map(|line| line.strip_prefix("session: ")?.parse().ok())
            .zip(listen_and_credentials(lines)),
        Response::Error(_) => None,
    };
    print_response(response)?;
    if let Some((session, (listen, credentials))) = issued
        && let Err(note) = show_credentials(Some(session), listen, credentials).await
    {
        eprintln!("warning: {note}");
    }
    Ok(())
}

fn listen_and_credentials(lines: &[String]) -> Option<(SocketAddr, SessionCredentials)> {
    let listen = lines
        .iter()
        .find_map(|line| line.strip_prefix("listen: ")?.parse().ok())?;
    Some((listen, ipc::issued_credentials(lines)?))
}

async fn show_credentials(
    session: Option<SessionId>,
    listen: SocketAddr,
    credentials: SessionCredentials,
) -> std::result::Result<(), String> {
    tokio::task::spawn_blocking(move || {
        let notice = prompt::CredentialsNotice {
            session,
            listen,
            credentials: &credentials,
        };
        if prompt::show_credentials(&notice) {
            Ok(())
        } else {
            Err(prompt::unshown_text(&notice))
        }
    })
    .await
    .map_err(|error| error.to_string())?
}

async fn session_credentials(id: SessionId) -> Result {
    let endpoint = Endpoint::for_current_user()?;
    let lines = match ipc::send(&endpoint, &Request::Credentials(id)).await? {
        Response::Ok(lines) => lines,
        Response::Error(message) => return Err(message.into()),
    };
    let (listen, credentials) =
        listen_and_credentials(&lines).ok_or("the agent did not return the session credentials")?;
    Ok(show_credentials(Some(id), listen, credentials).await?)
}

async fn agent_request(request: Request) -> Result {
    let endpoint = Endpoint::for_current_user()?;
    print_response(ipc::send(&endpoint, &request).await?)
}

const AGENT_EXIT_TIMEOUT: Duration = Duration::from_secs(15);

async fn stop_and_wait() -> Result<Result<u32, RequestError>, String> {
    let endpoint = Endpoint::for_current_user().map_err(|error| error.to_string())?;
    let lines = match ipc::send(&endpoint, &Request::Stop).await {
        Ok(Response::Ok(lines)) => lines,
        Ok(Response::Error(message)) => return Err(message),
        Err(error @ (RequestError::NotRunning | RequestError::Closed)) => return Ok(Err(error)),
        Err(error) => return Err(error.to_string()),
    };
    let pid = ipc::agent_pid(&lines).ok_or("the agent did not report its process id")?;
    let exited = tokio::task::spawn_blocking(move || {
        gateinto::process::wait_for_exit(pid, AGENT_EXIT_TIMEOUT)
    })
    .await
    .map_err(|error| error.to_string())?
    .map_err(|error| format!("waiting for the agent (process {pid}) failed: {error}"))?;
    if !exited {
        return Err(format!(
            "the agent (process {pid}) did not exit within {} seconds",
            AGENT_EXIT_TIMEOUT.as_secs()
        ));
    }
    Ok(Ok(pid))
}

async fn stop(args: StopArgs) -> Result {
    match stop_and_wait().await? {
        Ok(pid) => println!("stopped the agent (process {pid})"),
        Err(error) if !args.remove_stale_profiles => return Err(error.into()),
        Err(_) => println!("no agent is running"),
    }
    if args.remove_stale_profiles {
        let root = browser::profiles_root()
            .ok_or("cannot find the per-user application data directory for browser profiles")?;
        println!("removed {} stale browser profiles", browser::sweep(&root));
    }
    Ok(())
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

fn linked_store() -> Option<LinkedStore> {
    store::default_dir().map(LinkedStore::new)
}

fn print_config(args: &ConfigArg, file: &ConfigFile) {
    let store = linked_store();
    let known = Known::new(file, load_linked(store.as_ref()));
    let lines = |source| {
        let known: Vec<KnownGateway> = known
            .gateways
            .iter()
            .filter(|gateway| gateway.source == source)
            .cloned()
            .collect();
        for line in lifecycle::gateway_lines(&known) {
            println!("gateway: {line}");
        }
    };
    match args.path() {
        Some((path, default)) => {
            let location = if default { " (default location)" } else { "" };
            println!("config: {}{location}", path.display());
            lines(Source::Config);
        }
        None => println!(
            "config: none (no file at {}; pass --config to use another file)",
            default_config_display()
        ),
    }
    match store {
        _ if known.unavailable.is_some() => {}
        Some(store) if store.dir().is_dir() => {
            println!("linked-gateways: {}", store.dir().display());
            lines(Source::Linked);
        }
        Some(store) => println!(
            "linked-gateways: none (no directory at {})",
            store.dir().display()
        ),
        None => println!("linked-gateways: none (no default location)"),
    }
    for line in known.error_lines() {
        println!("{line}");
    }
}

fn gateway(command: GatewayCommand) -> Result {
    match command {
        GatewayCommand::List(args) => {
            let known = Known::new(&args.load()?, load_linked(linked_store().as_ref()));
            if let Some(error) = &known.unavailable {
                return Err(error.clone().into());
            }
            for line in lifecycle::gateway_list(&known.gateways) {
                println!("{line}");
            }
            for line in known.error_lines() {
                println!("{line}");
            }
        }
        GatewayCommand::Forget { config, name } => {
            let file = config.load()?;
            let store = linked_store().ok_or("cannot find the per-user config directory")?;
            let configured = file.gateways.iter().any(|(known, _)| *known == name);
            if let Some(path) = store.forget(&name)? {
                println!(
                    "removed the gateway \"{name}\" added from a link ({})",
                    path.display()
                );
                if configured {
                    println!("the config file still defines a gateway \"{name}\"");
                }
                println!("open browser sessions of this gateway stay open until closed");
            } else if let Some(entry) = store
                .load()?
                .invalid
                .into_iter()
                .find(|entry| entry.name.as_ref() == Some(&name))
            {
                return Err(format!(
                    "the gateway \"{name}\" is in a damaged file ({entry}); delete that file to \
                     remove it"
                )
                .into());
            } else if configured {
                return Err(format!(
                    "the gateway \"{name}\" is defined in the config file, not added from a \
                     link; edit the config file to change it"
                )
                .into());
            } else {
                return Err(format!("no gateway added from a link named \"{name}\"").into());
            }
        }
    }
    Ok(())
}

fn print_handler() {
    println!(
        "uri-handler: {}",
        lifecycle::handler_state(registration::registered_command(registration::SCHEME))
    );
}

fn setup(args: KeyInitArgs) -> Result {
    if let Some(note) = lifecycle::check_current_account()? {
        eprintln!("{note}");
    }
    let file = args.config.load()?;
    let settings = args.settings()?;
    print_config(&args.config, &file);
    let store = gateinto::identity::system_store()?;
    let options = InitOptions {
        backend: settings.preferred,
        allow_software_fallback: settings.software_fallback_on_first_create,
    };
    let (key, provenance) = device_key::init(&store, &settings.name, options)?;
    let state = match provenance {
        Provenance::Reused => "reused",
        Provenance::Created => "created",
        Provenance::CreatedAfterFallback(problem) => {
            eprintln!("warning: {problem}; created a software key instead");
            "created"
        }
    };
    println!("key-name: {}", settings.name);
    println!("device-key: {state}");
    println!("provider: {}", key.backend.provider());
    print!("{}", key.summary());
    print_handler();
    Ok(())
}

async fn status(args: StatusArgs) -> Result {
    let file = args.config.load()?;
    let name = device_key_settings(&args.config, args.name.clone())?.name;
    println!("key-name: {name}");
    match gateinto::identity::system_store() {
        Err(error) => println!("device-key: unavailable: {error}"),
        Ok(store) => match device_key::info(&store, &name) {
            Ok((key, duplicate)) => {
                if let Some(duplicate) = duplicate {
                    eprintln!("{}", duplicate.info_warning());
                }
                println!("device-key: present");
                println!("provider: {}", key.backend.provider());
                println!("spki-sha256: {}", key.fingerprint());
            }
            Err(KeyError::NotFound(_)) => {
                println!("device-key: absent (run `gateinto setup` to create it)");
            }
            Err(error) => println!("device-key: error: {error}"),
        },
    }
    print_config(&args.config, &file);
    println!("device-session: {}", lifecycle::device_session_line(&file));
    let agent = match Endpoint::for_current_user() {
        Ok(endpoint) => ipc::send(&endpoint, &Request::List).await,
        Err(error) => Err(RequestError::Io(error)),
    };
    match agent {
        Ok(Response::Ok(sessions)) => {
            println!("agent: running");
            for session in sessions {
                println!("{session}");
            }
        }
        Ok(Response::Error(message)) => println!("agent: running, list failed: {message}"),
        Err(RequestError::NotRunning | RequestError::Closed) => println!("agent: not running"),
        Err(error) => println!("agent: unknown: {error}"),
    }
    print_handler();
    Ok(())
}

async fn stop_agent() -> Result<(), String> {
    stop_and_wait().await.map(drop)
}

fn files_to_purge(args: &ResetArgs) -> Result<Option<Purge>> {
    if !args.purge_config {
        return Ok(None);
    }
    let config = args.config.path().map(|(path, _)| path);
    let purge = lifecycle::files_to_purge(config.as_deref(), linked_store().as_ref())?;
    if purge == Purge::default() {
        return Err(format!(
            "--purge-config found no config file named with --config or at {}, and no gateways \
             added from links; nothing was deleted",
            default_config_display()
        )
        .into());
    }
    Ok(Some(purge))
}

const NO_TERMINAL: &str = "refusing to delete the device key without confirmation: no \
                           terminal to ask on; pass --confirm-spki with at least the first 16 \
                           hex digits of the spki-sha256 shown by `gateinto status`";

fn delete_files(files: &Purge) -> Result {
    if let Some(path) = &files.config {
        std::fs::remove_file(path)
            .map_err(|error| format!("deleting {}: {error}", path.display()))?;
        println!("deleted config file {}", path.display());
    }
    if let (Some(dir), Some(summary)) = (&files.linked_dir, files.linked_summary()) {
        LinkedStore::new(dir.clone()).remove(&files.linked)?;
        println!("deleted {summary}");
    }
    Ok(())
}

fn purge_files_only(name: &KeyName, files: &Purge, yes: bool, terminal: bool) -> Result {
    use std::io::{BufRead, Write};

    println!("no device key named \"{name}\"; no key was deleted");
    println!("This permanently deletes {}.", files.items().join(" and "));
    if !yes {
        if !terminal {
            return Err(
                "refusing to delete the config file without confirmation: no terminal \
                        to ask on; pass --yes"
                    .into(),
            );
        }
        print!("\nType purge to delete them: ");
        std::io::stdout().flush()?;
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        if line.trim() != "purge" {
            return Err("the confirmation did not match; nothing was deleted".into());
        }
    }
    delete_files(files)
}

async fn reset(args: ResetArgs) -> Result {
    use std::io::IsTerminal;

    let terminal = std::io::stdin().is_terminal();
    if args.confirm_spki.is_none() && !args.yes && !terminal {
        return Err(NO_TERMINAL.into());
    }
    let files = files_to_purge(&args)?;
    let name = device_key_settings(&args.config, args.name.clone())?.name;
    let store = gateinto::identity::system_store()?;
    let found = match device_key::info(&store, &name) {
        Ok((key, None)) => Some((key.backend, key.fingerprint())),
        Ok((_, Some(duplicate))) => return Err(KeyError::Duplicate(duplicate).into()),
        Err(KeyError::NotFound(_)) if files.is_some() => None,
        Err(error) => return Err(error.into()),
    };
    let Some((backend, fingerprint)) = found else {
        let files = files.expect("only a config purge reaches here without a key");
        return purge_files_only(&name, &files, args.yes, terminal);
    };
    if args.confirm_spki.is_none() && !terminal {
        return Err(NO_TERMINAL.into());
    }
    print!(
        "{}",
        lifecycle::purge_warning(
            &name,
            backend,
            &fingerprint,
            &files.clone().unwrap_or_default()
        )
    );
    let confirmation = match args.confirm_spki {
        Some(confirmation) => confirmation,
        None => {
            use std::io::Write;
            print!("\nType the first 16 characters of the spki-sha256 above to delete the key: ");
            std::io::stdout().flush()?;
            if !lifecycle::confirm_from(&mut std::io::stdin().lock(), &fingerprint) {
                return Err("the confirmation did not match; nothing was deleted".into());
            }
            fingerprint[..16].parse()?
        }
    };
    let purged =
        lifecycle::purge_device_identity(&store, &name, &confirmation, stop_agent()).await?;
    println!(
        "deleted device key \"{name}\" from the {} (spki-sha256: {})",
        purged.backend.provider(),
        purged.fingerprint
    );
    if let Some(files) = &files {
        delete_files(files)?;
    }
    println!(
        "The device is NOT revoked at any gateway. `gateinto setup` creates a new device key \
         with a new identity."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_device_session_hint_names_the_accepted_methods() {
        let id: SessionId = "3".parse().unwrap();
        assert_eq!(
            device_session_hint(id, LocalAuth::SESSION_CREDENTIALS).as_deref(),
            Some(
                "device session 3 accepts session_credentials; run `gateinto session credentials 3` for the credentials"
            )
        );
        let both = LocalAuth {
            os_user: true,
            session_credentials: true,
        };
        assert_eq!(
            device_session_hint(id, both).as_deref(),
            Some(
                "device session 3 accepts os_user, session_credentials; run `gateinto session credentials 3` for the credentials"
            )
        );
        assert_eq!(device_session_hint(id, LocalAuth::OS_USER), None);
        assert_eq!(device_session_hint(id, LocalAuth::NONE), None);
    }

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
