use std::net::SocketAddr;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use gateinto::check::{self, CheckOptions};
use gateinto::config::{self, ConfigFile, DeviceKeySettings, Settings};
use gateinto::http::Authority;
use gateinto::identity::client_cert::{
    self, ClientCertificateMode, ClientCertificateOptions, ClientIdentityStore,
};
use gateinto::identity::device_key::{self, Backend, InitOptions, KeyName, KeyStore, Provenance};
use gateinto::proxy::{Config, Limits, Proxy, Upstream};
use gateinto::tls::{self, TlsMode};
use rustls::pki_types::{ServerName, UnixTime};
use rustls::sign::CertifiedKey;
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

    /// Fail instead of creating a software key when the TPM cannot be used
    #[arg(long)]
    no_software_fallback: bool,
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

    /// Name of the persisted CNG device key that signs for the client certificate [default: gateinto-device-v1]
    #[arg(long)]
    key_name: Option<KeyName>,
}

impl UpstreamArgs {
    fn overrides(&self) -> ConfigFile {
        let mut overrides = ConfigFile::default();
        overrides.upstream.host = self.upstream_host.clone();
        overrides.upstream.port = self.upstream_port.and_then(NonZeroU16::new);
        overrides.upstream.server_name = self.upstream_server_name.clone();
        overrides.upstream.ca_file = self.ca_file.clone();
        overrides.tls.mode = self.tls_mode;
        overrides.tls.client_certificate = self.client_certificate.map(Into::into);
        overrides.tls.client_cert_file = self.client_cert_file.clone();
        overrides.device_key.name = self.key_name.clone();
        overrides
    }

    fn settings(&self, extra: impl FnOnce(&mut ConfigFile)) -> Result<Settings> {
        let mut overrides = self.overrides();
        extra(&mut overrides);
        Ok(self.config.load()?.merge(overrides).settings()?)
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
            let mut settings = device_key_settings(&args.config, args.name.clone())?;
            if let Some(backend) = args.backend {
                settings.preferred = backend.into();
            }
            if args.no_software_fallback {
                settings.software_fallback_on_first_create = false;
            }
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
    let upstream = &settings.upstream;
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

fn client_certificate(settings: &Settings) -> Result<Option<Arc<CertifiedKey>>> {
    let options = ClientCertificateOptions {
        mode: settings.client_certificate,
        key_name: settings.device_key.name.clone(),
        file: settings.client_cert_file.clone(),
    };
    let store = gateinto::identity::system_store();
    let client_auth =
        client_cert::configure(&options, store.as_ref().map_err(|&e| e), UnixTime::now())?;
    Ok(client_auth.into_certified_key())
}

async fn check_upstream(args: CheckUpstreamArgs) -> Result {
    let settings = args.upstream.settings(|_| {})?;
    init_logging("warn");
    let options = CheckOptions {
        upstream: upstream(&settings)?,
        tls_mode: settings.tls_mode,
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
    let settings = args.upstream.settings(|overrides| {
        overrides.listen.address = args.listen;
        let limits = &mut overrides.limits;
        limits.max_concurrent_tunnels = args.max_tunnels.and_then(NonZeroU32::new);
        limits.header_max_bytes = args.max_header_bytes.and_then(NonZeroU32::new);
        limits.connect_timeout_seconds = args.connect_timeout_secs.and_then(NonZeroU64::new);
        limits.idle_timeout_seconds = args.idle_timeout_secs.and_then(NonZeroU64::new);
    })?;
    init_logging("info");
    let limits = &settings.limits;
    let config = Config {
        listen: settings.listen,
        allow_non_loopback: args.unsafe_allow_non_loopback_listen,
        upstream: upstream(&settings)?,
        tls_mode: settings.tls_mode,
        client_certificate: client_certificate(&settings)?,
        limits: Limits {
            max_header_bytes: limits.header_max_bytes as usize,
            max_tunnels: limits.max_concurrent_tunnels as usize,
            handshake_timeout: Duration::from_secs(limits.connect_timeout_seconds),
            idle_timeout: Duration::from_secs(limits.idle_timeout_seconds),
            ..Limits::default()
        },
    };
    Proxy::bind(config).await?.run().await;
    Ok(())
}
