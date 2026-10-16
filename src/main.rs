use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use gateinto::http::DEFAULT_MAX_HEADER_BYTES;
use gateinto::identity::device_key::{
    self, Backend, DEFAULT_KEY_NAME, InitOptions, KeyName, KeyStore, Provenance,
};
use gateinto::proxy::{Config, DEFAULT_LISTEN, Limits, Proxy, Upstream};
use gateinto::tls;
use rustls::pki_types::ServerName;
use tracing_subscriber::EnvFilter;

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
struct KeyInitArgs {
    /// Name of the persisted CNG key
    #[arg(long, default_value = DEFAULT_KEY_NAME)]
    name: KeyName,

    /// Backend for a new key; an existing key is reused wherever it is
    #[arg(long, value_enum, default_value_t = BackendArg::Tpm)]
    backend: BackendArg,

    /// Fail instead of creating a software key when the TPM cannot be used
    #[arg(long)]
    no_software_fallback: bool,
}

#[derive(Args)]
struct KeyInfoArgs {
    /// Name of the persisted CNG key
    #[arg(long, default_value = DEFAULT_KEY_NAME)]
    name: KeyName,

    /// Write the DER SubjectPublicKeyInfo of the public key to this file
    #[arg(long)]
    spki_out: Option<PathBuf>,
}

#[derive(Clone, Copy, ValueEnum)]
enum BackendArg {
    Tpm,
    Software,
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
    /// Local address to listen on
    #[arg(long, default_value_t = DEFAULT_LISTEN)]
    listen: SocketAddr,

    /// Allow listening on a non-loopback address, exposing the proxy to the network
    #[arg(long)]
    unsafe_allow_non_loopback_listen: bool,

    /// Upstream HTTPS proxy host name or IP address
    #[arg(long)]
    upstream_host: String,

    /// Upstream HTTPS proxy port
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    upstream_port: u16,

    /// Name to verify in the upstream certificate [default: the upstream host]
    #[arg(long)]
    upstream_server_name: Option<String>,

    /// PEM file with the CA certificates trusted for the upstream [default: Mozilla roots]
    #[arg(long)]
    ca_file: Option<PathBuf>,

    /// Maximum number of concurrent connections
    #[arg(long, default_value_t = 64, value_parser = clap::value_parser!(u32).range(1..))]
    max_tunnels: u32,

    /// Maximum size of a CONNECT request or response header block
    #[arg(long, default_value_t = DEFAULT_MAX_HEADER_BYTES as u32, value_parser = clap::value_parser!(u32).range(1..))]
    max_header_bytes: u32,

    /// Timeout for reading the request and opening the upstream tunnel
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..))]
    connect_timeout_secs: u64,

    /// Close a tunnel after this many seconds without traffic
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..))]
    idle_timeout_secs: u64,
}

#[tokio::main]
async fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Proxy(args) => proxy(args).await,
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

fn key(command: KeyCommand) -> Result<(), Box<dyn std::error::Error>> {
    let store = gateinto::identity::system_store()?;
    match command {
        KeyCommand::Init(args) => key_init(&store, args),
        KeyCommand::Info(args) => key_info(&store, args),
    }
}

fn key_init<S: KeyStore>(store: &S, args: KeyInitArgs) -> Result<(), Box<dyn std::error::Error>> {
    let options = InitOptions {
        backend: args.backend.into(),
        allow_software_fallback: !args.no_software_fallback,
    };
    let (key, provenance) = device_key::init(store, &args.name, options)?;
    match provenance {
        Provenance::Reused => println!("using existing device key \"{}\"", args.name),
        Provenance::Created => println!("created device key \"{}\"", args.name),
        Provenance::CreatedAfterFallback(problem) => {
            eprintln!("warning: {problem}");
            println!(
                "created software device key \"{}\" because the TPM could not be used",
                args.name
            );
        }
    }
    print!("{}", key.summary());
    Ok(())
}

fn key_info<S: KeyStore>(store: &S, args: KeyInfoArgs) -> Result<(), Box<dyn std::error::Error>> {
    let (key, duplicate) = device_key::info(store, &args.name)?;
    if let Some(duplicate) = duplicate {
        eprintln!("{}", duplicate.info_warning());
    }
    print!("{}", key.summary());
    if let Some(path) = args.spki_out {
        std::fs::write(&path, key.spki_der())
            .map_err(|error| format!("writing {}: {error}", path.display()))?;
    }
    Ok(())
}

async fn proxy(args: ProxyArgs) -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        // Otherwise a closed stderr makes tracing-subscriber panic inside connection tasks.
        .log_internal_errors(false)
        .init();
    let server_name = args
        .upstream_server_name
        .unwrap_or_else(|| args.upstream_host.clone());
    let server_name = ServerName::try_from(server_name)
        .map_err(|error| format!("invalid upstream server name: {error}"))?;
    let roots = match &args.ca_file {
        Some(path) => tls::load_pem_roots(path)?,
        None => tls::webpki_roots(),
    };
    let config = Config {
        listen: args.listen,
        allow_non_loopback: args.unsafe_allow_non_loopback_listen,
        upstream: Upstream {
            host: args.upstream_host,
            port: args.upstream_port,
            server_name,
            roots,
        },
        limits: Limits {
            max_header_bytes: args.max_header_bytes as usize,
            max_tunnels: args.max_tunnels as usize,
            handshake_timeout: Duration::from_secs(args.connect_timeout_secs),
            idle_timeout: Duration::from_secs(args.idle_timeout_secs),
            ..Limits::default()
        },
    };
    Proxy::bind(config).await?.run().await;
    Ok(())
}
