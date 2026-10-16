use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use gateinto::http::DEFAULT_MAX_HEADER_BYTES;
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
    let Command::Proxy(args) = Cli::parse().command;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        // Otherwise a closed stderr makes tracing-subscriber panic inside connection tasks.
        .log_internal_errors(false)
        .init();
    match proxy(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn proxy(args: ProxyArgs) -> Result<(), Box<dyn std::error::Error>> {
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
        },
    };
    Proxy::bind(config).await?.run().await;
    Ok(())
}
