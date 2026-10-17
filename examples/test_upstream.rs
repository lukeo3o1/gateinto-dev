#[allow(dead_code)]
#[path = "../tests/fixture/mod.rs"]
mod fixture;

use std::path::PathBuf;

use clap::Parser;
use fixture::{Behavior, LOOPBACK, TestCa, UpstreamProxy};
use tokio::net::TcpListener;

/// Throwaway HTTPS CONNECT upstream on loopback, for development and CI only
#[derive(Parser)]
struct Args {
    /// Loopback port to listen on
    #[arg(long)]
    port: u16,

    /// File to write the PEM certificate of the generated test CA to
    #[arg(long)]
    ca_out: PathBuf,

    /// Name in the server certificate
    #[arg(long, default_value = "localhost")]
    name: String,
}

async fn start(args: &Args) -> std::io::Result<UpstreamProxy> {
    let ca = TestCa::new();
    std::fs::write(&args.ca_out, ca.pem())?;
    let listener = TcpListener::bind((LOOPBACK, args.port)).await?;
    Ok(UpstreamProxy::serve(
        listener,
        ca.server_config(&args.name),
        Behavior::Tunnel,
    ))
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let upstream = start(&Args::parse()).await?;
    println!("listening on {}", upstream.addr);
    std::future::pending().await
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use gateinto::check::{CheckOptions, check_upstream};
    use gateinto::tls::{TlsMode, load_pem_roots};
    use rustls::{NamedGroup, ProtocolVersion};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use fixture::{agent_config, echo_server, open_tunnel, start_agent};

    fn args(test: &str) -> Args {
        let ca_out = std::env::temp_dir().join(format!(
            "gateinto-test-upstream-{}-{test}-ca.pem",
            std::process::id()
        ));
        Args {
            port: 0,
            ca_out,
            name: "localhost".to_owned(),
        }
    }

    #[test]
    fn name_defaults_to_localhost() {
        let args = Args::try_parse_from(["test_upstream", "--port", "8443", "--ca-out", "ca.pem"])
            .unwrap();
        assert_eq!(args.name, "localhost");
        assert_eq!(args.port, 8443);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn negotiates_tls13_hybrid_with_the_written_ca_and_tunnels() {
        let args = args("check");
        let upstream = start(&args).await.unwrap();
        assert!(upstream.addr.ip().is_loopback());
        let roots = load_pem_roots(&args.ca_out).unwrap();
        std::fs::remove_file(&args.ca_out).unwrap();
        let target = echo_server().await;
        let config = agent_config(upstream.addr, roots, &args.name);

        let report = check_upstream(CheckOptions {
            upstream: config.upstream,
            tls_mode: TlsMode::HybridPreferred,
            client_certificate: None,
            target: Some(target.to_string().parse().unwrap()),
            timeout: Duration::from_secs(5),
            max_header_bytes: 16384,
        })
        .await
        .unwrap();

        assert_eq!(report.protocol_version, ProtocolVersion::TLSv1_3);
        assert_eq!(report.key_exchange_group, NamedGroup::X25519MLKEM768);
        assert_eq!(
            report.connect_status,
            Some((200, "HTTP/1.1 200 Connection established".to_owned()))
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn relays_both_ways_through_the_proxy() {
        let args = args("relay");
        let upstream = start(&args).await.unwrap();
        let roots = load_pem_roots(&args.ca_out).unwrap();
        std::fs::remove_file(&args.ca_out).unwrap();
        let agent = start_agent(agent_config(upstream.addr, roots, &args.name)).await;
        let mut tunnel = open_tunnel(agent, echo_server().await).await;

        tunnel.write_all(b"ping").await.unwrap();
        let mut reply = [0; 4];
        tunnel.read_exact(&mut reply).await.unwrap();

        assert_eq!(&reply, b"ping");
    }
}
