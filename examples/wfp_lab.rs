#[allow(dead_code)]
#[path = "../tests/fixture/mod.rs"]
mod fixture;

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;
use fixture::{Behavior, TestCa, UpstreamProxy};
use gateinto::proxy::{LocalAuth, Proxy, Route};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::{JoinHandle, JoinSet};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[arg(long, default_value_t = 60)]
    seconds: u64,
    #[arg(long, default_value = "127.0.0.1")]
    bind_ip: Ipv4Addr,
}

struct Lab {
    upstream: UpstreamProxy,
    proxy_addr: SocketAddr,
    target_addr: SocketAddr,
    udp_addrs: [SocketAddr; 2],
    authorization: String,
    manifest: PathBuf,
    manifest_owned: bool,
    gateway_log: PathBuf,
    tasks: Vec<JoinHandle<()>>,
}

impl Lab {
    async fn start(args: &Args) -> io::Result<Self> {
        if args.bind_ip.is_unspecified() || args.bind_ip.is_multicast() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bind-ip must name one local address",
            ));
        }
        std::fs::create_dir_all(&args.out)?;
        let target_log = Arc::new(Mutex::new(
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(args.out.join("target.jsonl"))?,
        ));
        let listener = TcpListener::bind((args.bind_ip, 0)).await?;
        let target_addr = listener.local_addr()?;
        let udp_a = UdpSocket::bind((args.bind_ip, 0)).await?;
        let udp_b = UdpSocket::bind((args.bind_ip, 0)).await?;
        let udp_addrs = [udp_a.local_addr()?, udp_b.local_addr()?];
        let ca = TestCa::new();
        let upstream = UpstreamProxy::start(ca.server_config("localhost"), Behavior::Tunnel).await;
        let mut config = fixture::agent_config(upstream.addr, ca.roots(), "localhost");
        config.local_auth = LocalAuth::SESSION_CREDENTIALS;
        config.route = Route::Gateway;
        let proxy = Proxy::bind(config).await.map_err(io::Error::other)?;
        let proxy_addr = proxy.local_addr();
        let credentials = proxy
            .credentials()
            .expect("credential authentication was configured");
        let authorization = fixture::basic(credentials.username(), credentials.password());
        let gateway_log = args.out.join("gateway.jsonl");
        std::fs::write(&gateway_log, "")?;
        let mut lab = Self {
            upstream,
            proxy_addr,
            target_addr,
            udp_addrs,
            authorization,
            manifest: args.manifest.clone(),
            manifest_owned: false,
            gateway_log,
            tasks: Vec::new(),
        };
        lab.write_manifest()?;
        lab.tasks.push(tokio::spawn(proxy.run()));
        lab.tasks
            .push(tokio::spawn(tcp_echo(listener, target_log.clone())));
        lab.tasks
            .push(tokio::spawn(udp_echo(udp_a, target_log.clone())));
        lab.tasks.push(tokio::spawn(udp_echo(udp_b, target_log)));
        Ok(lab)
    }

    fn write_manifest(&mut self) -> io::Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut manifest = options.open(&self.manifest)?;
        self.manifest_owned = true;
        writeln!(
            manifest,
            "{{\"topology\":\"same-host-local\",\"target_ip\":\"{}\",\"target_port\":{},\"udp_ports\":[{},{}],\"proxy_host\":\"{}\",\"proxy_port\":{},\"proxy_authorization\":\"{}\",\"gateway_host\":\"{}\",\"gateway_port\":{}}}",
            self.target_addr.ip(),
            self.target_addr.port(),
            self.udp_addrs[0].port(),
            self.udp_addrs[1].port(),
            self.proxy_addr.ip(),
            self.proxy_addr.port(),
            self.authorization,
            self.upstream.addr.ip(),
            self.upstream.addr.port()
        )?;
        manifest.sync_all()
    }

    fn snapshot_gateway(&self) -> io::Result<()> {
        let mut log = String::new();
        for (index, request) in self.upstream.requests().iter().enumerate() {
            let first = request.lines().next().unwrap_or_default();
            let first = first.replace('\\', "\\\\").replace('"', "\\\"");
            log.push_str(&format!(
                "{{\"kind\":\"gateway_connect\",\"index\":{index},\"request_line\":\"{first}\"}}\n"
            ));
        }
        std::fs::write(&self.gateway_log, log)
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = self.snapshot_gateway();
        for task in &self.tasks {
            task.abort();
        }
        if self.manifest_owned {
            let _ = std::fs::remove_file(&self.manifest);
        }
    }
}

fn record(
    log: &Mutex<File>,
    protocol: &str,
    local: SocketAddr,
    peer: SocketAddr,
    payload: &[u8],
) -> io::Result<()> {
    let hex: String = payload.iter().map(|byte| format!("{byte:02x}")).collect();
    let unix_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos();
    let mut log = log
        .lock()
        .map_err(|_| io::Error::other("target log lock poisoned"))?;
    writeln!(
        log,
        "{{\"kind\":\"target_payload\",\"protocol\":\"{protocol}\",\"local\":\"{local}\",\"peer\":\"{peer}\",\"unix_ns\":{unix_ns},\"payload_hex\":\"{hex}\"}}"
    )?;
    log.flush()
}

async fn tcp_echo(listener: TcpListener, log: Arc<Mutex<File>>) {
    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            Some(_) = clients.join_next(), if !clients.is_empty() => {},
            accepted = listener.accept() => {
                let Ok((mut stream, peer)) = accepted else { break };
                let Ok(local) = stream.local_addr() else { continue };
                let log = log.clone();
                clients.spawn(async move {
                    let mut bytes = [0; 8192];
                    while let Ok(size) = stream.read(&mut bytes).await {
                        if size == 0 { break }
                        if record(&log, "tcp", local, peer, &bytes[..size]).is_err() { break }
                        if stream.write_all(&bytes[..size]).await.is_err() { break }
                    }
                    let _ = stream.shutdown().await;
                });
            }
        }
    }
}

async fn udp_echo(socket: UdpSocket, log: Arc<Mutex<File>>) {
    let Ok(local) = socket.local_addr() else {
        return;
    };
    let mut bytes = [0; 65535];
    while let Ok((size, peer)) = socket.recv_from(&mut bytes).await {
        if record(&log, "udp", local, peer, &bytes[..size]).is_err() {
            break;
        }
        if socket.send_to(&bytes[..size], peer).await.is_err() {
            break;
        }
    }
}

fn ensure_manifest_parent(manifest: &Path) -> io::Result<()> {
    if let Some(parent) = manifest
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();
    ensure_manifest_parent(&args.manifest)?;
    let lab = Lab::start(&args).await?;
    println!("WFP lab ready; same-host local topology, credentials only in private manifest");
    let done = tokio::time::sleep(Duration::from_secs(args.seconds));
    tokio::pin!(done);
    let mut snapshot = tokio::time::interval(Duration::from_millis(100));
    loop {
        tokio::select! {
            () = &mut done => break,
            signal = tokio::signal::ctrl_c() => { signal?; break },
            _ = snapshot.tick() => lab.snapshot_gateway()?,
        }
    }
    lab.snapshot_gateway()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(name: &str) -> Args {
        let out =
            std::env::temp_dir().join(format!("gateinto-wfp-lab-{}-{name}", std::process::id()));
        Args {
            manifest: out.join("private-manifest.json"),
            out,
            seconds: 10,
            bind_ip: Ipv4Addr::LOCALHOST,
        }
    }

    #[tokio::test]
    async fn requires_credentials_and_records_gateway_connect_and_echo() {
        let args = args("tcp");
        let lab = Lab::start(&args).await.unwrap();
        let (_, denied) = fixture::send(
            lab.proxy_addr,
            &fixture::connect_request(&lab.target_addr.to_string()),
        )
        .await;
        assert_eq!(denied.status, 407);
        assert!(lab.upstream.requests().is_empty());

        let request = fixture::connect_with(&lab.target_addr.to_string(), Some(&lab.authorization));
        let (mut client, response) = fixture::send(lab.proxy_addr, &request).await;
        assert_eq!(response.status, 200);
        client.write_all(b"wfp-lab-nonce").await.unwrap();
        let mut echo = [0; 13];
        client.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"wfp-lab-nonce");
        assert_eq!(lab.upstream.requests().len(), 1);
        assert!(lab.upstream.requests()[0].starts_with(&format!("CONNECT {} ", lab.target_addr)));
        lab.snapshot_gateway().unwrap();
        assert!(
            std::fs::read_to_string(args.out.join("gateway.jsonl"))
                .unwrap()
                .contains("CONNECT")
        );
        drop(lab);
        assert!(!args.manifest.exists());
        std::fs::remove_dir_all(args.out).unwrap();
    }

    #[tokio::test]
    async fn one_udp_socket_can_reach_both_echo_destinations() {
        let args = args("udp");
        let lab = Lab::start(&args).await.unwrap();
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        for (index, destination) in lab.udp_addrs.iter().enumerate() {
            let nonce = format!("udp-destination-{index}");
            socket.send_to(nonce.as_bytes(), destination).await.unwrap();
            let mut response = [0; 64];
            let (size, sender) = socket.recv_from(&mut response).await.unwrap();
            assert_eq!(sender, *destination);
            assert_eq!(&response[..size], nonce.as_bytes());
        }
        assert!(lab.upstream.requests().is_empty());
        drop(lab);
        std::fs::remove_dir_all(args.out).unwrap();
    }

    #[tokio::test]
    async fn refuses_an_existing_manifest_without_deleting_it() {
        let args = args("existing-manifest");
        std::fs::create_dir_all(&args.out).unwrap();
        std::fs::write(&args.manifest, "preexisting").unwrap();
        assert!(Lab::start(&args).await.is_err());
        assert_eq!(
            std::fs::read_to_string(&args.manifest).unwrap(),
            "preexisting"
        );
        std::fs::remove_dir_all(args.out).unwrap();
    }
}
