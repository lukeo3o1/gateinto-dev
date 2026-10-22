use std::future::poll_fn;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use h2::Reason;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsAcceptor;

pub struct Server {
    pub addr: SocketAddr,
    pub accepted: Arc<AtomicUsize>,
    pub active: Arc<AtomicUsize>,
    pub sent_bytes: Arc<AtomicUsize>,
    pub requests: Arc<Mutex<Vec<(usize, String)>>>,
    pub certificates: Arc<Mutex<Vec<Vec<rustls::pki_types::CertificateDer<'static>>>>>,
    task: JoinHandle<()>,
}

struct Active(Arc<AtomicUsize>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Server {
    pub async fn start(config: Arc<ServerConfig>, max_streams: u32) -> Self {
        Self::start_switching(config, max_streams, false).await
    }

    pub async fn start_switching(
        config: Arc<ServerConfig>,
        max_streams: u32,
        legacy_first: bool,
    ) -> Self {
        Self::start_inner(config, max_streams, legacy_first, None).await
    }

    pub async fn start_with_stalled_initialization(
        config: Arc<ServerConfig>,
        prefix: &'static [u8],
    ) -> Self {
        Self::start_inner(config, 10, false, Some(prefix)).await
    }

    async fn start_inner(
        mut config: Arc<ServerConfig>,
        max_streams: u32,
        legacy_first: bool,
        stalled_initial_prefix: Option<&'static [u8]>,
    ) -> Self {
        Arc::make_mut(&mut config).alpn_protocols = vec![b"h2".to_vec()];
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let sent_bytes = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let certificates = Arc::new(Mutex::new(Vec::new()));
        let task = tokio::spawn({
            let accepted = accepted.clone();
            let active = active.clone();
            let requests = requests.clone();
            let certificates = certificates.clone();
            let sent_bytes = sent_bytes.clone();
            async move {
                let mut legacy_config = (*config).clone();
                legacy_config.alpn_protocols = vec![b"http/1.1".to_vec()];
                let legacy_acceptor = TlsAcceptor::from(Arc::new(legacy_config));
                let acceptor = TlsAcceptor::from(config);
                let mut connections = JoinSet::new();
                loop {
                    let (tcp, _) = tokio::select! {
                        result = listener.accept() => result.unwrap(),
                        Some(result) = connections.join_next(), if !connections.is_empty() => {
                            result.unwrap();
                            continue;
                        }
                    };
                    let id = accepted.fetch_add(1, Ordering::SeqCst);
                    active.fetch_add(1, Ordering::SeqCst);
                    let active = Active(active.clone());
                    let acceptor = if legacy_first && id == 0 {
                        legacy_acceptor.clone()
                    } else {
                        acceptor.clone()
                    };
                    let requests = requests.clone();
                    let certificates = certificates.clone();
                    let sent_bytes = sent_bytes.clone();
                    connections.spawn(async move {
                        let _active = active;
                        let Ok(mut tls) = acceptor.accept(tcp).await else {
                            return;
                        };
                        if id == 0
                            && let Some(prefix) = stalled_initial_prefix
                        {
                            use tokio::io::AsyncWriteExt;
                            if tls.write_all(prefix).await.is_ok() {
                                let _ = tokio::io::copy(&mut tls, &mut tokio::io::sink()).await;
                            }
                            return;
                        }
                        if tls.get_ref().1.alpn_protocol() == Some(b"http/1.1") {
                            use tokio::io::AsyncWriteExt;
                            let _ = super::fixture::read_head(&mut tls).await;
                            if tls.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.is_ok() {
                                let (mut reader, mut writer) = tokio::io::split(tls);
                                let _ = tokio::io::copy(&mut reader, &mut writer).await;
                            }
                            return;
                        }
                        certificates.lock().unwrap().push(
                            tls.get_ref()
                                .1
                                .peer_certificates()
                                .unwrap_or_default()
                                .to_vec(),
                        );
                        let Ok(mut connection) = h2::server::Builder::new()
                            .max_concurrent_streams(max_streams)
                            .handshake::<_, Bytes>(tls)
                            .await
                        else {
                            return;
                        };
                        let mut streams = JoinSet::new();
                        while let Some(Ok((request, respond))) = connection.accept().await {
                            assert_eq!(request.method(), http::Method::CONNECT);
                            assert_eq!(request.version(), http::Version::HTTP_2);
                            assert!(request.uri().scheme().is_none());
                            assert!(request.uri().path_and_query().is_none());
                            let target = request.uri().authority().unwrap().to_string();
                            requests.lock().unwrap().push((id, target.clone()));
                            if target.starts_with("drop.") {
                                break;
                            }
                            if target.starts_with("goaway.") {
                                connection.graceful_shutdown();
                            }
                            streams.spawn(serve(
                                request.into_body(),
                                respond,
                                target,
                                sent_bytes.clone(),
                            ));
                        }
                        streams.shutdown().await;
                    });
                }
            }
        });
        Self {
            addr,
            accepted,
            active,
            sent_bytes,
            requests,
            certificates,
            task,
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn send_data(send: &mut h2::SendStream<Bytes>, mut bytes: Bytes) -> Result<(), h2::Error> {
    while !bytes.is_empty() {
        send.reserve_capacity(bytes.len());
        let Some(capacity) = poll_fn(|cx| send.poll_capacity(cx)).await else {
            return Ok(());
        };
        let amount = capacity?.min(bytes.len());
        if amount > 0 {
            send.send_data(bytes.split_to(amount), false)?;
        }
    }
    Ok(())
}

async fn serve(
    mut recv: h2::RecvStream,
    mut respond: h2::server::SendResponse<Bytes>,
    target: String,
    sent_bytes: Arc<AtomicUsize>,
) {
    if target.starts_with("reset.") {
        respond.send_reset(Reason::REFUSED_STREAM);
        return;
    }
    if target.starts_with("slow.") {
        std::future::pending::<()>().await;
    }
    let status = target
        .strip_suffix(".test:443")
        .and_then(|name| name.parse::<u16>().ok())
        .unwrap_or(200);
    let response = http::Response::builder().status(status).body(()).unwrap();
    let Ok(mut send) = respond.send_response(response, status != 200) else {
        return;
    };
    if status != 200 {
        return;
    }
    if target.starts_with("greeting.")
        && send_data(&mut send, Bytes::from_static(b"upstream early"))
            .await
            .is_err()
    {
        return;
    }
    if target.starts_with("flood.") {
        for _ in 0..1024 {
            if send_data(&mut send, Bytes::from(vec![0x5a; 16 * 1024]))
                .await
                .is_err()
            {
                return;
            }
            sent_bytes.fetch_add(16 * 1024, Ordering::SeqCst);
        }
    }
    let halfclose = target.starts_with("halfclose.");
    let mut collected = Vec::new();
    while let Some(Ok(data)) = recv.data().await {
        let size = data.len();
        if halfclose {
            collected.extend_from_slice(&data);
        } else if send_data(&mut send, data).await.is_err() {
            return;
        }
        if recv.flow_control().release_capacity(size).is_err() {
            return;
        }
    }
    if halfclose && send_data(&mut send, Bytes::from(collected)).await.is_err() {
        return;
    }
    let _ = send.send_data(Bytes::new(), true);
}
