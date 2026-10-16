use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::danger::ClientCertVerifier;
use rustls::{
    ClientConfig, ClientConnection, ConnectionCommon, RootCertStore, ServerConfig, ServerConnection,
};

pub struct TestServer {
    pub certificate: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

impl TestServer {
    pub fn new() -> Self {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        Self {
            certificate: certified.cert.der().clone(),
            key: PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()).into(),
        }
    }

    pub fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(self.certificate.clone()).unwrap();
        roots
    }

    pub fn config(
        &self,
        provider: CryptoProvider,
        client_verifier: Option<Arc<dyn ClientCertVerifier>>,
    ) -> ServerConfig {
        let builder = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap();
        let builder = match client_verifier {
            Some(verifier) => builder.with_client_cert_verifier(verifier),
            None => builder.with_no_client_auth(),
        };
        builder
            .with_single_cert(vec![self.certificate.clone()], self.key.clone_key())
            .unwrap()
    }
}

pub fn connect(
    client: ClientConfig,
    server: ServerConfig,
) -> (
    ClientConnection,
    ServerConnection,
    Result<(), rustls::Error>,
) {
    let mut client =
        ClientConnection::new(Arc::new(client), ServerName::try_from("localhost").unwrap())
            .unwrap();
    let mut server = ServerConnection::new(Arc::new(server)).unwrap();
    let result = handshake(&mut client, &mut server);
    (client, server, result)
}

fn handshake(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> Result<(), rustls::Error> {
    while client.is_handshaking() || server.is_handshaking() {
        let to_server = transfer(client, server);
        server.process_new_packets()?;
        let to_client = transfer(server, client);
        client.process_new_packets()?;
        if to_server == 0 && to_client == 0 {
            return Err(rustls::Error::General("handshake stalled".to_owned()));
        }
    }
    Ok(())
}

fn transfer<A, B>(from: &mut ConnectionCommon<A>, to: &mut ConnectionCommon<B>) -> usize {
    let mut buffer = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut buffer).unwrap();
    }
    let mut pending = buffer.as_slice();
    while !pending.is_empty() {
        to.read_tls(&mut pending).unwrap();
    }
    buffer.len()
}
