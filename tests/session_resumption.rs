mod common;

use std::sync::Arc;

use common::{TestServer, connect};
use gateinto::tls::{ClientCertificateResolver, TlsMode, client_config};
use rustls::crypto::aws_lc_rs;
use rustls::{ClientConnection, HandshakeKind, ServerConnection};

fn deliver_tickets(server: &mut ServerConnection, client: &mut ClientConnection) {
    let mut buffer = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut buffer).unwrap();
    }
    let mut pending = buffer.as_slice();
    while !pending.is_empty() {
        client.read_tls(&mut pending).unwrap();
    }
    client.process_new_packets().unwrap();
}

#[test]
fn upstream_handshakes_are_never_resumed() {
    let server = TestServer::new();
    let server_config = server.config(aws_lc_rs::default_provider(), None);
    let client = client_config(
        TlsMode::default(),
        server.roots(),
        Arc::new(ClientCertificateResolver::new(None)),
    )
    .unwrap();
    assert!(!client.enable_early_data);

    let (mut first_client, mut first_server, result) =
        connect(client.clone(), server_config.clone());
    result.unwrap();
    deliver_tickets(&mut first_server, &mut first_client);
    assert_eq!(first_server.handshake_kind(), Some(HandshakeKind::Full));

    let (second_client, second_server, result) = connect(client, server_config);
    result.unwrap();
    assert_eq!(second_server.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(second_client.handshake_kind(), Some(HandshakeKind::Full));
}
