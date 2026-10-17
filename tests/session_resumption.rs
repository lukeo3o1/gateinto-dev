mod common;

use std::sync::Arc;

use common::{TestServer, connect};
use gateinto::tls::{ClientCertificateResolver, TlsMode, client_config};
use rustls::HandshakeKind;
use rustls::crypto::aws_lc_rs;

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

    let (_first_client, first_server, result) = connect(client.clone(), server_config.clone());
    result.unwrap();
    assert_eq!(first_server.handshake_kind(), Some(HandshakeKind::Full));

    let (second_client, second_server, result) = connect(client, server_config);
    result.unwrap();
    assert_eq!(second_server.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(second_client.handshake_kind(), Some(HandshakeKind::Full));
}
