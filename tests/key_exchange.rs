mod common;

use std::sync::Arc;

use common::{TestServer, connect};
use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::{self, kx_group};
use rustls::{ClientConfig, Error, NamedGroup, PeerIncompatible, ProtocolVersion};

fn server_provider(groups: &[&'static dyn rustls::crypto::SupportedKxGroup]) -> CryptoProvider {
    CryptoProvider {
        kx_groups: groups.to_vec(),
        ..aws_lc_rs::default_provider()
    }
}

fn client_config(server: &TestServer) -> ClientConfig {
    ClientConfig::builder_with_provider(Arc::new(
        gateinto::tls::TlsMode::default().crypto_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(server.roots())
    .with_no_client_auth()
}

#[test]
fn negotiates_x25519mlkem768_when_server_supports_it() {
    let server = TestServer::new();
    let server_config = server.config(aws_lc_rs::default_provider(), None);

    let (client, _, result) = connect(client_config(&server), server_config);

    result.unwrap();
    assert_eq!(client.protocol_version(), Some(ProtocolVersion::TLSv1_3));
    assert_eq!(
        client.negotiated_key_exchange_group().unwrap().name(),
        NamedGroup::X25519MLKEM768
    );
}

#[test]
fn falls_back_to_x25519_when_server_lacks_hybrid_group() {
    let server = TestServer::new();
    let server_config = server.config(server_provider(&[kx_group::X25519]), None);

    let (client, _, result) = connect(client_config(&server), server_config);

    result.unwrap();
    assert_eq!(
        client.negotiated_key_exchange_group().unwrap().name(),
        NamedGroup::X25519
    );
}

#[test]
fn refuses_groups_other_than_x25519mlkem768_and_x25519() {
    let server = TestServer::new();
    let server_config = server.config(server_provider(&[kx_group::SECP256R1]), None);

    let (_, _, result) = connect(client_config(&server), server_config);

    assert_eq!(
        result.unwrap_err(),
        Error::PeerIncompatible(PeerIncompatible::NoKxGroupsInCommon)
    );
}
