#![cfg(windows)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use common::{TestServer, connect};
use gateinto::identity::windows_cng::{
    SOFTWARE_KEY_STORAGE_PROVIDER, create_ecdsa_p256_key, delete_key, export_public_key, open_key,
};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    PublicKeyData,
};
use rustls::client::ResolvesClientCert;
use rustls::pki_types::CertificateDer;
use rustls::server::WebPkiClientVerifier;
use rustls::sign::{CertifiedKey, SigningKey};
use rustls::{ClientConfig, NamedGroup, RootCertStore, SignatureAlgorithm, SignatureScheme};
use rustls_cng::key::SignaturePadding;
use rustls_cng::signer::CngSigningKey;

struct TestKeyName(String);

impl TestKeyName {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        Self(format!(
            "gateinto-test-{}-{}-{}",
            std::process::id(),
            nanos,
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
    }
}

impl Drop for TestKeyName {
    fn drop(&mut self) {
        let _ = delete_key(SOFTWARE_KEY_STORAGE_PROVIDER, &self.0);
    }
}

struct CngPublicKey(Vec<u8>);

impl PublicKeyData for CngPublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

#[derive(Debug)]
struct FixedClientCert(Arc<CertifiedKey>);

impl ResolvesClientCert for FixedClientCert {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[test]
fn persisted_key_can_be_reopened_and_deleted() {
    let name = TestKeyName::new();
    let created = create_ecdsa_p256_key(SOFTWARE_KEY_STORAGE_PROVIDER, &name.0).unwrap();
    let created_public_key = export_public_key(&created).unwrap();
    drop(created);

    let opened = open_key(SOFTWARE_KEY_STORAGE_PROVIDER, &name.0).unwrap();
    assert_eq!(export_public_key(&opened).unwrap(), created_public_key);
    drop(opened);

    delete_key(SOFTWARE_KEY_STORAGE_PROVIDER, &name.0).unwrap();
    assert!(open_key(SOFTWARE_KEY_STORAGE_PROVIDER, &name.0).is_err());
}

#[test]
fn creating_an_existing_key_fails() {
    let name = TestKeyName::new();
    create_ecdsa_p256_key(SOFTWARE_KEY_STORAGE_PROVIDER, &name.0).unwrap();

    assert!(create_ecdsa_p256_key(SOFTWARE_KEY_STORAGE_PROVIDER, &name.0).is_err());
}

#[test]
fn exported_public_key_is_an_uncompressed_p256_point() {
    let name = TestKeyName::new();
    let key = create_ecdsa_p256_key(SOFTWARE_KEY_STORAGE_PROVIDER, &name.0).unwrap();

    let public_key = export_public_key(&key).unwrap();

    assert_eq!(public_key.len(), 65);
    assert_eq!(public_key[0], 0x04);
}

#[test]
fn ncrypt_signature_is_raw_r_and_s() {
    let name = TestKeyName::new();
    let key = create_ecdsa_p256_key(SOFTWARE_KEY_STORAGE_PROVIDER, &name.0).unwrap();
    let public_key = export_public_key(&key).unwrap();
    let message = b"gateinto raw signature";
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, message);

    let signature = key.sign(digest.as_ref(), SignaturePadding::None).unwrap();

    assert_eq!(signature.len(), 64);
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &public_key)
        .verify(message, &signature)
        .unwrap();
}

#[test]
fn rustls_signer_produces_der_ecdsa_p256_sha256_signature() {
    let name = TestKeyName::new();
    let key = create_ecdsa_p256_key(SOFTWARE_KEY_STORAGE_PROVIDER, &name.0).unwrap();
    let public_key = export_public_key(&key).unwrap();
    let signing_key = CngSigningKey::new(key).unwrap();
    let message = b"gateinto tls signature";

    assert_eq!(signing_key.algorithm(), SignatureAlgorithm::ECDSA);
    let signer = signing_key
        .choose_scheme(&[
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
        ])
        .unwrap();
    assert_eq!(signer.scheme(), SignatureScheme::ECDSA_NISTP256_SHA256);
    let signature = signer.sign(message).unwrap();

    assert_eq!(signature[0], 0x30);
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &public_key)
        .verify(message, &signature)
        .unwrap();
}

#[test]
fn rustls_signer_rejects_unsupported_schemes() {
    let name = TestKeyName::new();
    let key = create_ecdsa_p256_key(SOFTWARE_KEY_STORAGE_PROVIDER, &name.0).unwrap();
    let signing_key = CngSigningKey::new(key).unwrap();

    assert!(
        signing_key
            .choose_scheme(&[
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PSS_SHA256
            ])
            .is_none()
    );
}

#[test]
fn tls13_client_authenticates_with_cng_key() {
    let name = TestKeyName::new();
    let key = create_ecdsa_p256_key(SOFTWARE_KEY_STORAGE_PROVIDER, &name.0).unwrap();
    let public_key = CngPublicKey(export_public_key(&key).unwrap());

    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_certificate = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);
    let mut client_params = CertificateParams::new(vec!["gateinto-client".to_owned()]).unwrap();
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_certificate: CertificateDer<'static> = client_params
        .signed_by(&public_key, &issuer)
        .unwrap()
        .into();

    let mut client_roots = RootCertStore::empty();
    client_roots.add(ca_certificate.der().clone()).unwrap();
    let verifier = WebPkiClientVerifier::builder_with_provider(
        Arc::new(client_roots),
        Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
    )
    .build()
    .unwrap();

    let server = TestServer::new();
    let server_config = server.config(
        rustls::crypto::aws_lc_rs::default_provider(),
        Some(verifier),
    );
    let certified_key = CertifiedKey::new(
        vec![client_certificate.clone()],
        Arc::new(CngSigningKey::new(key).unwrap()),
    );
    let client_config =
        ClientConfig::builder_with_provider(Arc::new(gateinto::tls::crypto_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(server.roots())
            .with_client_cert_resolver(Arc::new(FixedClientCert(Arc::new(certified_key))));

    let (client, server, result) = connect(client_config, server_config);

    result.unwrap();
    assert_eq!(
        server.peer_certificates().unwrap(),
        std::slice::from_ref(&client_certificate)
    );
    assert_eq!(
        client.negotiated_key_exchange_group().unwrap().name(),
        NamedGroup::X25519MLKEM768
    );
}
