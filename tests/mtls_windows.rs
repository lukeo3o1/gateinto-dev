#![cfg(windows)]
mod isolated;

#[allow(dead_code)]
mod fixture;

use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fixture::*;
use gateinto::identity::client_cert::{
    CertificateSource, ClientAuth, ClientCertificateMode, ClientCertificateOptions, ClientIdentity,
    configure,
};
use gateinto::identity::device_key::{self, Backend, InitOptions, KeyName};
use gateinto::identity::encoding::sha256_fingerprint;
use gateinto::identity::windows_cng::{
    CngStore, PLATFORM_CRYPTO_PROVIDER, SOFTWARE_KEY_STORAGE_PROVIDER, delete_key,
};
use gateinto::identity::x509::parse_certificate;
use rcgen::PublicKeyData;
use rustls::pki_types::UnixTime;
use rustls_cng::store::{CertStore, CertStoreType};
use tokio::io::AsyncWriteExt;
use windows_sys::Win32::Security::Cryptography::{
    CERT_CONTEXT, CERT_STORE_ADD_NEW, CertAddEncodedCertificateToStore,
    CertDeleteCertificateFromStore, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};

const CLOSE_WITHIN: Duration = Duration::from_secs(5);

fn unique(prefix: &str) -> String {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!(
        "{prefix}-{}-{nanos}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

struct TestKey(KeyName);

impl Drop for TestKey {
    fn drop(&mut self) {
        let _ = delete_key(PLATFORM_CRYPTO_PROVIDER, self.0.as_str());
        let _ = delete_key(SOFTWARE_KEY_STORAGE_PROVIDER, self.0.as_str());
    }
}

struct DevicePublicKey(Vec<u8>);

impl PublicKeyData for DevicePublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

fn create_device_key() -> (TestKey, DevicePublicKey) {
    let key = TestKey(unique("gateinto-test-mtls").parse().unwrap());
    let options = InitOptions {
        backend: Backend::Software,
        ..InitOptions::default()
    };
    let (created, _) = device_key::init(&CngStore, &key.0, options).unwrap();
    assert_eq!(created.backend, Backend::Software);
    (key, DevicePublicKey(created.point.to_vec()))
}

struct TempFile(PathBuf);

impl TempFile {
    fn new(contents: &str) -> Self {
        let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(unique("mtls-client") + ".pem");
        std::fs::write(&path, contents).unwrap();
        Self(path)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

struct ImportedCertificate {
    _store: CertStore,
    context: *const CERT_CONTEXT,
}

impl ImportedCertificate {
    fn import(der: &[u8]) -> Self {
        let store = CertStore::open(CertStoreType::CurrentUser, "My").unwrap();
        let mut context: *mut CERT_CONTEXT = ptr::null_mut();
        let added = unsafe {
            CertAddEncodedCertificateToStore(
                store.inner(),
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                der.as_ptr(),
                der.len() as u32,
                CERT_STORE_ADD_NEW,
                &mut context,
            )
        };
        assert_ne!(added, 0, "{}", std::io::Error::last_os_error());
        Self {
            _store: store,
            context,
        }
    }
}

impl Drop for ImportedCertificate {
    fn drop(&mut self) {
        unsafe { CertDeleteCertificateFromStore(self.context) };
    }
}

fn required(key: &TestKey, source: CertificateSource) -> ClientIdentity {
    let options = ClientCertificateOptions {
        mode: ClientCertificateMode::Required,
        key_name: key.0.clone(),
        source,
    };
    match configure(&options, Ok(&CngStore), UnixTime::now()).unwrap() {
        ClientAuth::Enabled(identity) => identity,
        other => panic!("required client auth resolved to {other:?}"),
    }
}

async fn tunnel_through_mtls_upstream(
    identity: ClientIdentity,
    client_ca: &TestCa,
) -> UpstreamProxy {
    let server_ca = TestCa::new();
    let upstream = UpstreamProxy::start(
        server_ca.server_config_requiring_client_certificates(PROXY_NAME, client_ca),
        Behavior::Tunnel,
    )
    .await;
    tunnel(identity, &server_ca, &upstream).await;
    upstream
}

async fn tunnel(identity: ClientIdentity, server_ca: &TestCa, upstream: &UpstreamProxy) {
    let mut config = agent_config(upstream.addr, server_ca.roots(), PROXY_NAME);
    config.client_certificate = ClientAuth::Enabled(identity).into_client_certificate();
    let agent = start_agent(config).await;

    let mut stream = open_tunnel(agent, echo_server().await).await;
    stream.write_all(b"signed by cng").await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(
        read_to_end_within(&mut stream, CLOSE_WITHIN).await,
        b"signed by cng"
    );
}

fn key_info(args: &[&str]) -> String {
    let output = isolated::gateinto()
        .args(["key", "info"])
        .args(args)
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success(), "{stdout}{stderr}");
    stdout
}

fn field<'a>(output: &'a str, name: &str) -> &'a str {
    output
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(": "))
        .unwrap_or_else(|| panic!("no {name} in {output}"))
}

#[tokio::test(flavor = "multi_thread")]
async fn client_certificate_file_authenticates_with_the_cng_device_key() {
    let (key, public_key) = create_device_key();
    let client_ca = TestCa::new();
    let certificate = client_ca.issue_client_certificate(&public_key);
    let file = TempFile::new(&certificate.pem);

    let identity = required(&key, CertificateSource::File(file.0.clone()));
    assert_eq!(identity.backend, Backend::Software);
    assert_eq!(
        identity.binding.source,
        CertificateSource::File(file.0.clone())
    );
    let upstream = tunnel_through_mtls_upstream(identity, &client_ca).await;

    assert_eq!(
        upstream.client_certificates(),
        vec![vec![certificate.der.clone()]]
    );
    let info = key_info(&[
        "--name",
        key.0.as_str(),
        "--client-cert-file",
        file.0.to_str().unwrap(),
    ]);
    assert_eq!(
        field(&info, "client-certificate-sha1"),
        parse_certificate(&certificate.der).unwrap().sha1_thumbprint
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn client_certificate_is_found_in_the_user_store_by_its_public_key() {
    let (key, public_key) = create_device_key();
    let client_ca = TestCa::new();
    let certificate = client_ca.issue_client_certificate(&public_key);
    assert_eq!(
        key_info(&["--name", key.0.as_str()])
            .lines()
            .last()
            .unwrap(),
        "client-certificate: none"
    );
    let _imported = ImportedCertificate::import(&certificate.der);

    let identity = required(&key, CertificateSource::Store);
    assert_eq!(identity.binding.source, CertificateSource::Store);
    let upstream = tunnel_through_mtls_upstream(identity, &client_ca).await;

    assert_eq!(
        upstream.client_certificates(),
        vec![vec![certificate.der.clone()]]
    );
    let info = key_info(&["--name", key.0.as_str()]);
    assert_eq!(
        field(&info, "client-certificate-sha1"),
        parse_certificate(&certificate.der).unwrap().sha1_thumbprint
    );
    assert_eq!(field(&info, "client-certificate-source"), "CurrentUser\\My");
}

#[tokio::test(flavor = "multi_thread")]
async fn self_signed_certificates_are_signed_by_the_cng_device_key() {
    let (key, public_key) = create_device_key();
    let spki = public_key.subject_public_key_info();
    let server_ca = TestCa::new();
    let upstream = UpstreamProxy::start(
        server_ca.server_config_trusting_client_spki(PROXY_NAME, spki.clone()),
        Behavior::Tunnel,
    )
    .await;

    for _ in 0..2 {
        let identity = required(&key, CertificateSource::SelfSigned);
        assert_eq!(identity.backend, Backend::Software);
        assert_eq!(identity.binding.source, CertificateSource::SelfSigned);
        assert_eq!(identity.binding.leaf.spki, spki);
        tunnel(identity, &server_ca, &upstream).await;
    }

    let presented = upstream.client_certificates();
    assert_eq!(presented.len(), 2);
    assert!(presented.iter().all(|chain| chain.len() == 1));
    let (first, second) = (&presented[0][0], &presented[1][0]);
    assert_ne!(sha256_fingerprint(first), sha256_fingerprint(second));
    for certificate in [first, second] {
        assert_eq!(parse_certificate(certificate).unwrap().spki, spki);
    }
}
