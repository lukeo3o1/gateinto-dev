#[allow(dead_code)]
mod fixture;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use fixture::*;
use gateinto::identity::client_cert::{
    CertificateSource, ClientAuth, ClientAuthError, ClientCertificate, ClientCertificateMode,
    ClientCertificateOptions, ClientIdentityStore, configure,
};
use gateinto::identity::device_key::{Backend, KeyName, KeyStore, StoreError};
use gateinto::identity::encoding::{P256Point, sha256_fingerprint};
use gateinto::identity::x509::parse_certificate;
use rcgen::{KeyPair, PublicKeyData};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::sign::{CertifiedKey, SigningKey};
use tokio::io::AsyncWriteExt;

const CLOSE_WITHIN: Duration = Duration::from_secs(5);

struct SoftwareStore {
    key: KeyPair,
}

impl SoftwareStore {
    fn new() -> Self {
        Self {
            key: KeyPair::generate().unwrap(),
        }
    }
}

impl KeyStore for SoftwareStore {
    type Key = ();

    fn open(&self, backend: Backend, _: &KeyName) -> Result<(), StoreError> {
        match backend {
            Backend::Software => Ok(()),
            Backend::Tpm => Err(StoreError::NotFound),
        }
    }

    fn create(&self, _: Backend, _: &KeyName) -> Result<(), StoreError> {
        Err(StoreError::Failed(
            "the proxy path must not create keys".to_owned(),
        ))
    }

    fn delete(&self, _: ()) -> Result<(), StoreError> {
        Err(StoreError::Failed(
            "the proxy path must not delete keys".to_owned(),
        ))
    }

    fn public_point(&self, _: &()) -> Result<P256Point, StoreError> {
        Ok(self.key.der_bytes().try_into().unwrap())
    }

    fn sign_digest(&self, _: &(), _: &[u8]) -> Result<Vec<u8>, StoreError> {
        Err(StoreError::Failed(
            "TLS signs through signing_key".to_owned(),
        ))
    }
}

impl ClientIdentityStore for SoftwareStore {
    fn signing_key(&self, _: ()) -> Result<Arc<dyn SigningKey>, StoreError> {
        let der = PrivatePkcs8KeyDer::from(self.key.serialize_der()).into();
        rustls::crypto::aws_lc_rs::sign::any_ecdsa_type(&der)
            .map_err(|error| StoreError::Failed(error.to_string()))
    }

    fn client_certificates(&self) -> Result<Vec<CertificateDer<'static>>, StoreError> {
        Ok(Vec::new())
    }
}

fn write_temp(name: &str, contents: &str) -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("mtls-{}-{n}-{name}", std::process::id()));
    std::fs::write(&path, contents).unwrap();
    path
}

fn identity(
    store: &SoftwareStore,
    certificate: &IssuedCertificate,
) -> Result<Arc<CertifiedKey>, ClientAuthError> {
    let options = ClientCertificateOptions {
        mode: ClientCertificateMode::Required,
        key_name: KeyName::default(),
        source: CertificateSource::File(write_temp("client.pem", &certificate.pem)),
    };
    match configure(&options, Ok(store), UnixTime::now())? {
        ClientAuth::Enabled(identity) => Ok(identity.certified_key),
        other => panic!("required client auth resolved to {other:?}"),
    }
}

struct Setup {
    server_ca: TestCa,
    client_ca: TestCa,
    upstream: UpstreamProxy,
}

impl Setup {
    async fn new() -> Self {
        let server_ca = TestCa::new();
        let client_ca = TestCa::new();
        let upstream = UpstreamProxy::start(
            server_ca.server_config_requiring_client_certificates(PROXY_NAME, &client_ca),
            Behavior::Tunnel,
        )
        .await;
        Self {
            server_ca,
            client_ca,
            upstream,
        }
    }

    async fn agent(&self, client_certificate: Option<Arc<CertifiedKey>>) -> std::net::SocketAddr {
        let mut config = agent_config(self.upstream.addr, self.server_ca.roots(), PROXY_NAME);
        config.client_certificate = client_certificate.map(Into::into);
        start_agent(config).await
    }
}

async fn assert_bad_gateway(agent: std::net::SocketAddr) {
    let target = echo_server().await;
    let (mut stream, response) = send(agent, &connect_request(&target.to_string())).await;
    assert_eq!(response.status, 502, "{}", response.head);
    read_to_end_within(&mut stream, CLOSE_WITHIN).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_requiring_client_certificates_rejects_an_agent_without_one() {
    let setup = Setup::new().await;

    assert_bad_gateway(setup.agent(None).await).await;

    assert!(setup.upstream.requests().is_empty());
    assert!(setup.upstream.client_certificates().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_presents_the_certificate_bound_to_the_device_key() {
    let setup = Setup::new().await;
    let store = SoftwareStore::new();
    let certificate = setup.client_ca.issue_client_certificate(&store.key);
    let agent = setup
        .agent(Some(identity(&store, &certificate).unwrap()))
        .await;
    let target = echo_server().await;

    let mut stream = open_tunnel(agent, target).await;
    stream.write_all(b"authenticated").await.unwrap();
    stream.shutdown().await.unwrap();

    assert_eq!(
        read_to_end_within(&mut stream, CLOSE_WITHIN).await,
        b"authenticated"
    );
    assert_eq!(
        setup.upstream.client_certificates(),
        vec![vec![certificate.der]]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn certificate_for_another_key_is_refused_before_connecting() {
    let setup = Setup::new().await;
    let store = SoftwareStore::new();
    let other = KeyPair::generate().unwrap();
    let certificate = setup.client_ca.issue_client_certificate(&other);

    let error = identity(&store, &certificate).unwrap_err();

    assert!(matches!(error, ClientAuthError::Mismatch { .. }), "{error}");
    assert!(
        error
            .to_string()
            .contains("does not belong to the device key"),
        "{error}"
    );
    assert!(setup.upstream.requests().is_empty());
    assert!(setup.upstream.client_certificates().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn certificate_from_an_untrusted_ca_is_rejected_by_the_upstream() {
    let setup = Setup::new().await;
    let store = SoftwareStore::new();
    let certificate = TestCa::new().issue_client_certificate(&store.key);
    let agent = setup
        .agent(Some(identity(&store, &certificate).unwrap()))
        .await;

    assert_bad_gateway(agent).await;

    assert!(setup.upstream.requests().is_empty());
    assert!(setup.upstream.client_certificates().is_empty());
}

fn self_signed_identity(store: &SoftwareStore) -> ClientCertificate {
    let options = ClientCertificateOptions {
        mode: ClientCertificateMode::Required,
        key_name: KeyName::default(),
        source: CertificateSource::SelfSigned,
    };
    configure(&options, Ok(store), UnixTime::now())
        .unwrap()
        .into_client_certificate()
        .unwrap()
}

async fn tunnel_with(
    upstream: &UpstreamProxy,
    server_ca: &TestCa,
    certificate: ClientCertificate,
) -> Vec<u8> {
    let mut config = agent_config(upstream.addr, server_ca.roots(), PROXY_NAME);
    config.client_certificate = Some(certificate);
    let agent = start_agent(config).await;
    let target = echo_server().await;
    let (mut stream, response) = send(agent, &connect_request(&target.to_string())).await;
    if response.status != 200 {
        read_to_end_within(&mut stream, CLOSE_WITHIN).await;
        return Vec::new();
    }
    stream.write_all(b"self-signed").await.unwrap();
    stream.shutdown().await.unwrap();
    read_to_end_within(&mut stream, CLOSE_WITHIN).await
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_trusting_the_device_spki_accepts_each_self_signed_certificate() {
    let store = SoftwareStore::new();
    let spki = store.key.subject_public_key_info();
    let server_ca = TestCa::new();
    let upstream = UpstreamProxy::start(
        server_ca.server_config_trusting_client_spki(PROXY_NAME, spki.clone()),
        Behavior::Tunnel,
    )
    .await;

    for _ in 0..2 {
        let echoed = tunnel_with(&upstream, &server_ca, self_signed_identity(&store)).await;
        assert_eq!(echoed, b"self-signed");
    }

    let presented = upstream.client_certificates();
    assert_eq!(presented.len(), 2);
    assert!(presented.iter().all(|chain| chain.len() == 1));
    let (first, second) = (&presented[0][0], &presented[1][0]);
    assert_ne!(sha256_fingerprint(first), sha256_fingerprint(second));
    for certificate in [first, second] {
        let parsed = parse_certificate(certificate).unwrap();
        assert_eq!(parsed.spki, spki);
        assert_eq!(parsed.subject, "CN=Gateinto device");
    }
    assert_eq!(upstream.requests().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn required_expired_self_signed_certificate_fails_locally_without_connecting() {
    let key = KeyPair::generate().unwrap();
    let server_ca = TestCa::new();
    let client_ca = TestCa::new();
    let upstream = UpstreamProxy::start(
        server_ca.server_config_requesting_client_certificates(PROXY_NAME, &client_ca),
        Behavior::Tunnel,
    )
    .await;
    let mut config = agent_config(upstream.addr, server_ca.roots(), PROXY_NAME);
    config.client_certificate = Some(ClientCertificate::SelfSigned {
        certificates: expired_self_signed_certificates(&key),
        required: true,
    });

    assert_bad_gateway(start_agent(config).await).await;

    assert!(upstream.negotiated_groups().is_empty());
    assert!(upstream.client_certificates().is_empty());
    assert!(upstream.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn optional_expired_self_signed_certificate_is_not_sent() {
    let key = KeyPair::generate().unwrap();
    let server_ca = TestCa::new();
    let client_ca = TestCa::new();
    let upstream = UpstreamProxy::start(
        server_ca.server_config_requesting_client_certificates(PROXY_NAME, &client_ca),
        Behavior::Tunnel,
    )
    .await;

    let echoed = tunnel_with(
        &upstream,
        &server_ca,
        ClientCertificate::SelfSigned {
            certificates: expired_self_signed_certificates(&key),
            required: false,
        },
    )
    .await;

    assert_eq!(echoed, b"self-signed");
    assert!(upstream.client_certificates().is_empty());
    assert_eq!(upstream.requests().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_trusting_another_spki_rejects_the_self_signed_certificate() {
    let store = SoftwareStore::new();
    let other = KeyPair::generate().unwrap();
    let server_ca = TestCa::new();
    let upstream = UpstreamProxy::start(
        server_ca.server_config_trusting_client_spki(PROXY_NAME, other.subject_public_key_info()),
        Behavior::Tunnel,
    )
    .await;

    let echoed = tunnel_with(&upstream, &server_ca, self_signed_identity(&store)).await;

    assert!(echoed.is_empty());
    assert!(upstream.requests().is_empty());
    assert!(upstream.client_certificates().is_empty());
    assert_eq!(upstream.wait_for_handshake_errors(1).await.len(), 1);
}
