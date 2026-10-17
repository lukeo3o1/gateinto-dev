#[allow(dead_code)]
mod fixture;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use fixture::*;
use gateinto::identity::client_cert::{
    CertificateSource, ClientAuth, ClientAuthError, ClientCertificateMode,
    ClientCertificateOptions, ClientIdentityStore, configure,
};
use gateinto::identity::device_key::{Backend, KeyName, KeyStore, StoreError};
use gateinto::identity::encoding::P256Point;
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
