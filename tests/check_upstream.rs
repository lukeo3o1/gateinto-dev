#[allow(dead_code)]
mod fixture;

use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use fixture::*;
use gateinto::check::{CheckOptions, ClientCertificateUse, check_upstream};
use gateinto::http::Authority;
use gateinto::tls::TlsMode;
use rcgen::KeyPair;
use rustls::crypto::SupportedKxGroup;
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::sign::CertifiedKey;
use rustls::{NamedGroup, ProtocolVersion, ServerConfig};

struct Setup {
    ca: TestCa,
    upstream: UpstreamProxy,
}

impl Setup {
    async fn start(config: Arc<ServerConfig>, ca: TestCa, behavior: Behavior) -> Self {
        let upstream = UpstreamProxy::start(config, behavior).await;
        Self { ca, upstream }
    }

    async fn with_groups(groups: &[&'static dyn SupportedKxGroup], behavior: Behavior) -> Self {
        let ca = TestCa::new();
        let config = ca.server_config_with_groups(PROXY_NAME, groups);
        Self::start(config, ca, behavior).await
    }

    fn options(&self, mode: TlsMode) -> CheckOptions {
        let config = agent_config(self.upstream.addr, self.ca.roots(), PROXY_NAME);
        CheckOptions {
            upstream: config.upstream,
            tls_mode: mode,
            client_certificate: None,
            target: None,
            timeout: Duration::from_secs(5),
            max_header_bytes: 16384,
        }
    }

    fn command(&self, extra: &[&str]) -> (bool, String, String) {
        let ca_file = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "check-{}-{}-ca.pem",
            std::process::id(),
            self.upstream.addr.port()
        ));
        std::fs::write(&ca_file, self.ca.pem()).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_gateinto"))
            .args(["check-upstream", "--upstream-host", "127.0.0.1"])
            .args(["--upstream-port", &self.upstream.addr.port().to_string()])
            .args(["--upstream-server-name", PROXY_NAME])
            .arg("--ca-file")
            .arg(&ca_file)
            .args(extra)
            .output()
            .unwrap();
        (
            output.status.success(),
            String::from_utf8(output.stdout).unwrap(),
            String::from_utf8(output.stderr).unwrap(),
        )
    }
}

fn authority(addr: SocketAddr) -> Authority {
    addr.to_string().parse().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn reports_the_negotiated_parameters_of_a_hybrid_upstream() {
    let setup = Setup::with_groups(HYBRID_GROUPS, Behavior::Tunnel).await;

    let report = check_upstream(setup.options(TlsMode::HybridPreferred))
        .await
        .unwrap();

    assert_eq!(report.protocol_version, ProtocolVersion::TLSv1_3);
    assert_eq!(report.key_exchange_group, NamedGroup::X25519MLKEM768);
    assert!(
        format!("{:?}", report.cipher_suite).starts_with("TLS13_"),
        "{:?}",
        report.cipher_suite
    );
    assert_eq!(
        report.server_certificate_subject,
        "CN=rcgen self signed cert"
    );
    assert_eq!(
        report.client_certificate,
        ClientCertificateUse::NotRequested
    );
    assert_eq!(report.connect_status, None);
    assert!(setup.upstream.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn reports_x25519_for_a_classical_upstream_unless_hybrid_is_required() {
    let setup = Setup::with_groups(CLASSICAL_GROUPS, Behavior::Tunnel).await;

    for mode in [TlsMode::HybridPreferred, TlsMode::ClassicalOnly] {
        let report = check_upstream(setup.options(mode)).await.unwrap();
        assert_eq!(report.key_exchange_group, NamedGroup::X25519);
    }
    let error = check_upstream(setup.options(TlsMode::HybridRequired))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("TLS handshake failed"), "{error}");
}

#[tokio::test(flavor = "multi_thread")]
async fn classical_only_reports_x25519_for_a_hybrid_upstream() {
    let setup = Setup::with_groups(HYBRID_GROUPS, Behavior::Tunnel).await;
    let report = check_upstream(setup.options(TlsMode::ClassicalOnly))
        .await
        .unwrap();
    assert_eq!(report.key_exchange_group, NamedGroup::X25519);
}

#[tokio::test(flavor = "multi_thread")]
async fn untrusted_or_misnamed_upstream_certificates_fail_in_every_mode() {
    let setup = Setup::with_groups(HYBRID_GROUPS, Behavior::Tunnel).await;
    for mode in [
        TlsMode::HybridPreferred,
        TlsMode::HybridRequired,
        TlsMode::ClassicalOnly,
    ] {
        let mut options = setup.options(mode);
        options.upstream.roots = TestCa::new().roots();
        let error = check_upstream(options).await.unwrap_err().to_string();
        assert!(error.contains("invalid peer certificate"), "{error}");

        let mut options = setup.options(mode);
        options.upstream.server_name = "other.test".try_into().unwrap();
        let error = check_upstream(options).await.unwrap_err().to_string();
        assert!(error.contains("invalid peer certificate"), "{error}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn target_sends_connect_and_reports_the_status_line() {
    let setup = Setup::with_groups(HYBRID_GROUPS, Behavior::Tunnel).await;
    let target = echo_server().await;
    let mut options = setup.options(TlsMode::HybridPreferred);
    options.target = Some(authority(target));

    let report = check_upstream(options).await.unwrap();

    assert_eq!(
        report.connect_status,
        Some((200, "HTTP/1.1 200 Connection established".to_owned()))
    );
    assert_eq!(
        setup.upstream.requests(),
        [format!(
            "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n"
        )]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn refused_connect_reports_only_the_status_line() {
    let setup = Setup::with_groups(HYBRID_GROUPS, Behavior::Status(407)).await;
    let mut options = setup.options(TlsMode::HybridPreferred);
    options.target = Some("example.test:443".parse().unwrap());

    let report = check_upstream(options).await.unwrap();

    assert_eq!(
        report.connect_status,
        Some((407, "HTTP/1.1 407 Fixture".to_owned()))
    );
    assert!(!report.to_string().contains(SECRET), "{report}");
}

fn certified_key(certificate: &IssuedCertificate, key: &KeyPair) -> Arc<CertifiedKey> {
    let der = PrivatePkcs8KeyDer::from(key.serialize_der()).into();
    let signer = rustls::crypto::aws_lc_rs::sign::any_ecdsa_type(&der).unwrap();
    Arc::new(CertifiedKey::new(vec![certificate.der.clone()], signer))
}

#[tokio::test(flavor = "multi_thread")]
async fn reports_whether_a_client_certificate_was_sent() {
    let ca = TestCa::new();
    let client_ca = TestCa::new();
    let config = ca.server_config_requesting_client_certificates(PROXY_NAME, &client_ca);
    let setup = Setup::start(config, ca, Behavior::Tunnel).await;
    let target = echo_server().await;

    let mut options = setup.options(TlsMode::HybridPreferred);
    options.target = Some(authority(target));
    let report = check_upstream(options).await.unwrap();
    assert_eq!(
        report.client_certificate,
        ClientCertificateUse::RequestedNoneSent
    );

    let key = KeyPair::generate().unwrap();
    let certificate = client_ca.issue_client_certificate(&key);
    let mut options = setup.options(TlsMode::HybridPreferred);
    options.target = Some(authority(target));
    options.client_certificate = Some(certified_key(&certificate, &key));
    let report = check_upstream(options).await.unwrap();
    assert_eq!(report.client_certificate, ClientCertificateUse::Sent);
    assert_eq!(
        setup.upstream.client_certificates(),
        [vec![certificate.der]]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn command_prints_the_negotiated_group_of_each_fixture() {
    for (groups, mode, expected) in [
        (HYBRID_GROUPS, "hybrid_preferred", "X25519MLKEM768"),
        (HYBRID_GROUPS, "hybrid_required", "X25519MLKEM768"),
        (HYBRID_GROUPS, "classical_only", "X25519"),
        (CLASSICAL_GROUPS, "hybrid_preferred", "X25519"),
        (CLASSICAL_GROUPS, "classical_only", "X25519"),
    ] {
        let setup = Setup::with_groups(groups, Behavior::Tunnel).await;
        let (success, stdout, stderr) = tokio::task::spawn_blocking(move || {
            setup.command(&["--tls-mode", mode, "--client-certificate", "off"])
        })
        .await
        .unwrap();
        assert!(success, "{mode}: {stdout}{stderr}");
        assert!(
            stdout
                .lines()
                .any(|line| line == format!("key-exchange-group: {expected}")),
            "{mode}: {stdout}"
        );
        assert!(stdout.contains("tls-version: TLSv1_3\n"), "{stdout}");
        assert!(stdout.contains(&format!("tls-mode: {mode}\n")), "{stdout}");
        assert!(stdout.contains("cipher-suite: TLS13_"), "{stdout}");
        assert!(
            stdout.contains("server-certificate-subject: CN=rcgen self signed cert\n"),
            "{stdout}"
        );
        assert!(
            stdout.contains("client-certificate: not requested\n"),
            "{stdout}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn command_fails_when_hybrid_is_required_but_unavailable() {
    let setup = Setup::with_groups(CLASSICAL_GROUPS, Behavior::Tunnel).await;
    let (success, stdout, stderr) = tokio::task::spawn_blocking(move || {
        setup.command(&[
            "--tls-mode",
            "hybrid_required",
            "--client-certificate",
            "off",
        ])
    })
    .await
    .unwrap();
    assert!(!success, "{stdout}");
    assert!(!stdout.contains("key-exchange-group"), "{stdout}");
    assert!(stderr.contains("TLS handshake failed"), "{stderr}");
}

#[tokio::test(flavor = "multi_thread")]
async fn command_prints_the_connect_status_line_and_fails_on_refusal() {
    let target = echo_server().await.to_string();
    let setup = Setup::with_groups(HYBRID_GROUPS, Behavior::Tunnel).await;
    let accepted = target.clone();
    let (success, stdout, stderr) = tokio::task::spawn_blocking(move || {
        setup.command(&["--target", &accepted, "--client-certificate", "off"])
    })
    .await
    .unwrap();
    assert!(success, "{stdout}{stderr}");
    assert!(
        stdout.contains(&format!("connect-target: {target}\n")),
        "{stdout}"
    );
    assert!(
        stdout.contains("connect-status: HTTP/1.1 200 Connection established\n"),
        "{stdout}"
    );

    let setup = Setup::with_groups(HYBRID_GROUPS, Behavior::Status(407)).await;
    let (success, stdout, stderr) = tokio::task::spawn_blocking(move || {
        setup.command(&[
            "--target",
            "example.test:443",
            "--client-certificate",
            "off",
        ])
    })
    .await
    .unwrap();
    assert!(!success, "{stdout}");
    assert!(
        stdout.contains("connect-status: HTTP/1.1 407 Fixture\n"),
        "{stdout}"
    );
    assert!(stderr.contains("407"), "{stderr}");
    assert!(!stdout.contains(SECRET) && !stderr.contains(SECRET));
}

#[tokio::test(flavor = "multi_thread")]
async fn command_fails_for_an_unreachable_upstream_or_untrusted_ca() {
    let unreachable = unused_port().await;
    let output = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_gateinto"))
            .args(["check-upstream", "--upstream-host", "127.0.0.1"])
            .args(["--upstream-port", &unreachable.port().to_string()])
            .args(["--client-certificate", "off"])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("connect failed"));

    let setup = Setup::with_groups(HYBRID_GROUPS, Behavior::Tunnel).await;
    let port = setup.upstream.addr.port();
    let output = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_gateinto"))
            .args(["check-upstream", "--upstream-host", "127.0.0.1"])
            .args(["--upstream-port", &port.to_string()])
            .args(["--upstream-server-name", PROXY_NAME])
            .args(["--client-certificate", "off"])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("invalid peer certificate"), "{stderr}");
}

#[test]
fn command_rejects_a_malformed_target() {
    let output = Command::new(env!("CARGO_BIN_EXE_gateinto"))
        .args(["check-upstream", "--upstream-host", "127.0.0.1"])
        .args(["--upstream-port", "9", "--target", "no-port"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--target"));
}
