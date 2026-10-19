use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use rustls::{CipherSuite, NamedGroup, ProtocolVersion};
use tokio::time::timeout;

use crate::http::{Authority, parse_status_line};
use crate::identity::client_cert::ClientCertificate;
use crate::identity::encoding::sha256_fingerprint;
use crate::identity::x509::parse_certificate;
use crate::proxy::{Endpoint, Upstream, UpstreamError, request_tunnel};
use crate::tls::{ClientCertificateResolver, TlsMode};

pub struct CheckOptions {
    pub upstream: Upstream,
    pub tls_mode: TlsMode,
    pub client_certificate: Option<ClientCertificate>,
    pub target: Option<Authority>,
    pub timeout: Duration,
    pub max_header_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientCertificateUse {
    NotRequested,
    RequestedNoneSent,
    Sent,
}

impl fmt::Display for ClientCertificateUse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotRequested => "not requested",
            Self::RequestedNoneSent => "requested by the upstream, none sent",
            Self::Sent => "sent",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfSignedCertificate {
    pub certificate_sha256: String,
    pub device_key_spki_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub upstream: String,
    pub server_name: String,
    pub tls_mode: TlsMode,
    pub protocol_version: ProtocolVersion,
    pub alpn: Option<String>,
    pub key_exchange_group: NamedGroup,
    pub cipher_suite: CipherSuite,
    pub server_certificate_subject: String,
    pub client_certificate: ClientCertificateUse,
    pub self_signed_certificate: Option<SelfSignedCertificate>,
    pub target: Option<Authority>,
    pub connect_status: Option<(u16, String)>,
}

impl Report {
    pub fn connect_refused(&self) -> Option<u16> {
        self.connect_status
            .as_ref()
            .map(|(status, _)| *status)
            .filter(|status| !(200..300).contains(status))
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "upstream: {}", self.upstream)?;
        writeln!(f, "server-name: {}", self.server_name)?;
        writeln!(f, "tls-mode: {}", self.tls_mode)?;
        writeln!(f, "tls-version: {:?}", self.protocol_version)?;
        writeln!(f, "alpn: {}", self.alpn.as_deref().unwrap_or("none"))?;
        writeln!(f, "key-exchange-group: {:?}", self.key_exchange_group)?;
        writeln!(f, "cipher-suite: {:?}", self.cipher_suite)?;
        writeln!(
            f,
            "server-certificate-subject: {}",
            self.server_certificate_subject
        )?;
        writeln!(f, "client-certificate: {}", self.client_certificate)?;
        if let Some(certificate) = &self.self_signed_certificate {
            writeln!(f, "client-certificate-source: self-signed")?;
            writeln!(
                f,
                "client-certificate-sha256: {}",
                certificate.certificate_sha256
            )?;
            writeln!(
                f,
                "device-key-spki-sha256: {}",
                certificate.device_key_spki_sha256
            )?;
        }
        if let Some(target) = &self.target {
            writeln!(f, "connect-target: {target}")?;
        }
        if let Some((_, line)) = &self.connect_status {
            writeln!(f, "connect-status: {line}")?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct CheckError(Kind);

#[derive(Debug)]
enum Kind {
    Config(rustls::Error),
    Upstream(UpstreamError),
    Incomplete(&'static str),
    Timeout(Duration),
}

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Kind::Config(error) => write!(f, "invalid upstream TLS configuration: {error}"),
            Kind::Upstream(error) => write!(f, "upstream check failed: {error}"),
            Kind::Incomplete(missing) => {
                write!(
                    f,
                    "upstream check failed: the handshake reported no {missing}"
                )
            }
            Kind::Timeout(limit) => {
                write!(f, "upstream check did not finish within {limit:?}")
            }
        }
    }
}

impl std::error::Error for CheckError {}

pub async fn check_upstream(options: CheckOptions) -> Result<Report, CheckError> {
    let limit = options.timeout;
    timeout(limit, check(options))
        .await
        .map_err(|_| CheckError(Kind::Timeout(limit)))?
}

async fn check(options: CheckOptions) -> Result<Report, CheckError> {
    let upstream = format!("{}:{}", options.upstream.host, options.upstream.port);
    let server_name = options.upstream.server_name.to_str().into_owned();
    let self_signed = match &options.client_certificate {
        Some(ClientCertificate::SelfSigned { certificates, .. }) => Some(certificates.clone()),
        _ => None,
    };
    let resolver = Arc::new(ClientCertificateResolver::new(options.client_certificate));
    let endpoint = Endpoint::new(options.upstream, options.tls_mode, resolver.clone())
        .map_err(|error| CheckError(Kind::Config(error)))?;
    let upstream_error = |error| CheckError(Kind::Upstream(error));
    let mut tls = endpoint.connect().await.map_err(upstream_error)?;
    let connection = tls.get_ref().1;
    let incomplete = |missing| CheckError(Kind::Incomplete(missing));
    let server_certificate_subject = connection
        .peer_certificates()
        .and_then(|chain| chain.first())
        .map_or_else(
            || "none".to_owned(),
            |leaf| {
                parse_certificate(leaf).map_or_else(
                    |error| format!("unparsable ({error})"),
                    |certificate| certificate.subject,
                )
            },
        );
    let mut report = Report {
        upstream,
        server_name,
        tls_mode: options.tls_mode,
        alpn: connection
            .alpn_protocol()
            .map(|protocol| String::from_utf8_lossy(protocol).into_owned()),
        protocol_version: connection
            .protocol_version()
            .ok_or_else(|| incomplete("protocol version"))?,
        key_exchange_group: connection
            .negotiated_key_exchange_group()
            .ok_or_else(|| incomplete("key exchange group"))?
            .name(),
        cipher_suite: connection
            .negotiated_cipher_suite()
            .ok_or_else(|| incomplete("cipher suite"))?
            .suite(),
        server_certificate_subject,
        client_certificate: match (resolver.requested(), resolver.sent()) {
            (_, true) => ClientCertificateUse::Sent,
            (true, false) => ClientCertificateUse::RequestedNoneSent,
            (false, false) => ClientCertificateUse::NotRequested,
        },
        self_signed_certificate: self_signed.map(|certificates| SelfSignedCertificate {
            certificate_sha256: sha256_fingerprint(
                &resolver
                    .sent_certificate()
                    .unwrap_or_else(|| certificates.current().cert[0].clone()),
            ),
            device_key_spki_sha256: sha256_fingerprint(&certificates.spki()),
        }),
        target: options.target,
        connect_status: None,
    };
    if let Some(target) = &report.target {
        if report.alpn.as_deref() == Some("h2") {
            let (mut sender, _driver) = crate::proxy::h2::connect(tls, options.max_header_bytes)
                .await
                .map_err(upstream_error)?;
            crate::proxy::h2::ready(&mut sender)
                .await
                .map_err(|error| upstream_error(UpstreamError::Http2(error)))?;
            let (status, _stream) = crate::proxy::h2::request(&mut sender, target)
                .map_err(upstream_error)?
                .response()
                .await
                .map_err(upstream_error)?;
            report.connect_status = Some((status, format!("HTTP/2 {status}")));
        } else {
            let (status, _) = request_tunnel(
                &mut tls,
                target,
                options.max_header_bytes,
                parse_status_line,
            )
            .await
            .map_err(upstream_error)?;
            report.connect_status = Some(status);
        }
    }

    Ok(report)
}
