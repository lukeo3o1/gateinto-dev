use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rustls::client::{ResolvesClientCert, Resumption};
use rustls::crypto::aws_lc_rs::{self, kx_group};
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::pki_types::pem::{self, PemObject};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, NamedGroup, ProtocolVersion, RootCertStore, SignatureScheme};

use tracing::warn;

use crate::identity::certificates::ExpiredCertificate;
use crate::identity::client_cert::ClientCertificate;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    #[default]
    HybridPreferred,
    HybridRequired,
    ClassicalOnly,
}

impl TlsMode {
    pub const NAMES: [&str; 3] = ["hybrid_preferred", "hybrid_required", "classical_only"];

    pub fn kx_groups(self) -> Vec<&'static dyn SupportedKxGroup> {
        match self {
            Self::HybridPreferred => vec![kx_group::X25519MLKEM768, kx_group::X25519],
            Self::HybridRequired => vec![kx_group::X25519MLKEM768],
            Self::ClassicalOnly => vec![kx_group::X25519],
        }
    }

    pub fn crypto_provider(self) -> CryptoProvider {
        CryptoProvider {
            kx_groups: self.kx_groups(),
            ..aws_lc_rs::default_provider()
        }
    }

    pub fn verify_negotiated(
        self,
        version: Option<ProtocolVersion>,
        group: Option<NamedGroup>,
    ) -> Result<(), NegotiationError> {
        if version != Some(ProtocolVersion::TLSv1_3) {
            return Err(NegotiationError::ProtocolVersion(version));
        }
        match group {
            Some(name) if self.kx_groups().iter().any(|g| g.name() == name) => Ok(()),
            _ => Err(NegotiationError::KeyExchangeGroup {
                mode: self,
                negotiated: group,
            }),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::HybridPreferred => Self::NAMES[0],
            Self::HybridRequired => Self::NAMES[1],
            Self::ClassicalOnly => Self::NAMES[2],
        }
    }
}

impl fmt::Display for TlsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for TlsMode {
    type Err = String;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        [
            Self::HybridPreferred,
            Self::HybridRequired,
            Self::ClassicalOnly,
        ]
        .into_iter()
        .find(|mode| mode.name() == name)
        .ok_or_else(|| {
            format!(
                "unknown TLS mode \"{name}\"; expected one of {}",
                Self::NAMES.join(", ")
            )
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiationError {
    ProtocolVersion(Option<ProtocolVersion>),
    KeyExchangeGroup {
        mode: TlsMode,
        negotiated: Option<NamedGroup>,
    },
}

impl fmt::Display for NegotiationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProtocolVersion(version) => {
                write!(f, "negotiated {version:?} instead of TLS 1.3")
            }
            Self::KeyExchangeGroup { mode, negotiated } => {
                let allowed: Vec<String> = mode
                    .kx_groups()
                    .iter()
                    .map(|group| format!("{:?}", group.name()))
                    .collect();
                write!(
                    f,
                    "TLS mode {mode} allows key exchange {} but {negotiated:?} was negotiated",
                    allowed.join(" or ")
                )
            }
        }
    }
}

impl std::error::Error for NegotiationError {}

pub fn client_config(
    mode: TlsMode,
    roots: RootCertStore,
    client_certificate: Arc<ClientCertificateResolver>,
) -> Result<ClientConfig, rustls::Error> {
    let mut config = ClientConfig::builder_with_provider(Arc::new(mode.crypto_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_client_cert_resolver(client_certificate);
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    Ok(config)
}

#[derive(Debug, Default)]
pub struct ClientCertificateResolver {
    certificate: Option<ClientCertificate>,
    requested: AtomicBool,
    sent: AtomicBool,
}

impl ClientCertificateResolver {
    pub fn new(certificate: Option<ClientCertificate>) -> Self {
        Self {
            certificate,
            ..Self::default()
        }
    }

    pub fn requested(&self) -> bool {
        self.requested.load(Ordering::Relaxed)
    }

    pub fn check_required(&self, now: UnixTime) -> Result<(), ExpiredCertificate> {
        self.certificate
            .as_ref()
            .map_or(Ok(()), |certificate| certificate.check_required(now))
    }

    pub fn sent(&self) -> bool {
        self.sent.load(Ordering::Relaxed)
    }
}

impl ResolvesClientCert for ClientCertificateResolver {
    fn resolve(&self, _: &[&[u8]], schemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        self.requested.store(true, Ordering::Relaxed);
        let certified_key = match self.certificate.as_ref()?.certified_key(UnixTime::now()) {
            Ok(certified_key) => certified_key,
            Err(error) => {
                warn!("{error}; no client certificate is sent");
                return None;
            }
        };
        // rustls sends an empty certificate when the key offers none of the server's schemes.
        if certified_key.key.choose_scheme(schemes).is_some() {
            self.sent.store(true, Ordering::Relaxed);
        }
        Some(certified_key)
    }

    fn has_certs(&self) -> bool {
        self.certificate.is_some()
    }
}

pub fn webpki_roots() -> RootCertStore {
    RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

pub fn load_pem_roots(path: &Path) -> Result<RootCertStore, RootsError> {
    let error = |kind| RootsError {
        path: path.to_owned(),
        kind,
    };
    let mut roots = RootCertStore::empty();
    for certificate in
        CertificateDer::pem_file_iter(path).map_err(|e| error(RootsErrorKind::Pem(e)))?
    {
        let certificate = certificate.map_err(|e| error(RootsErrorKind::Pem(e)))?;
        roots
            .add(certificate)
            .map_err(|e| error(RootsErrorKind::Certificate(e)))?;
    }
    if roots.is_empty() {
        return Err(error(RootsErrorKind::Empty));
    }
    Ok(roots)
}

#[derive(Debug)]
pub struct RootsError {
    path: PathBuf,
    kind: RootsErrorKind,
}

#[derive(Debug)]
enum RootsErrorKind {
    Pem(pem::Error),
    Certificate(rustls::Error),
    Empty,
}

impl fmt::Display for RootsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let path = self.path.display();
        match &self.kind {
            RootsErrorKind::Pem(error) => write!(f, "cannot read CA bundle {path}: {error}"),
            RootsErrorKind::Certificate(error) => {
                write!(f, "invalid certificate in CA bundle {path}: {error}")
            }
            RootsErrorKind::Empty => write!(f, "CA bundle {path} contains no certificates"),
        }
    }
}

impl std::error::Error for RootsError {}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{NamedGroup, ProtocolVersion};

    fn offered(mode: TlsMode) -> Vec<NamedGroup> {
        mode.crypto_provider()
            .kx_groups
            .iter()
            .map(|group| group.name())
            .collect()
    }

    #[test]
    fn modes_offer_their_key_exchange_groups_in_order() {
        assert_eq!(
            offered(TlsMode::HybridPreferred),
            [NamedGroup::X25519MLKEM768, NamedGroup::X25519]
        );
        assert_eq!(
            offered(TlsMode::HybridRequired),
            [NamedGroup::X25519MLKEM768]
        );
        assert_eq!(offered(TlsMode::ClassicalOnly), [NamedGroup::X25519]);
    }

    #[test]
    fn hybrid_preferred_is_the_default() {
        assert_eq!(TlsMode::default(), TlsMode::HybridPreferred);
    }

    #[test]
    fn modes_parse_and_display_their_names() {
        for (name, mode) in [
            ("hybrid_preferred", TlsMode::HybridPreferred),
            ("hybrid_required", TlsMode::HybridRequired),
            ("classical_only", TlsMode::ClassicalOnly),
        ] {
            assert_eq!(name.parse::<TlsMode>(), Ok(mode));
            assert_eq!(mode.to_string(), name);
        }
        let error = "hybrid".parse::<TlsMode>().unwrap_err();
        assert!(error.contains("hybrid_preferred"), "{error}");
    }

    #[test]
    fn negotiation_must_be_tls13_with_an_offered_group() {
        let tls13 = Some(ProtocolVersion::TLSv1_3);
        let hybrid = Some(NamedGroup::X25519MLKEM768);
        let classical = Some(NamedGroup::X25519);
        for mode in [TlsMode::HybridPreferred, TlsMode::HybridRequired] {
            assert_eq!(mode.verify_negotiated(tls13, hybrid), Ok(()));
        }
        for mode in [TlsMode::HybridPreferred, TlsMode::ClassicalOnly] {
            assert_eq!(mode.verify_negotiated(tls13, classical), Ok(()));
        }
        assert_eq!(
            TlsMode::HybridRequired.verify_negotiated(tls13, classical),
            Err(NegotiationError::KeyExchangeGroup {
                mode: TlsMode::HybridRequired,
                negotiated: classical,
            })
        );
        assert_eq!(
            TlsMode::ClassicalOnly.verify_negotiated(tls13, hybrid),
            Err(NegotiationError::KeyExchangeGroup {
                mode: TlsMode::ClassicalOnly,
                negotiated: hybrid,
            })
        );
        assert_eq!(
            TlsMode::HybridPreferred.verify_negotiated(tls13, None),
            Err(NegotiationError::KeyExchangeGroup {
                mode: TlsMode::HybridPreferred,
                negotiated: None,
            })
        );
        assert_eq!(
            TlsMode::HybridPreferred.verify_negotiated(Some(ProtocolVersion::TLSv1_2), hybrid),
            Err(NegotiationError::ProtocolVersion(Some(
                ProtocolVersion::TLSv1_2
            )))
        );
    }

    #[test]
    fn hybrid_required_violation_names_the_groups() {
        let error = TlsMode::HybridRequired
            .verify_negotiated(Some(ProtocolVersion::TLSv1_3), Some(NamedGroup::X25519))
            .unwrap_err()
            .to_string();
        assert!(error.contains("hybrid_required"), "{error}");
        assert!(error.contains("X25519MLKEM768"), "{error}");
        assert!(error.contains("X25519"), "{error}");
    }
}
