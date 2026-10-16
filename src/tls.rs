use std::fmt;
use std::path::{Path, PathBuf};

use rustls::RootCertStore;
use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::{self, kx_group};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::{self, PemObject};

pub fn crypto_provider() -> CryptoProvider {
    CryptoProvider {
        kx_groups: vec![kx_group::X25519MLKEM768, kx_group::X25519],
        ..aws_lc_rs::default_provider()
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
