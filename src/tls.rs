use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::{self, kx_group};

pub fn crypto_provider() -> CryptoProvider {
    CryptoProvider {
        kx_groups: vec![kx_group::X25519MLKEM768, kx_group::X25519],
        ..aws_lc_rs::default_provider()
    }
}
