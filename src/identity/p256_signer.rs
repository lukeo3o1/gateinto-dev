use std::fmt;
use std::sync::Arc;

use aws_lc_rs::digest::{SHA256, digest};
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};

const SCALAR_LEN: usize = 32;

pub trait DigestSigner: fmt::Debug + Send + Sync + 'static {
    fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>, String>;
}

#[derive(Debug)]
pub struct P256SigningKey<K>(Arc<K>);

impl<K: DigestSigner> P256SigningKey<K> {
    pub fn new(key: K) -> Self {
        Self(Arc::new(key))
    }
}

impl<K: DigestSigner> SigningKey for P256SigningKey<K> {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
            .then(|| Box::new(P256Signer(self.0.clone())) as Box<dyn Signer>)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

#[derive(Debug)]
struct P256Signer<K>(Arc<K>);

impl<K: DigestSigner> Signer for P256Signer<K> {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let signature = self
            .0
            .sign_digest(digest(&SHA256, message).as_ref())
            .map_err(rustls::Error::General)?;
        if signature.len() != 2 * SCALAR_LEN {
            return Err(rustls::Error::General(format!(
                "expected a {}-byte ECDSA P-256 signature, got {} bytes",
                2 * SCALAR_LEN,
                signature.len()
            )));
        }
        let (r, s) = signature.split_at(SCALAR_LEN);
        let integers = [der_integer(r), der_integer(s)].concat();
        Ok([&[0x30, integers.len() as u8][..], &integers].concat())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

fn der_integer(unsigned: &[u8]) -> Vec<u8> {
    let start = unsigned
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(unsigned.len() - 1);
    let unsigned = &unsigned[start..];
    let sign_padding: &[u8] = if unsigned[0] & 0x80 == 0 { &[] } else { &[0] };
    let length = (sign_padding.len() + unsigned.len()) as u8;
    [&[0x02, length][..], sign_padding, unsigned].concat()
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{
        ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair,
        UnparsedPublicKey,
    };
    use rustls::SignatureAlgorithm;

    use super::*;

    #[derive(Debug)]
    struct SoftwareKey {
        pair: EcdsaKeyPair,
        message: Mutex<Vec<u8>>,
    }

    impl DigestSigner for SoftwareKey {
        fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>, String> {
            let message = self.message.lock().unwrap();
            assert_eq!(
                digest,
                aws_lc_rs::digest::digest(&SHA256, &message).as_ref()
            );
            Ok(self
                .pair
                .sign(&SystemRandom::new(), &message)
                .unwrap()
                .as_ref()
                .to_vec())
        }
    }

    #[derive(Debug)]
    struct FixedKey(Result<Vec<u8>, String>);

    impl DigestSigner for FixedKey {
        fn sign_digest(&self, _: &[u8]) -> Result<Vec<u8>, String> {
            self.0.clone()
        }
    }

    fn sign_with(key: impl DigestSigner, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        P256SigningKey::new(key)
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
            .unwrap()
            .sign(message)
    }

    #[test]
    fn signs_the_sha256_digest_as_a_der_ecdsa_signature() {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .unwrap();
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref()).unwrap();
        let public_key = pair.public_key().as_ref().to_vec();
        let key = Arc::new(SoftwareKey {
            pair,
            message: Mutex::new(Vec::new()),
        });
        let signing_key = P256SigningKey(key.clone());

        for round in 0..64u8 {
            let message = vec![round; usize::from(round) + 1];
            *key.message.lock().unwrap() = message.clone();
            let signer = signing_key
                .choose_scheme(&[
                    SignatureScheme::ED25519,
                    SignatureScheme::ECDSA_NISTP256_SHA256,
                ])
                .unwrap();
            assert_eq!(signer.scheme(), SignatureScheme::ECDSA_NISTP256_SHA256);
            let signature = signer.sign(&message).unwrap();
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &public_key)
                .verify(&message, &signature)
                .unwrap();
        }
    }

    #[test]
    fn offers_only_ecdsa_p256_sha256() {
        let key = P256SigningKey::new(FixedKey(Ok(vec![1; 64])));

        assert_eq!(key.algorithm(), SignatureAlgorithm::ECDSA);
        assert!(
            key.choose_scheme(&[
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PSS_SHA256,
            ])
            .is_none()
        );
    }

    #[test]
    fn integers_are_minimal_and_non_negative() {
        let mut raw = [0u8; 64];
        raw[31] = 0x7f;
        raw[32] = 0x80;
        assert_eq!(
            sign_with(FixedKey(Ok(raw.to_vec())), b"m").unwrap(),
            [
                &[0x30, 0x26, 0x02, 0x01, 0x7f, 0x02, 0x21, 0x00, 0x80][..],
                &[0; 31]
            ]
            .concat()
        );
        assert_eq!(
            sign_with(FixedKey(Ok(vec![0; 64])), b"m").unwrap(),
            [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00]
        );
    }

    #[test]
    fn signatures_of_the_wrong_length_are_errors() {
        for length in [0, 63, 65, 96] {
            assert!(
                sign_with(FixedKey(Ok(vec![1; length])), b"m").is_err(),
                "{length}"
            );
        }
    }

    #[test]
    fn signing_failures_are_passed_through() {
        assert_eq!(
            sign_with(FixedKey(Err("NTE_PERM (0x80090010)".to_owned())), b"m").unwrap_err(),
            rustls::Error::General("NTE_PERM (0x80090010)".to_owned())
        );
    }
}
