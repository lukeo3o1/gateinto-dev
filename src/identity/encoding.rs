use std::fmt;

pub const P256_COORDINATE_LEN: usize = 32;
pub const P256_POINT_LEN: usize = 1 + 2 * P256_COORDINATE_LEN;
pub const ECC_BLOB_HEADER_LEN: usize = 8;
pub const ECC_PUBLIC_P256_BLOB_LEN: usize = ECC_BLOB_HEADER_LEN + 2 * P256_COORDINATE_LEN;
pub const BCRYPT_ECDSA_PUBLIC_P256_MAGIC: u32 = 0x3153_4345;

pub type P256Point = [u8; P256_POINT_LEN];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlobError {
    Truncated { len: usize },
    WrongMagic { magic: u32 },
    WrongKeySize { cb_key: u32 },
    WrongLength { len: usize },
}

impl fmt::Display for BlobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { len } => write!(
                f,
                "ECC public key blob is truncated: {len} bytes, header needs {ECC_BLOB_HEADER_LEN}"
            ),
            Self::WrongMagic { magic } => write!(
                f,
                "ECC public key blob has magic {magic:#010x}, expected ECDSA P-256 ({BCRYPT_ECDSA_PUBLIC_P256_MAGIC:#010x})"
            ),
            Self::WrongKeySize { cb_key } => write!(
                f,
                "ECC public key blob has {cb_key}-byte coordinates, expected {P256_COORDINATE_LEN}"
            ),
            Self::WrongLength { len } => write!(
                f,
                "ECC public key blob is {len} bytes, expected {ECC_PUBLIC_P256_BLOB_LEN}"
            ),
        }
    }
}

impl std::error::Error for BlobError {}

pub fn parse_ecc_public_blob(blob: &[u8]) -> Result<P256Point, BlobError> {
    let Some((header, coordinates)) = blob.split_first_chunk::<ECC_BLOB_HEADER_LEN>() else {
        return Err(BlobError::Truncated { len: blob.len() });
    };
    let magic = u32::from_le_bytes(header[..4].try_into().expect("4 bytes"));
    let cb_key = u32::from_le_bytes(header[4..].try_into().expect("4 bytes"));
    if magic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC {
        return Err(BlobError::WrongMagic { magic });
    }
    if cb_key as usize != P256_COORDINATE_LEN {
        return Err(BlobError::WrongKeySize { cb_key });
    }
    if blob.len() != ECC_PUBLIC_P256_BLOB_LEN {
        return Err(BlobError::WrongLength { len: blob.len() });
    }
    let mut point = [0; P256_POINT_LEN];
    point[0] = 0x04;
    point[1..].copy_from_slice(coordinates);
    Ok(point)
}

// SEQUENCE { SEQUENCE { id-ecPublicKey, prime256v1 }, BIT STRING (0 unused bits) ... }
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

pub fn p256_spki_der(point: &P256Point) -> Vec<u8> {
    [&P256_SPKI_PREFIX[..], point].concat()
}

pub fn sha256_fingerprint(der: &[u8]) -> String {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, der)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(magic: u32, cb_key: u32, coordinates: &[u8]) -> Vec<u8> {
        let mut blob = magic.to_le_bytes().to_vec();
        blob.extend_from_slice(&cb_key.to_le_bytes());
        blob.extend_from_slice(coordinates);
        blob
    }

    fn coordinates() -> Vec<u8> {
        (1..=64).collect()
    }

    #[test]
    fn parses_a_p256_public_blob_into_an_uncompressed_point() {
        let point = parse_ecc_public_blob(&blob(0x3153_4345, 32, &coordinates())).unwrap();

        assert_eq!(point[0], 0x04);
        assert_eq!(&point[1..], coordinates().as_slice());
    }

    #[test]
    fn rejects_a_blob_with_another_magic() {
        let p384_magic = 0x3353_4345;
        assert_eq!(
            parse_ecc_public_blob(&blob(p384_magic, 32, &coordinates())),
            Err(BlobError::WrongMagic { magic: p384_magic })
        );
    }

    #[test]
    fn rejects_a_blob_with_another_key_size() {
        assert_eq!(
            parse_ecc_public_blob(&blob(0x3153_4345, 48, &coordinates())),
            Err(BlobError::WrongKeySize { cb_key: 48 })
        );
    }

    #[test]
    fn rejects_truncated_blobs() {
        let full = blob(0x3153_4345, 32, &coordinates());
        assert_eq!(
            parse_ecc_public_blob(&full[..7]),
            Err(BlobError::Truncated { len: 7 })
        );
        assert_eq!(
            parse_ecc_public_blob(&full[..71]),
            Err(BlobError::WrongLength { len: 71 })
        );
        let mut long = full.clone();
        long.push(0);
        assert_eq!(
            parse_ecc_public_blob(&long),
            Err(BlobError::WrongLength { len: 73 })
        );
    }

    #[test]
    fn blob_errors_name_the_problem() {
        assert_eq!(
            BlobError::WrongMagic { magic: 0x3353_4345 }.to_string(),
            "ECC public key blob has magic 0x33534345, expected ECDSA P-256 (0x31534345)"
        );
        assert_eq!(
            BlobError::WrongKeySize { cb_key: 48 }.to_string(),
            "ECC public key blob has 48-byte coordinates, expected 32"
        );
        assert_eq!(
            BlobError::Truncated { len: 7 }.to_string(),
            "ECC public key blob is truncated: 7 bytes, header needs 8"
        );
        assert_eq!(
            BlobError::WrongLength { len: 71 }.to_string(),
            "ECC public key blob is 71 bytes, expected 72"
        );
    }

    #[test]
    fn spki_matches_a_generated_p256_key() {
        use aws_lc_rs::encoding::AsDer;
        use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

        let key = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
        let point: P256Point = key.public_key().as_ref().try_into().unwrap();
        let expected = key.public_key().as_der().unwrap();

        assert_eq!(p256_spki_der(&point), expected.as_ref());
    }

    #[test]
    fn fingerprint_is_lowercase_hex_sha256() {
        assert_eq!(
            sha256_fingerprint(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
