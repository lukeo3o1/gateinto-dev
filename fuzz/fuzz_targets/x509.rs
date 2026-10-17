#![no_main]

use gateinto::identity::x509::{format_utc, parse_certificate};
use libfuzzer_sys::fuzz_target;

const YEAR_0: i64 = -62_167_219_200;
const YEAR_10000: i64 = 253_402_300_800;

fuzz_target!(|data: &[u8]| {
    let Ok(certificate) = parse_certificate(data) else {
        return;
    };
    assert_eq!(certificate.sha1_thumbprint.len(), 40);
    assert!(
        certificate
            .sha1_thumbprint
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
    );
    assert!(!certificate.subject.chars().any(char::is_control));
    for time in [certificate.not_before, certificate.not_after] {
        assert!((YEAR_0..YEAR_10000).contains(&time), "{time}");
        assert_eq!(format_utc(time).len(), 20);
    }
    assert_eq!(certificate.spki.first(), Some(&0x30));
    assert_eq!(parse_certificate(data).as_ref(), Ok(&certificate));
});
