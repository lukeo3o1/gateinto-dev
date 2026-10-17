use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtendedKeyUsage {
    Absent,
    Present { client_auth: bool },
}

impl ExtendedKeyUsage {
    pub fn allows_client_auth(&self) -> bool {
        matches!(self, Self::Absent | Self::Present { client_auth: true })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub spki: Vec<u8>,
    pub subject: String,
    pub not_before: i64,
    pub not_after: i64,
    pub extended_key_usage: ExtendedKeyUsage,
    pub sha1_thumbprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509Error(&'static str);

impl fmt::Display for X509Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed X.509 certificate: {}", self.0)
    }
}

impl std::error::Error for X509Error {}

const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const INTEGER: u8 = 0x02;
const BOOLEAN: u8 = 0x01;
const OCTET_STRING: u8 = 0x04;
const OID: u8 = 0x06;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
const VERSION: u8 = 0xa0;
const ISSUER_UNIQUE_ID: u8 = 0x81;
const SUBJECT_UNIQUE_ID: u8 = 0x82;
const EXTENSIONS: u8 = 0xa3;

const EXTENDED_KEY_USAGE_OID: &[u8] = &[0x55, 0x1d, 0x25];
const CLIENT_AUTH_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn peek(&self) -> Option<u8> {
        self.0.first().copied()
    }

    fn read_any(&mut self) -> Result<(u8, &'a [u8], &'a [u8]), X509Error> {
        let input = self.0;
        let (&tag, rest) = input.split_first().ok_or(X509Error("truncated"))?;
        if tag & 0x1f == 0x1f {
            return Err(X509Error("unsupported tag"));
        }
        let (&first, rest) = rest.split_first().ok_or(X509Error("truncated"))?;
        let (len, rest) = match first {
            0..=0x7f => (first as usize, rest),
            0x81..=0x84 => {
                let count = (first & 0x7f) as usize;
                let bytes = rest.get(..count).ok_or(X509Error("truncated"))?;
                let len = bytes
                    .iter()
                    .fold(0usize, |len, byte| (len << 8) | *byte as usize);
                (len, &rest[count..])
            }
            _ => return Err(X509Error("unsupported length")),
        };
        let contents = rest.get(..len).ok_or(X509Error("truncated"))?;
        let header = input.len() - rest.len();
        self.0 = &rest[len..];
        Ok((tag, contents, &input[..header + len]))
    }

    fn read(&mut self, expected: u8) -> Result<&'a [u8], X509Error> {
        let (tag, contents, _) = self.read_any()?;
        if tag == expected {
            Ok(contents)
        } else {
            Err(X509Error("unexpected tag"))
        }
    }

    fn read_optional(&mut self, expected: u8) -> Result<Option<&'a [u8]>, X509Error> {
        if self.peek() == Some(expected) {
            self.read(expected).map(Some)
        } else {
            Ok(None)
        }
    }

    fn finish(&self) -> Result<(), X509Error> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(X509Error("trailing data"))
        }
    }
}

pub fn parse_certificate(der: &[u8]) -> Result<Certificate, X509Error> {
    let mut outer = Reader(der);
    let mut certificate = Reader(outer.read(SEQUENCE)?);
    outer.finish()?;
    let mut tbs = Reader(certificate.read(SEQUENCE)?);
    certificate.read(SEQUENCE)?;
    certificate.read_any()?;
    certificate.finish()?;

    tbs.read_optional(VERSION)?;
    tbs.read(INTEGER)?;
    tbs.read(SEQUENCE)?;
    tbs.read(SEQUENCE)?;
    let mut validity = Reader(tbs.read(SEQUENCE)?);
    let not_before = parse_time(&mut validity)?;
    let not_after = parse_time(&mut validity)?;
    validity.finish()?;
    let subject = render_name(tbs.read(SEQUENCE)?)?;
    let (tag, _, spki) = tbs.read_any()?;
    if tag != SEQUENCE {
        return Err(X509Error("unexpected tag"));
    }
    tbs.read_optional(ISSUER_UNIQUE_ID)?;
    tbs.read_optional(SUBJECT_UNIQUE_ID)?;
    let extended_key_usage = match tbs.read_optional(EXTENSIONS)? {
        Some(extensions) => parse_extended_key_usage(extensions)?,
        None => ExtendedKeyUsage::Absent,
    };
    tbs.finish()?;

    Ok(Certificate {
        spki: spki.to_vec(),
        subject,
        not_before,
        not_after,
        extended_key_usage,
        sha1_thumbprint: aws_lc_rs::digest::digest(
            &aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY,
            der,
        )
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect(),
    })
}

fn parse_extended_key_usage(extensions: &[u8]) -> Result<ExtendedKeyUsage, X509Error> {
    let mut outer = Reader(extensions);
    let mut list = Reader(outer.read(SEQUENCE)?);
    outer.finish()?;
    let mut found = ExtendedKeyUsage::Absent;
    while !list.is_empty() {
        let mut extension = Reader(list.read(SEQUENCE)?);
        let id = extension.read(OID)?;
        extension.read_optional(BOOLEAN)?;
        let value = extension.read(OCTET_STRING)?;
        extension.finish()?;
        if id != EXTENDED_KEY_USAGE_OID {
            continue;
        }
        if found != ExtendedKeyUsage::Absent {
            return Err(X509Error("duplicate extended key usage"));
        }
        let mut value = Reader(value);
        let mut purposes = Reader(value.read(SEQUENCE)?);
        value.finish()?;
        let mut client_auth = false;
        while !purposes.is_empty() {
            client_auth |= purposes.read(OID)? == CLIENT_AUTH_OID;
        }
        found = ExtendedKeyUsage::Present { client_auth };
    }
    Ok(found)
}

fn parse_time(reader: &mut Reader<'_>) -> Result<i64, X509Error> {
    let (tag, contents, _) = reader.read_any()?;
    let invalid = X509Error("invalid time");
    let digits = match (tag, contents) {
        (UTC_TIME, [digits @ .., b'Z']) if digits.len() == 12 => digits,
        (GENERALIZED_TIME, [digits @ .., b'Z']) if digits.len() == 14 => digits,
        _ => return Err(invalid),
    };
    if !digits.iter().all(u8::is_ascii_digit) {
        return Err(invalid);
    }
    let number = |range: std::ops::Range<usize>| {
        digits[range]
            .iter()
            .fold(0i64, |value, digit| value * 10 + i64::from(digit - b'0'))
    };
    let (year, rest) = if tag == UTC_TIME {
        let year = number(0..2);
        (if year >= 50 { 1900 + year } else { 2000 + year }, 2)
    } else {
        (number(0..4), 4)
    };
    let month = number(rest..rest + 2);
    let day = number(rest + 2..rest + 4);
    let hour = number(rest + 4..rest + 6);
    let minute = number(rest + 6..rest + 8);
    let second = number(rest + 8..rest + 10);
    if !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return Err(invalid);
    }
    let days = days_from_civil(year, month, day);
    if civil_from_days(days) != (year, month, day) {
        return Err(invalid);
    }
    Ok(days * 86_400 + hour * 3600 + minute * 60 + second)
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

pub fn format_utc(secs: i64) -> String {
    let (year, month, day) = civil_from_days(secs.div_euclid(86_400));
    let time = secs.rem_euclid(86_400);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        time / 3600,
        time / 60 % 60,
        time % 60
    )
}

fn render_name(name: &[u8]) -> Result<String, X509Error> {
    let mut relative_names = Reader(name);
    let mut rendered = Vec::new();
    while !relative_names.is_empty() {
        let mut attributes = Reader(relative_names.read(SET)?);
        let mut parts = Vec::new();
        while !attributes.is_empty() {
            let mut attribute = Reader(attributes.read(SEQUENCE)?);
            let id = attribute.read(OID)?;
            let (tag, value, _) = attribute.read_any()?;
            attribute.finish()?;
            parts.push(format!(
                "{}={}",
                attribute_name(id),
                attribute_value(tag, value)
            ));
        }
        rendered.push(parts.join("+"));
    }
    Ok(rendered.join(", "))
}

fn attribute_name(id: &[u8]) -> String {
    match id {
        [0x55, 0x04, 0x03] => "CN".to_owned(),
        [0x55, 0x04, 0x06] => "C".to_owned(),
        [0x55, 0x04, 0x07] => "L".to_owned(),
        [0x55, 0x04, 0x08] => "ST".to_owned(),
        [0x55, 0x04, 0x0a] => "O".to_owned(),
        [0x55, 0x04, 0x0b] => "OU".to_owned(),
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01] => "E".to_owned(),
        [0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19] => "DC".to_owned(),
        _ => dotted_oid(id),
    }
}

fn dotted_oid(id: &[u8]) -> String {
    let mut arcs = Vec::new();
    let mut value: u64 = 0;
    for byte in id {
        value = (value << 7) | u64::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            if arcs.is_empty() {
                let first = (value / 40).min(2);
                arcs.push(first);
                arcs.push(value - first * 40);
            } else {
                arcs.push(value);
            }
            value = 0;
        }
    }
    arcs.iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

fn attribute_value(tag: u8, value: &[u8]) -> String {
    let text = match tag {
        0x0c | 0x13 | 0x16 => String::from_utf8_lossy(value).into_owned(),
        0x14 => value.iter().map(|byte| char::from(*byte)).collect(),
        0x1e => char::decode_utf16(
            value
                .chunks(2)
                .map(|pair| u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)])),
        )
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect(),
        _ => {
            return format!(
                "#{}",
                value
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            );
        }
    };
    text.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use rcgen::{
        CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, PublicKeyData, date_time_ymd,
    };

    use super::*;

    fn certificate(configure: impl FnOnce(&mut CertificateParams)) -> (Vec<u8>, KeyPair) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        configure(&mut params);
        let certificate = params.self_signed(&key).unwrap();
        (certificate.der().to_vec(), key)
    }

    #[test]
    fn reads_the_subject_public_key_info() {
        let (der, key) = certificate(|_| {});

        let parsed = parse_certificate(&der).unwrap();

        assert_eq!(parsed.spki, key.subject_public_key_info());
    }

    #[test]
    fn reads_utc_and_generalized_validity_times() {
        let (der, _) = certificate(|params| {
            params.not_before = date_time_ymd(2026, 1, 2);
            params.not_after = date_time_ymd(2051, 6, 7);
        });

        let parsed = parse_certificate(&der).unwrap();

        assert_eq!(parsed.not_before, 1_767_312_000);
        assert_eq!(parsed.not_after, 2_569_708_800);
    }

    #[test]
    fn reads_times_before_2000() {
        let (der, _) = certificate(|params| params.not_before = date_time_ymd(1999, 12, 31));

        assert_eq!(parse_certificate(&der).unwrap().not_before, 946_598_400);
    }

    #[test]
    fn reads_the_extended_key_usage() {
        let eku = |purposes: Vec<ExtendedKeyUsagePurpose>| {
            let (der, _) = certificate(|params| params.extended_key_usages = purposes);
            parse_certificate(&der).unwrap().extended_key_usage
        };

        assert_eq!(eku(vec![]), ExtendedKeyUsage::Absent);
        assert_eq!(
            eku(vec![ExtendedKeyUsagePurpose::ClientAuth]),
            ExtendedKeyUsage::Present { client_auth: true }
        );
        assert_eq!(
            eku(vec![
                ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsagePurpose::ClientAuth
            ]),
            ExtendedKeyUsage::Present { client_auth: true }
        );
        assert_eq!(
            eku(vec![ExtendedKeyUsagePurpose::ServerAuth]),
            ExtendedKeyUsage::Present { client_auth: false }
        );
    }

    #[test]
    fn client_auth_is_allowed_without_an_extended_key_usage_or_with_client_auth() {
        assert!(ExtendedKeyUsage::Absent.allows_client_auth());
        assert!(ExtendedKeyUsage::Present { client_auth: true }.allows_client_auth());
        assert!(!ExtendedKeyUsage::Present { client_auth: false }.allows_client_auth());
    }

    #[test]
    fn renders_the_subject() {
        let (der, _) = certificate(|params| {
            params
                .distinguished_name
                .push(DnType::CommonName, "gateinto-client");
            params
                .distinguished_name
                .push(DnType::OrganizationName, "Gateinto Test");
        });

        assert_eq!(
            parse_certificate(&der).unwrap().subject,
            "CN=gateinto-client, O=Gateinto Test"
        );
    }

    #[test]
    fn thumbprint_is_uppercase_sha1_of_the_der() {
        let (der, _) = certificate(|_| {});
        let expected: String =
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY, &der)
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect();

        assert_eq!(parse_certificate(&der).unwrap().sha1_thumbprint, expected);
        assert_eq!(expected.len(), 40);
    }

    #[test]
    fn rejects_malformed_input() {
        let (der, _) = certificate(|_| {});
        let mut trailing = der.clone();
        trailing.push(0);

        assert!(parse_certificate(&[]).is_err());
        assert!(parse_certificate(b"not a certificate").is_err());
        assert!(parse_certificate(&der[..der.len() - 1]).is_err());
        assert!(parse_certificate(&trailing).is_err());
        assert!(parse_certificate(&[0x30, 0x80, 0x00, 0x00]).is_err());
    }

    #[test]
    fn formats_unix_time_as_utc() {
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(1_767_323_045), "2026-01-02T03:04:05Z");
        assert_eq!(format_utc(2_569_708_800), "2051-06-07T00:00:00Z");
        assert_eq!(format_utc(951_782_400), "2000-02-29T00:00:00Z");
    }
}
