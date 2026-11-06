use std::collections::HashSet;
use std::fmt;
use std::net::Ipv6Addr;
use std::str::FromStr;

use zeroize::Zeroizing;

pub(crate) const MAX_AUTH_URI_LEN: usize = 2048;
pub(crate) const MAX_EXPIRES_IN: u64 = 600;

#[derive(PartialEq, Eq)]
pub(crate) struct Challenge {
    auth_uri: AuthUri,
    user_code: Zeroizing<String>,
    expires_in: u64,
}

impl fmt::Debug for Challenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Challenge")
            .field("auth_uri", &self.auth_uri)
            .field("user_code", &"<redacted>")
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

impl Challenge {
    pub(crate) fn auth_uri(&self) -> &str {
        &self.auth_uri.url
    }

    pub(crate) fn origin(&self) -> &str {
        &self.auth_uri.origin
    }

    pub(crate) fn user_code(&self) -> &str {
        &self.user_code
    }

    pub(crate) fn expires_in(&self) -> u64 {
        self.expires_in
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Invalid {
    Absent,
    Malformed,
    Repeated,
    Token68,
    DuplicateParameter,
    MissingParameter,
    AuthUri(UriError),
    UserCode,
    ExpiresIn,
    Fingerprint,
    Origin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UriError {
    Length,
    Character,
    Scheme,
    Userinfo,
    Port,
    Host,
    Bracket,
    Percent,
    Control,
    CertKey,
    ReservedKey,
}

pub(crate) fn parse(
    values: &[&[u8]],
    fingerprint: &str,
    origins: Option<&[VerificationOrigin]>,
) -> Result<Challenge, Invalid> {
    let combined = Zeroizing::new(values.join(&b", "[..]));
    let challenges = challenges(&combined).ok_or(Invalid::Malformed)?;
    let mut ours = challenges
        .into_iter()
        .filter(|challenge| challenge.scheme.eq_ignore_ascii_case(SCHEME));
    let challenge = ours.next().ok_or(Invalid::Absent)?;
    if ours.next().is_some() {
        return Err(Invalid::Repeated);
    }
    if challenge.token68 {
        return Err(Invalid::Token68);
    }
    let mut known: [Option<&[u8]>; PARAMETERS.len()] = [None; PARAMETERS.len()];
    let mut others = HashSet::new();
    for (name, value) in &challenge.params {
        let fresh = match PARAMETERS
            .iter()
            .position(|wanted| name.eq_ignore_ascii_case(wanted))
        {
            Some(index) => known[index].replace(value).is_none(),
            None => others.insert(name.to_ascii_lowercase()),
        };
        if !fresh {
            return Err(Invalid::DuplicateParameter);
        }
    }
    let [Some(uri), Some(code), Some(expiry)] = known else {
        return Err(Invalid::MissingParameter);
    };
    let auth_uri = auth_uri(uri).map_err(Invalid::AuthUri)?;
    let user_code = user_code(code).ok_or(Invalid::UserCode)?;
    let expires_in = expires_in(expiry).ok_or(Invalid::ExpiresIn)?;
    if auth_uri.cert_sha256 != fingerprint {
        return Err(Invalid::Fingerprint);
    }
    if let Some(origins) = origins
        && !origins.iter().any(|origin| origin.0 == *auth_uri.origin)
    {
        return Err(Invalid::Origin);
    }
    Ok(Challenge {
        auth_uri,
        user_code,
        expires_in,
    })
}

const SCHEME: &[u8] = b"Gateinto";
const PARAMETERS: [&[u8]; 3] = [b"auth_uri", b"user_code", b"expires_in"];
const HTTPS: &str = "https://";
const CERT_KEY: &[u8] = b"cert_sha256";
const CODE_KEY: &[u8] = b"user_code";
const CODE_LETTERS: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";

struct RawChallenge<'a> {
    scheme: &'a [u8],
    token68: bool,
    params: Vec<(&'a [u8], Zeroizing<Vec<u8>>)>,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn at_end(&self) -> bool {
        self.pos == self.bytes.len()
    }

    fn at_element_end(&self) -> bool {
        matches!(self.peek(), None | Some(b','))
    }

    fn ows(&mut self) -> usize {
        let start = self.pos;
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.pos += 1;
        }
        self.pos - start
    }

    fn separators(&mut self) {
        loop {
            self.ows();
            if self.peek() != Some(b',') {
                return;
            }
            self.pos += 1;
        }
    }

    fn take_while(&mut self, accept: impl Fn(u8) -> bool) -> &'a [u8] {
        let start = self.pos;
        while self.peek().is_some_and(&accept) {
            self.pos += 1;
        }
        &self.bytes[start..self.pos]
    }

    fn token(&mut self) -> Option<&'a [u8]> {
        Some(self.take_while(is_tchar)).filter(|token| !token.is_empty())
    }

    fn quoted_string(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        if self.peek() != Some(b'"') {
            return None;
        }
        self.pos += 1;
        let capacity = (self.bytes.len() - self.pos).min(MAX_AUTH_URI_LEN);
        let mut value = Zeroizing::new(Vec::with_capacity(capacity));
        loop {
            let byte = self.peek()?;
            self.pos += 1;
            match byte {
                b'"' => return Some(value),
                b'\\' => {
                    let escaped = self.peek().filter(|&b| b == b'\t' || is_text(b))?;
                    self.pos += 1;
                    value.push(escaped);
                }
                b'\t' => value.push(byte),
                _ if is_text(byte) => value.push(byte),
                _ => return None,
            }
        }
    }

    fn param(&mut self) -> Option<(&'a [u8], Zeroizing<Vec<u8>>)> {
        let start = self.pos;
        let param = self.try_param();
        if param.is_none() {
            self.pos = start;
        }
        param
    }

    fn try_param(&mut self) -> Option<(&'a [u8], Zeroizing<Vec<u8>>)> {
        let name = self.token()?;
        self.ows();
        if self.peek() != Some(b'=') {
            return None;
        }
        self.pos += 1;
        self.ows();
        let value = match self.peek() {
            Some(b'"') => self.quoted_string()?,
            _ => Zeroizing::new(self.token()?.to_vec()),
        };
        Some((name, value))
    }

    fn token68(&mut self) -> bool {
        let body = self.take_while(|b| b.is_ascii_alphanumeric() || b"-._~+/".contains(&b));
        if body.is_empty() {
            return false;
        }
        self.take_while(|b| b == b'=');
        true
    }
}

fn challenges(bytes: &[u8]) -> Option<Vec<RawChallenge<'_>>> {
    let mut cursor = Cursor { bytes, pos: 0 };
    let mut challenges = Vec::new();
    loop {
        cursor.separators();
        if cursor.at_end() {
            return Some(challenges);
        }
        let mut challenge = RawChallenge {
            scheme: cursor.token()?,
            token68: false,
            params: Vec::new(),
        };
        let spaces = cursor.ows();
        if !cursor.at_element_end() {
            if spaces == 0 {
                return None;
            }
            if let Some(param) = cursor.param() {
                challenge.params.push(param);
                params(&mut cursor, &mut challenge.params)?;
            } else if cursor.token68() {
                challenge.token68 = true;
                cursor.ows();
                if !cursor.at_element_end() {
                    return None;
                }
            } else {
                return None;
            }
        }
        challenges.push(challenge);
    }
}

fn params<'a>(
    cursor: &mut Cursor<'a>,
    params: &mut Vec<(&'a [u8], Zeroizing<Vec<u8>>)>,
) -> Option<()> {
    loop {
        cursor.ows();
        if !cursor.at_element_end() {
            return None;
        }
        cursor.separators();
        match cursor.param() {
            Some(param) => params.push(param),
            None => return Some(()),
        }
    }
}

fn is_tchar(byte: u8) -> bool {
    crate::http::is_token(&[byte])
}

fn is_text(byte: u8) -> bool {
    matches!(byte, b' '..=b'~' | 0x80..=0xff)
}

#[derive(PartialEq, Eq)]
struct AuthUri {
    url: Zeroizing<String>,
    origin: Zeroizing<String>,
    cert_sha256: String,
}

impl fmt::Debug for AuthUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthUri(<redacted>)")
    }
}

fn auth_uri(value: &[u8]) -> Result<AuthUri, UriError> {
    if value.len() > MAX_AUTH_URI_LEN {
        return Err(UriError::Length);
    }
    if !value.iter().copied().all(is_uri_char) {
        return Err(UriError::Character);
    }
    let url = Zeroizing::new(String::from_utf8(value.to_vec()).map_err(|_| UriError::Character)?);
    let rest = strip_https(&url).ok_or(UriError::Scheme)?;
    let (authority, tail) = rest.split_at(rest.find(['/', '?']).unwrap_or(rest.len()));
    let origin = Zeroizing::new(origin(authority)?);
    if tail.contains(['[', ']']) {
        return Err(UriError::Bracket);
    }
    let (path, query) = tail.split_once('?').unwrap_or((tail, ""));
    for segment in path.split('/') {
        decode(segment)?;
    }
    let cert_sha256 = cert_sha256(query)?;
    Ok(AuthUri {
        url,
        origin,
        cert_sha256,
    })
}

fn cert_sha256(query: &str) -> Result<String, UriError> {
    let mut found = None;
    for pair in query.split('&') {
        let (key, value) = match pair.split_once('=') {
            Some((key, value)) => (key, Some(value)),
            None => (pair, None),
        };
        let key = decode(key)?;
        if let Some(value) = value {
            decode(value)?;
        }
        if *key == CERT_KEY {
            if found.replace(value).is_some() {
                return Err(UriError::CertKey);
            }
        } else if key.eq_ignore_ascii_case(CERT_KEY) || key.eq_ignore_ascii_case(CODE_KEY) {
            return Err(UriError::ReservedKey);
        }
    }
    found
        .flatten()
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
        .map(str::to_owned)
        .ok_or(UriError::CertKey)
}

fn decode(component: &str) -> Result<Zeroizing<Vec<u8>>, UriError> {
    let mut bytes = component.bytes();
    let mut decoded = Zeroizing::new(Vec::with_capacity(component.len()));
    while let Some(byte) = bytes.next() {
        let byte = if byte == b'%' {
            let mut digit = || {
                bytes
                    .next()
                    .and_then(|b| char::from(b).to_digit(16))
                    .ok_or(UriError::Percent)
            };
            let high = digit()?;
            let low = digit()?;
            (high * 16 + low) as u8
        } else {
            byte
        };
        if byte.is_ascii_control() {
            return Err(UriError::Control);
        }
        decoded.push(byte);
    }
    Ok(decoded)
}

fn is_uri_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._~:/?[]@!$&'()*+,=%".contains(&byte)
}

fn strip_https(url: &str) -> Option<&str> {
    url.get(..HTTPS.len())
        .filter(|scheme| scheme.eq_ignore_ascii_case(HTTPS))
        .map(|_| &url[HTTPS.len()..])
}

fn origin(authority: &str) -> Result<String, UriError> {
    if authority.contains('@') {
        return Err(UriError::Userinfo);
    }
    let (host, port) = if authority.starts_with('[') {
        let close = authority.find(']').ok_or(UriError::Host)?;
        let address: Ipv6Addr = authority[1..close].parse().map_err(|_| UriError::Host)?;
        let after = &authority[close + 1..];
        let port = match after {
            "" => None,
            _ => Some(after.strip_prefix(':').ok_or(UriError::Host)?),
        };
        (format!("[{address}]"), port)
    } else {
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        };
        if !is_registered_name(host) {
            return Err(UriError::Host);
        }
        (host.to_ascii_lowercase(), port)
    };
    let port = match port {
        Some(port) => parse_port(port).ok_or(UriError::Port)?,
        None => 443,
    };
    Ok(match port {
        443 => format!("{HTTPS}{host}"),
        _ => format!("{HTTPS}{host}:{port}"),
    })
}

fn parse_port(port: &str) -> Option<u16> {
    let digits = (1..=5).contains(&port.len())
        && !port.starts_with('0')
        && port.bytes().all(|b| b.is_ascii_digit());
    digits.then(|| port.parse().ok()).flatten()
}

fn is_registered_name(host: &str) -> bool {
    let labels_valid = host.len() <= 253
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        });
    let numeric = host.rsplit('.').next().is_some_and(is_numeric_label);
    labels_valid && (!numeric || is_ipv4(host))
}

fn is_numeric_label(label: &str) -> bool {
    let hex = label
        .strip_prefix("0x")
        .or_else(|| label.strip_prefix("0X"));
    match hex {
        Some(digits) => digits.bytes().all(|b| b.is_ascii_hexdigit()),
        None => label.bytes().all(|b| b.is_ascii_digit()),
    }
}

fn is_ipv4(host: &str) -> bool {
    let octets: Vec<&str> = host.split('.').collect();
    octets.len() == 4
        && octets.iter().all(|octet| {
            (octet == &"0" || !octet.starts_with('0'))
                && octet.len() <= 3
                && octet.bytes().all(|b| b.is_ascii_digit())
                && octet.parse::<u8>().is_ok()
        })
}

fn user_code(value: &[u8]) -> Option<Zeroizing<String>> {
    let valid = value.len() == 9
        && value.iter().enumerate().all(|(index, byte)| match index {
            4 => *byte == b'-',
            _ => CODE_LETTERS.contains(byte),
        });
    if !valid {
        return None;
    }
    String::from_utf8(value.to_vec()).ok().map(Zeroizing::new)
}

fn expires_in(value: &[u8]) -> Option<u64> {
    let digits =
        (1..=10).contains(&value.len()) && value[0] != b'0' && value.iter().all(u8::is_ascii_digit);
    let seconds: u64 = std::str::from_utf8(value)
        .ok()
        .filter(|_| digits)?
        .parse()
        .ok()?;
    Some(seconds.min(MAX_EXPIRES_IN))
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(try_from = "String")]
pub struct VerificationOrigin(String);

impl VerificationOrigin {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for VerificationOrigin {
    type Err = InvalidVerificationOrigin;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let authority = strip_https(text)
            .filter(|authority| {
                authority.bytes().all(is_uri_char) && !authority.contains(['/', '?'])
            })
            .ok_or(InvalidVerificationOrigin)?;
        origin(authority)
            .map(Self)
            .map_err(|_| InvalidVerificationOrigin)
    }
}

impl TryFrom<String> for VerificationOrigin {
    type Error = InvalidVerificationOrigin;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        text.parse()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidVerificationOrigin;

impl fmt::Display for InvalidVerificationOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "verification_origins entries must be https:// followed by a host and an optional \
             port, without a path, a trailing slash or dot, user information or wildcards",
        )
    }
}

impl std::error::Error for InvalidVerificationOrigin {}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const OTHER_FP: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    fn url(prefix: &str) -> String {
        format!("{prefix}cert_sha256={FP}")
    }

    fn header(auth_uri: &str) -> String {
        format!("Gateinto auth_uri=\"{auth_uri}\", user_code=\"WDJB-MJHT\", expires_in=\"300\"")
    }

    fn standard() -> String {
        header(&url("https://verify.example.test/device?x=1&"))
    }

    fn lines(values: &[&str]) -> Result<Challenge, Invalid> {
        let values: Vec<&[u8]> = values.iter().map(|value| value.as_bytes()).collect();
        parse(&values, FP, None)
    }

    fn one(value: &str) -> Result<Challenge, Invalid> {
        lines(&[value])
    }

    fn uri(value: &str) -> Result<AuthUri, UriError> {
        auth_uri(value.as_bytes())
    }

    fn origins(entries: &[&str]) -> Vec<VerificationOrigin> {
        entries.iter().map(|entry| entry.parse().unwrap()).collect()
    }

    #[test]
    fn debug_output_redacts_the_challenge() {
        let challenge = one(&standard()).unwrap();
        let debug = format!("{challenge:?} {:?}", challenge.auth_uri);
        for secret in ["verify.example.test", "WDJB", FP, "x=1"] {
            assert!(!debug.contains(secret), "{debug}");
        }
        assert!(debug.contains("300"), "{debug}");
    }

    #[test]
    fn a_quoted_challenge_yields_its_values() {
        let challenge = one(&standard()).unwrap();
        assert_eq!(
            challenge.auth_uri(),
            url("https://verify.example.test/device?x=1&")
        );
        assert_eq!(challenge.origin(), "https://verify.example.test");
        assert_eq!(challenge.user_code(), "WDJB-MJHT");
        assert_eq!(challenge.expires_in(), 300);
    }

    #[test]
    fn token_values_quoted_pairs_and_unknown_parameters_are_accepted() {
        let target = url("https://a.test/?");
        let escaped: String = target.chars().flat_map(|c| ['\\', c]).collect();
        for value in [
            format!("Gateinto auth_uri=\"{target}\", user_code=WDJB-MJHT, expires_in=300"),
            format!(
                "Gateinto auth_uri=\"{escaped}\", user_code=\"WDJB\\-MJHT\", expires_in=\"3\\00\""
            ),
            format!(
                "Gateinto realm=\"x\", auth_uri=\"{target}\", foo=bar, user_code=WDJB-MJHT, \
                 expires_in=300, baz=\"\\\"\""
            ),
        ] {
            let challenge = one(&value).unwrap();
            assert_eq!(challenge.auth_uri(), target, "{value}");
            assert_eq!(challenge.user_code(), "WDJB-MJHT", "{value}");
            assert_eq!(challenge.expires_in(), 300, "{value}");
        }
    }

    #[test]
    fn list_syntax_whitespace_and_case_follow_rfc_9110() {
        let target = url("https://a.test/?");
        for value in [
            format!(
                ", , Gateinto auth_uri=\"{target}\", , user_code=WDJB-MJHT ,expires_in=300 , ,"
            ),
            format!("Gateinto auth_uri = \"{target}\", user_code\t=\tWDJB-MJHT, expires_in= 300"),
            format!("gATEINTO AUTH_URI=\"{target}\", User_Code=WDJB-MJHT, EXPIRES_IN=300"),
            format!(
                "Basic realm=\"a\", Negotiate abc==, Bearer, Gateinto auth_uri=\"{target}\", \
                 user_code=WDJB-MJHT, expires_in=300, Digest realm=\"b\", nonce=\"c\""
            ),
        ] {
            assert_eq!(one(&value).unwrap().auth_uri(), target, "{value}");
        }
    }

    #[test]
    fn field_lines_are_combined_in_order() {
        let target = url("https://a.test/?");
        let auth_uri = format!("Gateinto auth_uri=\"{target}\"");
        let challenge = lines(&[
            "Basic realm=\"a\"",
            &auth_uri,
            "user_code=WDJB-MJHT",
            "expires_in=300",
        ])
        .unwrap();
        assert_eq!(challenge.auth_uri(), target);
        assert_eq!(challenge.user_code(), "WDJB-MJHT");
        assert_eq!(
            lines(&["Basic realm=\"a\"", &standard()]).unwrap(),
            one(&standard()).unwrap()
        );
    }

    #[test]
    fn responses_without_a_gateinto_challenge_have_none() {
        assert_eq!(lines(&[]), Err(Invalid::Absent));
        for value in [
            "",
            " , ",
            "Basic realm=\"a\"",
            "Gateintox auth_uri=x",
            "Negotiate abc==",
        ] {
            assert_eq!(one(value), Err(Invalid::Absent), "{value:?}");
        }
    }

    #[test]
    fn unparsable_fields_hide_every_challenge() {
        let good = standard();
        for value in [
            format!("{good}, Basic realm=\"unterminated"),
            format!("Basic realm=\"a\" junk, {good}"),
            format!("Basic realm=a b, {good}"),
            format!("Basic =a, {good}"),
            format!("{good}, realm=\"a\"\u{1}"),
            format!("{good}, x=\"a\\\u{1}\""),
            format!("{good}, Basic\u{7f}"),
            format!("Basic, abc=, {good}"),
            format!("@, {good}"),
            format!("Gateinto\"x\", {good}"),
        ] {
            assert_eq!(one(&value), Err(Invalid::Malformed), "{value}");
        }
    }

    #[test]
    fn malformed_gateinto_challenges_are_invalid() {
        let target = url("https://a.test/?");
        let cases = [
            ("Gateinto abc==".to_owned(), Invalid::Token68),
            ("Gateinto abc".to_owned(), Invalid::Token68),
            ("Gateinto".to_owned(), Invalid::MissingParameter),
            (
                format!("Gateinto auth_uri=\"{target}\", user_code=WDJB-MJHT"),
                Invalid::MissingParameter,
            ),
            (
                "Gateinto user_code=WDJB-MJHT, expires_in=300".to_owned(),
                Invalid::MissingParameter,
            ),
            (
                format!("Gateinto auth_uri=\"{target}\", expires_in=300"),
                Invalid::MissingParameter,
            ),
            (
                format!("{}, USER_CODE=WDJB-MJHT", header(&target)),
                Invalid::DuplicateParameter,
            ),
            (
                format!("{}, auth_uri=\"{target}\"", header(&target)),
                Invalid::DuplicateParameter,
            ),
            (
                format!("{}, foo=1, FOO=1", header(&target)),
                Invalid::DuplicateParameter,
            ),
            (
                format!("{}, {}", header(&target), header(&target)),
                Invalid::Repeated,
            ),
            (
                format!("{}, Basic realm=\"a\", gateinto abc", header(&target)),
                Invalid::Repeated,
            ),
            (
                format!("Gateinto auth_uri=\"{target}\", user_code=wdjb-mjht, expires_in=300"),
                Invalid::UserCode,
            ),
            (
                format!("Gateinto auth_uri=\"{target}\", user_code=WDJB-MJHT, expires_in=0"),
                Invalid::ExpiresIn,
            ),
            (
                "Gateinto auth_uri=\"http://a.test/\", user_code=WDJB-MJHT, expires_in=1"
                    .to_owned(),
                Invalid::AuthUri(UriError::Scheme),
            ),
        ];
        for (value, expected) in cases {
            assert_eq!(one(&value), Err(expected), "{value}");
        }
    }

    #[test]
    fn duplicates_are_found_among_many_parameters() {
        let unknown: String = (0..2000).map(|i| format!(", p{i}=1")).collect();
        let value = format!("{}{unknown}", standard());
        assert!(one(&value).is_ok());
        assert_eq!(
            one(&format!("{value}, P1999=2")),
            Err(Invalid::DuplicateParameter)
        );
        assert_eq!(
            one(&format!("{value}, Expires_In=1")),
            Err(Invalid::DuplicateParameter)
        );
    }

    #[test]
    fn the_auth_uri_limit_applies_after_unescaping() {
        let prefix = url("https://a.test/?");
        let fill = |len: usize| format!("{prefix}&{}", "a".repeat(len - prefix.len() - 1));
        let longest = fill(MAX_AUTH_URI_LEN);
        let escaped: String = longest.chars().flat_map(|c| ['\\', c]).collect();
        assert!(escaped.len() > MAX_AUTH_URI_LEN);
        assert_eq!(one(&header(&escaped)).unwrap().auth_uri(), longest);
        assert_eq!(
            one(&header(&fill(MAX_AUTH_URI_LEN + 1))),
            Err(Invalid::AuthUri(UriError::Length))
        );
    }

    #[test]
    fn the_fingerprint_must_be_the_one_of_the_handshake() {
        let value = standard();
        let values = [value.as_bytes()];
        assert!(parse(&values, FP, None).is_ok());
        assert_eq!(parse(&values, OTHER_FP, None), Err(Invalid::Fingerprint));
        assert_eq!(parse(&values, "", None), Err(Invalid::Fingerprint));
    }

    #[test]
    fn valid_auth_uris_keep_their_bytes_and_yield_an_origin() {
        let long_label = "a".repeat(63);
        let long_name = format!("{0}.{0}.{0}.{1}", "a".repeat(63), "a".repeat(61));
        assert_eq!(long_name.len(), 253);
        let cases = [
            (
                url("https://verify.example.test/device?x=1&"),
                "https://verify.example.test",
            ),
            (
                url("HTTPS://Verify.Example.TEST:8443/?"),
                "https://verify.example.test:8443",
            ),
            (
                url("https://verify.example.test:443/?"),
                "https://verify.example.test",
            ),
            (url("https://a.test:65535/?"), "https://a.test:65535"),
            (url("https://a.test:1?"), "https://a.test:1"),
            (url("https://a.test?"), "https://a.test"),
            (url("https://127.0.0.1/?"), "https://127.0.0.1"),
            (url("https://0.0.0.0/?"), "https://0.0.0.0"),
            (url("https://255.255.255.255/?"), "https://255.255.255.255"),
            (url("https://[::1]/?"), "https://[::1]"),
            (
                url("https://[2001:DB8::1]:8443/?"),
                "https://[2001:db8::1]:8443",
            ),
            (
                url("https://[::ffff:192.0.2.1]/?"),
                "https://[::ffff:192.0.2.1]",
            ),
            (
                url("https://xn--bcher-kva.example/?"),
                "https://xn--bcher-kva.example",
            ),
            (url("https://1a.b-c.x0/?"), "https://1a.b-c.x0"),
            (url("https://a.123x/?"), "https://a.123x"),
            (url("https://a.0xg/?"), "https://a.0xg"),
            (format!("https://{long_label}.test/?cert_sha256={FP}"), ""),
            (format!("https://{long_name}/?cert_sha256={FP}"), ""),
            (
                url("https://a.test/p%20a/%C3%A9/@:!$&'()*+,=-._~/?q=%2F%26&&k&v=a=b?c/@&"),
                "https://a.test",
            ),
            (
                format!("https://a.test/?cert%5Fsha256={FP}&x"),
                "https://a.test",
            ),
            (
                format!("https://a.test/?cert%5fsha256={FP}"),
                "https://a.test",
            ),
        ];
        for (value, origin) in cases {
            let parsed = uri(&value).unwrap_or_else(|error| panic!("{value}: {error:?}"));
            assert_eq!(*parsed.url, value);
            assert_eq!(parsed.cert_sha256, FP, "{value}");
            if !origin.is_empty() {
                assert_eq!(*parsed.origin, origin, "{value}");
            }
        }
    }

    #[test]
    fn auth_uris_with_excluded_characters_are_rejected() {
        let mut values = vec![
            url("https://a.test/\"?"),
            format!("https://a.test/\"%20--flag?cert_sha256={FP}"),
            url("https://a.test/a b?"),
            url("https://a.test/?a=\"&"),
            url("https://evil.test\\.corp.example/x?"),
            url("https://a.test/\\x?"),
            url("https://a.test/#?"),
            format!("https://a.test/?cert_sha256={FP}#top"),
            url("https://a.test/?a=1;"),
            format!("https://a.test/?cert_sha256={FP};cert_sha256={OTHER_FP}"),
            url("https://a.test/a;b?"),
            url("https://a.test/caf\u{e9}?"),
            url("https://a.test/\t?"),
            url("https://a.test/\u{7f}?"),
            url("https://a.test/\u{0}?"),
        ];
        for excluded in ['<', '>', '\\', '^', '`', '{', '|', '}'] {
            values.push(url(&format!("https://a.test/{excluded}?")));
            values.push(url(&format!("https://a.test/?q={excluded}&")));
        }
        for value in values {
            assert_eq!(
                uri(&value).map(|_| ()),
                Err(UriError::Character),
                "{value:?}"
            );
        }
        assert_eq!(uri(""), Err(UriError::Scheme));
    }

    #[test]
    fn auth_uris_need_https_without_userinfo_and_a_valid_port() {
        let cases = [
            (url("http://a.test/?"), UriError::Scheme),
            (url("https:/a.test/?"), UriError::Scheme),
            (url("https:a.test/?"), UriError::Scheme),
            (url("ftp://a.test/?"), UriError::Scheme),
            (url("httpsx://a.test/?"), UriError::Scheme),
            (url("https://user@a.test/?"), UriError::Userinfo),
            (url("https://u:p@a.test/?"), UriError::Userinfo),
            (url("https://a.test@/?"), UriError::Userinfo),
            (url("https://a.test:0/?"), UriError::Port),
            (url("https://a.test:0443/?"), UriError::Port),
            (url("https://a.test:65536/?"), UriError::Port),
            (url("https://a.test:123456/?"), UriError::Port),
            (url("https://a.test:/?"), UriError::Port),
            (url("https://a.test:+1/?"), UriError::Port),
            (url("https://a.test:1:2/?"), UriError::Port),
            (url("https://[::1]:0/?"), UriError::Port),
        ];
        for (value, expected) in cases {
            assert_eq!(uri(&value).map(|_| ()), Err(expected), "{value}");
        }
        assert!(uri(&url("https://a.test/user@x?a=@&")).is_ok());
    }

    #[test]
    fn auth_uri_hosts_follow_the_ldh_ipv4_and_ipv6_grammar() {
        let long_label = format!("https://{}.test/?", "a".repeat(64));
        let long_name = format!("https://{0}.{0}.{0}.{1}/?", "a".repeat(63), "a".repeat(62));
        let mut values = vec![
            "https:///?".to_owned(),
            "https://?".to_owned(),
            "https://:443/?".to_owned(),
            "https://a..b/?".to_owned(),
            "https://.a.test/?".to_owned(),
            "https://a.test./?".to_owned(),
            "https://-a.test/?".to_owned(),
            "https://a-.test/?".to_owned(),
            "https://a.-test/?".to_owned(),
            long_label,
            long_name,
            "https://a_b.test/?".to_owned(),
            "https://*.test/?".to_owned(),
            "https://a!.test/?".to_owned(),
            "https://1.2.3/?".to_owned(),
            "https://1.2.3.4.5/?".to_owned(),
            "https://0x7f.1/?".to_owned(),
            "https://0x7f000001/?".to_owned(),
            "https://256.1.1.1/?".to_owned(),
            "https://01.1.1.1/?".to_owned(),
            "https://1.1.1.00/?".to_owned(),
            "https://2130706433/?".to_owned(),
            "https://a.123/?".to_owned(),
            "https://a.0x/?".to_owned(),
            "https://a.0X/?".to_owned(),
            "https://a.0x1F/?".to_owned(),
            "https://a.0X1f/?".to_owned(),
            "https://[::1%25eth0]/?".to_owned(),
            "https://[fe80::1%eth0]/?".to_owned(),
            "https://[1.2.3.4]/?".to_owned(),
            "https://[v1.x]/?".to_owned(),
            "https://[::1/?".to_owned(),
            "https://[::1]x/?".to_owned(),
            "https://[]/?".to_owned(),
            "https://[::g]/?".to_owned(),
            "https://a%41.test/?".to_owned(),
            "https://::1/?".to_owned(),
        ];
        for value in &mut values {
            value.push_str(&format!("cert_sha256={FP}"));
        }
        for value in values {
            assert_eq!(uri(&value).map(|_| ()), Err(UriError::Host), "{value}");
        }
    }

    #[test]
    fn ipv6_hosts_are_canonicalised_in_the_origin() {
        for (value, origin) in [
            (
                url("https://[2001:DB8:0:0:0:0:0:1]/?"),
                "https://[2001:db8::1]",
            ),
            (
                url("https://[2001:0db8::0001]:8443/?"),
                "https://[2001:db8::1]:8443",
            ),
            (url("https://[0:0::1]/?"), "https://[::1]"),
            (
                url("https://[::FFFF:C000:0201]/?"),
                "https://[::ffff:192.0.2.1]",
            ),
        ] {
            let parsed = uri(&value).unwrap_or_else(|error| panic!("{value}: {error:?}"));
            assert_eq!(*parsed.url, value);
            assert_eq!(*parsed.origin, origin, "{value}");
        }
    }

    #[test]
    fn brackets_appear_only_around_an_ipv6_host() {
        for value in [
            url("https://a.test/[x]?"),
            url("https://a.test/?q=[&"),
            url("https://[::1]/]?"),
            url("https://[::1]/?a=[::1]&"),
        ] {
            assert_eq!(uri(&value).map(|_| ()), Err(UriError::Bracket), "{value}");
        }
    }

    #[test]
    fn percent_encoding_must_be_complete_and_decode_to_no_control_character() {
        for value in [
            url("https://a.test/%?"),
            url("https://a.test/%4?"),
            url("https://a.test/%zz?"),
            url("https://a.test/%%41?"),
            url("https://a.test/?q=%&"),
            format!("https://a.test/?cert_sha256={FP}&q=%4"),
        ] {
            assert_eq!(uri(&value).map(|_| ()), Err(UriError::Percent), "{value}");
        }
        for value in [
            url("https://a.test/a%00b?"),
            url("https://a.test/%1f?"),
            url("https://a.test/%7F/?"),
            url("https://a.test/?q=%0A&"),
            url("https://a.test/?q=a%0d%0aSet-Cookie:x&"),
            url("https://a.test/?%09=1&"),
            format!("https://a.test/?cert_sha256={FP}&q=%7f"),
        ] {
            assert_eq!(uri(&value).map(|_| ()), Err(UriError::Control), "{value}");
        }
    }

    #[test]
    fn the_query_names_the_certificate_exactly_once_with_literal_lowercase_hex() {
        let upper = FP.to_ascii_uppercase();
        let encoded: String = FP.bytes().map(|b| format!("%{b:02x}")).collect();
        for value in [
            "https://a.test/".to_owned(),
            "https://a.test/?x=1".to_owned(),
            format!("https://a.test/cert_sha256={FP}"),
            format!("https://a.test/?cert_sha256={FP}&cert_sha256={FP}"),
            format!("https://a.test/?cert_sha256={FP}&cert%5Fsha256={FP}"),
            format!("https://a.test/?cert_sha256={FP}&cert_sha256"),
            format!("https://a.test/?cert_sha256={upper}"),
            format!("https://a.test/?cert_sha256={encoded}"),
            format!("https://a.test/?cert_sha256={}", &FP[1..]),
            format!("https://a.test/?cert_sha256={FP}0"),
            format!("https://a.test/?cert_sha256={FP}=x"),
            "https://a.test/?cert_sha256=".to_owned(),
            "https://a.test/?cert_sha256".to_owned(),
        ] {
            assert_eq!(uri(&value).map(|_| ()), Err(UriError::CertKey), "{value}");
        }
    }

    #[test]
    fn keys_resembling_the_reserved_names_are_rejected() {
        for key in [
            "CERT_SHA256",
            "Cert_Sha256",
            "CERT%5FSHA256",
            "user_code",
            "USER_CODE",
            "User_Code",
            "user%5Fcode",
            "user%5fcode",
            "%75ser_code",
        ] {
            for value in [
                format!("https://a.test/?cert_sha256={FP}&{key}=WDJB-MJHT"),
                format!("https://a.test/?{key}&cert_sha256={FP}"),
            ] {
                assert_eq!(
                    uri(&value).map(|_| ()),
                    Err(UriError::ReservedKey),
                    "{value}"
                );
            }
        }
    }

    #[test]
    fn user_codes_are_two_groups_of_four_consonants() {
        for value in ["WDJB-MJHT", "BCDF-ZZZZ", "XWVT-SRQP"] {
            assert_eq!(
                user_code(value.as_bytes()).as_deref().map(String::as_str),
                Some(value)
            );
        }
        for value in [
            "",
            "wdjb-mjht",
            "WDJb-MJHT",
            "WDJB-MJHt",
            "AWDJ-MJHT",
            "WDJB-MJHE",
            "WDJB-MJHY",
            "WDJB-MJH1",
            "WDJBMJHT",
            "WDJB-MJH",
            "WDJ-BMJHT",
            "WDJB-MJHTX",
            "XWDJB-MJHT",
            "WDJB_MJHT",
            "WDJB MJHT",
            "WDJB--JHT",
        ] {
            assert_eq!(user_code(value.as_bytes()), None, "{value}");
        }
    }

    #[test]
    fn expiry_is_one_to_ten_digits_clamped_to_ten_minutes() {
        for (value, expected) in [
            ("1", 1),
            ("300", 300),
            ("600", 600),
            ("601", 600),
            ("1800", 600),
            ("9999999999", 600),
        ] {
            assert_eq!(expires_in(value.as_bytes()), Some(expected), "{value}");
        }
        for value in [
            "",
            "0",
            "01",
            "00",
            "10000000000",
            "+1",
            "-1",
            "1.5",
            " 1",
            "1 ",
            "1e3",
            "a",
        ] {
            assert_eq!(expires_in(value.as_bytes()), None, "{value:?}");
        }
    }

    #[test]
    fn verification_origins_are_stored_with_lowercase_host_and_without_port_443() {
        for (entry, stored) in [
            ("https://verify.example.test", "https://verify.example.test"),
            (
                "https://Verify.Example.TEST:443",
                "https://verify.example.test",
            ),
            (
                "HTTPS://login.example.test:8443",
                "https://login.example.test:8443",
            ),
            ("https://127.0.0.1", "https://127.0.0.1"),
            ("https://[::1]:8443", "https://[::1]:8443"),
            ("https://[2001:DB8::1]", "https://[2001:db8::1]"),
            ("https://[2001:db8:0:0::0001]", "https://[2001:db8::1]"),
            ("https://[0::1]:8443", "https://[::1]:8443"),
        ] {
            let origin: VerificationOrigin = entry.parse().unwrap();
            assert_eq!(origin.as_str(), stored, "{entry}");
        }
        for entry in [
            "",
            "https://",
            "http://verify.example.test",
            "verify.example.test",
            "https://verify.example.test/",
            "https://verify.example.test/path",
            "https://verify.example.test?",
            "https://verify.example.test?x=1",
            "https://verify.example.test#",
            "https://verify.example.test.",
            "https://verify.example.test.:443",
            "https://*.example.test",
            "https://*",
            "https://user@verify.example.test",
            "https://verify.example.test:0",
            "https://verify.example.test:0443",
            "https://verify.example.test:",
            "https://[::1%25eth0]",
            "https://0x7f.1",
            " https://verify.example.test",
        ] {
            assert!(entry.parse::<VerificationOrigin>().is_err(), "{entry:?}");
        }
    }

    #[test]
    fn the_origin_must_match_a_listed_one_exactly() {
        let listed = origins(&["https://verify.example.test"]);
        let check = |prefix: &str| {
            let value = header(&url(prefix));
            parse(&[value.as_bytes()], FP, Some(&listed))
        };
        for prefix in [
            "https://verify.example.test/?",
            "https://verify.example.test:443/?",
            "https://VERIFY.Example.test/?",
        ] {
            assert!(check(prefix).is_ok(), "{prefix}");
        }
        for prefix in [
            "https://example.test/?",
            "https://xverify.example.test/?",
            "https://verify.example.test.evil/?",
            "https://verify.example.test:8443/?",
        ] {
            assert_eq!(check(prefix), Err(Invalid::Origin), "{prefix}");
        }
        assert_eq!(
            check("https://verify.example.test./?"),
            Err(Invalid::AuthUri(UriError::Host))
        );
        let ipv6 = origins(&["https://[2001:db8:0::1]"]);
        let value = header(&url("https://[2001:DB8::0:1]/?"));
        assert!(parse(&[value.as_bytes()], FP, Some(&ipv6)).is_ok());
        let with_port = origins(&["https://verify.example.test:443"]);
        let value = standard();
        assert!(parse(&[value.as_bytes()], FP, Some(&with_port)).is_ok());
        assert_eq!(
            parse(&[value.as_bytes()], FP, Some(&[])),
            Err(Invalid::Origin)
        );
        let other = origins(&[
            "https://login.example.test:8443",
            "https://verify.example.test",
        ]);
        assert!(parse(&[value.as_bytes()], FP, Some(&other)).is_ok());
    }
}
