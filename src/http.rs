use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

pub const DEFAULT_MAX_HEADER_BYTES: usize = 16384;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    Malformed,
    TooLarge,
    MethodNotAllowed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    Name(String),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authority {
    pub host: Host,
    pub port: u16,
}

impl fmt::Display for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Host::Name(name) => write!(f, "{name}:{}", self.port),
            Host::Ipv4(ip) => write!(f, "{ip}:{}", self.port),
            Host::Ipv6(ip) => write!(f, "[{ip}]:{}", self.port),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidAuthority;

impl fmt::Display for InvalidAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected host:port with a port from 1 to 65535")
    }
}

impl std::error::Error for InvalidAuthority {}

impl FromStr for Authority {
    type Err = InvalidAuthority;

    fn from_str(target: &str) -> Result<Self, Self::Err> {
        parse_authority(target.as_bytes()).ok_or(InvalidAuthority)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed<T> {
    pub value: T,
    pub head_len: usize,
}

pub type ParseResult<T> = Result<Option<Parsed<T>>, ParseError>;

#[derive(Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    pub target: Authority,
    pub proxy_authorization: Option<Vec<u8>>,
}

impl fmt::Debug for ConnectRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectRequest")
            .field("target", &self.target)
            .field(
                "proxy_authorization",
                &self.proxy_authorization.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

pub fn parse_connect_request(buf: &[u8], max_header_bytes: usize) -> ParseResult<ConnectRequest> {
    let Some(head_len) = head_len(buf, max_header_bytes)? else {
        return Ok(None);
    };
    let mut lines = lines(&buf[..head_len]);
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.splitn(3, |&b| b == b' ');
    let (method, target, version) = match (parts.next(), parts.next(), parts.next()) {
        (Some(method), Some(target), Some(version)) => (method, target, version),
        _ => return Err(ParseError::Malformed),
    };
    if !is_token(method) || version != b"HTTP/1.1" {
        return Err(ParseError::Malformed);
    }
    let fields = lines.map(parse_field).collect::<Result<Vec<_>, _>>()?;
    if method != b"CONNECT" {
        return Err(ParseError::MethodNotAllowed);
    }
    let count = |name: &[u8]| {
        fields
            .iter()
            .filter(|field| field.name.eq_ignore_ascii_case(name))
            .count()
    };
    let content_length_ok = fields
        .iter()
        .filter(|field| field.name.eq_ignore_ascii_case(b"content-length"))
        .all(|field| field.value == b"0");
    if count(b"host") != 1
        || count(b"proxy-authorization") > 1
        || count(b"transfer-encoding") != 0
        || count(b"content-length") > 1
        || !content_length_ok
    {
        return Err(ParseError::Malformed);
    }
    let target = parse_authority(target).ok_or(ParseError::Malformed)?;
    let proxy_authorization = fields
        .iter()
        .find(|field| field.name.eq_ignore_ascii_case(b"proxy-authorization"))
        .map(|field| field.value.to_vec());
    Ok(Some(Parsed {
        value: ConnectRequest {
            target,
            proxy_authorization,
        },
        head_len,
    }))
}

pub fn parse_response(buf: &[u8], max_header_bytes: usize) -> ParseResult<u16> {
    let Some(head_len) = head_len(buf, max_header_bytes)? else {
        return Ok(None);
    };
    let mut lines = lines(&buf[..head_len]);
    let status_line = lines.next().unwrap_or_default();
    let rest = status_line
        .strip_prefix(b"HTTP/1.1 ")
        .ok_or(ParseError::Malformed)?;
    let value = match rest {
        [
            a @ b'1'..=b'5',
            b @ b'0'..=b'9',
            c @ b'0'..=b'9',
            b' ',
            reason @ ..,
        ] if reason.iter().copied().all(is_field_byte) => {
            u16::from(a - b'0') * 100 + u16::from(b - b'0') * 10 + u16::from(c - b'0')
        }
        _ => return Err(ParseError::Malformed),
    };
    for line in lines {
        parse_field(line)?;
    }
    Ok(Some(Parsed { value, head_len }))
}

pub fn parse_status_line(buf: &[u8], max_header_bytes: usize) -> ParseResult<(u16, String)> {
    Ok(parse_response(buf, max_header_bytes)?.map(|parsed| {
        let line = lines(&buf[..parsed.head_len]).next().unwrap_or_default();
        Parsed {
            value: (parsed.value, String::from_utf8_lossy(line).into_owned()),
            head_len: parsed.head_len,
        }
    }))
}

fn head_len(buf: &[u8], max_header_bytes: usize) -> Result<Option<usize>, ParseError> {
    let window = &buf[..buf.len().min(max_header_bytes)];
    for (i, &byte) in window.iter().enumerate() {
        match byte {
            0 => return Err(ParseError::Malformed),
            b'\r' if window.get(i + 1).is_some_and(|&next| next != b'\n') => {
                return Err(ParseError::Malformed);
            }
            b'\n' if i == 0 || window[i - 1] != b'\r' => return Err(ParseError::Malformed),
            b'\n' if i >= 3 && window[i - 3..i] == *b"\r\n\r" => return Ok(Some(i + 1)),
            _ => {}
        }
    }
    if buf.len() >= max_header_bytes {
        Err(ParseError::TooLarge)
    } else {
        Ok(None)
    }
}

fn lines(head: &[u8]) -> impl Iterator<Item = &[u8]> {
    head[..head.len() - 4]
        .split(|&b| b == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
}

struct Field<'a> {
    name: &'a [u8],
    value: &'a [u8],
}

fn parse_field(line: &[u8]) -> Result<Field<'_>, ParseError> {
    let colon = line
        .iter()
        .position(|&b| b == b':')
        .ok_or(ParseError::Malformed)?;
    let (name, value) = (&line[..colon], &line[colon + 1..]);
    if !is_token(name) || !value.iter().copied().all(is_field_byte) {
        return Err(ParseError::Malformed);
    }
    Ok(Field {
        name,
        value: value.trim_ascii(),
    })
}

pub(crate) fn is_token(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn is_field_byte(byte: u8) -> bool {
    matches!(byte, b'\t' | b' '..=b'~' | 0x80..=0xff)
}

fn parse_authority(target: &[u8]) -> Option<Authority> {
    let target = std::str::from_utf8(target).ok()?;
    let (host, port) = match target.strip_prefix('[') {
        Some(rest) => {
            let (ip, port) = rest.split_once("]:")?;
            (Host::Ipv6(ip.parse().ok()?), port)
        }
        None => {
            let (host, port) = target.split_once(':')?;
            (parse_host(host)?, port)
        }
    };
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let port = port.parse().ok().filter(|&port| port != 0)?;
    Some(Authority { host, port })
}

fn parse_host(host: &str) -> Option<Host> {
    if host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return host.parse().ok().map(Host::Ipv4);
    }
    let valid_label = |label: &str| {
        (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    };
    (host.len() <= 253 && host.split('.').all(valid_label)).then(|| Host::Name(host.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX: usize = DEFAULT_MAX_HEADER_BYTES;

    fn request(buf: &[u8]) -> ParseResult<ConnectRequest> {
        parse_connect_request(buf, MAX)
    }

    fn authority(target: &str) -> Result<Authority, ParseError> {
        let head = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
        request(head.as_bytes()).map(|parsed| parsed.unwrap().value.target)
    }

    fn connect(target: Authority) -> ConnectRequest {
        ConnectRequest {
            target,
            proxy_authorization: None,
        }
    }

    fn name(host: &str, port: u16) -> Authority {
        Authority {
            host: Host::Name(host.to_owned()),
            port,
        }
    }

    #[test]
    fn parses_connect_with_hostname() {
        let head = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        assert_eq!(
            request(head),
            Ok(Some(Parsed {
                value: connect(name("example.com", 443)),
                head_len: head.len(),
            }))
        );
    }

    #[test]
    fn reports_head_length_and_leaves_following_bytes() {
        let mut buf = b"CONNECT a.test:1 HTTP/1.1\r\nHost: a.test:1\r\n\r\n".to_vec();
        let head_len = buf.len();
        buf.extend_from_slice(b"\x16\x03\x01early");
        assert_eq!(request(&buf).unwrap().unwrap().head_len, head_len);
    }

    #[test]
    fn incomplete_head_needs_more_data() {
        assert_eq!(request(b""), Ok(None));
        assert_eq!(request(b"CONNECT a.test:1 HTTP/1.1\r\nHost: a"), Ok(None));
        assert_eq!(request(b"CONNECT a.test:1 HTTP/1.1\r\n\r"), Ok(None));
    }

    #[test]
    fn accepts_ip_literals_and_port_bounds() {
        assert_eq!(
            authority("192.0.2.1:1"),
            Ok(Authority {
                host: Host::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
                port: 1
            })
        );
        assert_eq!(
            authority("[2001:db8::1]:65535"),
            Ok(Authority {
                host: Host::Ipv6("2001:db8::1".parse().unwrap()),
                port: 65535
            })
        );
        assert_eq!(authority("a-b.c0.test:8080"), Ok(name("a-b.c0.test", 8080)));
        assert_eq!(authority("localhost:22"), Ok(name("localhost", 22)));
    }

    #[test]
    fn formats_authority_for_forwarding() {
        assert_eq!(authority("[::1]:443").unwrap().to_string(), "[::1]:443");
        assert_eq!(
            authority("192.0.2.1:80").unwrap().to_string(),
            "192.0.2.1:80"
        );
        assert_eq!(
            authority("example.com:443").unwrap().to_string(),
            "example.com:443"
        );
    }

    #[test]
    fn rejects_invalid_authorities() {
        for target in [
            "example.com",
            "example.com:",
            "example.com:0",
            "example.com:65536",
            "example.com:+443",
            "example.com:44a",
            "example.com:000443",
            ":443",
            "user@example.com:443",
            "example.com:443/path",
            "http://example.com:443",
            "2001:db8::1:443",
            "[2001:db8::1]",
            "[2001:db8::1]443",
            "[fe80::1%eth0]:443",
            "[192.0.2.1]:443",
            "[example.com]:443",
            "256.0.0.1:443",
            "1.2.3:443",
            "01.2.3.4:443",
            "-example.com:443",
            "example-.com:443",
            "exa_mple.com:443",
            "example..com:443",
            "example.com.:443",
            ".example.com:443",
            "*.example.com:443",
        ] {
            assert_eq!(authority(target), Err(ParseError::Malformed), "{target}");
        }
        let long_label = format!("{}.test:443", "a".repeat(64));
        assert_eq!(authority(&long_label), Err(ParseError::Malformed));
        let long_name = format!("{}a:443", "a.".repeat(127));
        assert_eq!(authority(&long_name), Err(ParseError::Malformed));
    }

    #[test]
    fn other_methods_are_not_allowed() {
        for head in [
            &b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"[..],
            b"POST / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            b"connect example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
        ] {
            assert_eq!(request(head), Err(ParseError::MethodNotAllowed));
        }
    }

    #[test]
    fn rejects_malformed_request_lines() {
        for head in [
            &b"CONNECT example.com:443 HTTP/1.0\r\nHost: example.com:443\r\n\r\n"[..],
            b"CONNECT example.com:443 HTTP/2\r\nHost: example.com:443\r\n\r\n",
            b"CONNECT example.com:443\r\nHost: example.com:443\r\n\r\n",
            b"CONNECT  example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
            b"CONNECT example.com:443 HTTP/1.1 \r\nHost: example.com:443\r\n\r\n",
            b" CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
            b"CONNECT\texample.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
            b"\r\nCONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
            b"G(T / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            b"\r\n\r\n",
        ] {
            assert_eq!(
                request(head),
                Err(ParseError::Malformed),
                "{}",
                String::from_utf8_lossy(head)
            );
        }
    }

    #[test]
    fn rejects_bare_line_feeds() {
        assert_eq!(
            request(b"CONNECT a.test:1 HTTP/1.1\nHost: a.test:1\r\n\r\n"),
            Err(ParseError::Malformed)
        );
        assert_eq!(
            request(b"CONNECT a.test:1 HTTP/1.1\r\nHost: a.test:1\n\n"),
            Err(ParseError::Malformed)
        );
        assert_eq!(
            request(b"CONNECT a.test:1 HTTP/1.1\n"),
            Err(ParseError::Malformed)
        );
    }

    #[test]
    fn rejects_carriage_returns_inside_fields() {
        assert_eq!(
            request(b"CONNECT a.test:1 HTTP/1.1\r\nHost: a.test:1\rX: y\r\n\r\n"),
            Err(ParseError::Malformed)
        );
        assert_eq!(
            request(b"CONNECT a.test:1\r HTTP/1.1\r\nHost: a.test:1\r\n\r\n"),
            Err(ParseError::Malformed)
        );
        assert_eq!(
            request(b"CONNECT a.test:1 HTTP/1.1\r"),
            Ok(None),
            "a trailing CR may still be followed by LF"
        );
    }

    #[test]
    fn rejects_nul_bytes() {
        assert_eq!(
            request(b"CONNECT a.test:1 HTTP/1.1\r\nHost: a.test:1\r\nX: a\0b\r\n\r\n"),
            Err(ParseError::Malformed)
        );
        assert_eq!(
            request(b"CONNECT a.test:1\0"),
            Err(ParseError::Malformed),
            "NUL is rejected before the head is complete"
        );
    }

    #[test]
    fn rejects_obs_fold() {
        assert_eq!(
            request(b"CONNECT a.test:1 HTTP/1.1\r\nHost: a.test:1\r\nX: a\r\n b\r\n\r\n"),
            Err(ParseError::Malformed)
        );
        assert_eq!(
            request(b"CONNECT a.test:1 HTTP/1.1\r\nHost: a.test:1\r\nX: a\r\n\tb\r\n\r\n"),
            Err(ParseError::Malformed)
        );
    }

    #[test]
    fn rejects_malformed_header_fields() {
        for field in [
            &b"NoColon"[..],
            b": empty-name",
            b"Bad Name: x",
            b"Bad\tName: x",
            b"Name : x",
            b"X: a\x01b",
            b"X: a\x7fb",
            b"X: a\x1bb",
        ] {
            let mut head = b"CONNECT a.test:1 HTTP/1.1\r\nHost: a.test:1\r\n".to_vec();
            head.extend_from_slice(field);
            head.extend_from_slice(b"\r\n\r\n");
            assert_eq!(
                request(&head),
                Err(ParseError::Malformed),
                "{}",
                String::from_utf8_lossy(field)
            );
        }
    }

    #[test]
    fn accepts_valid_header_values() {
        let head = b"CONNECT a.test:1 HTTP/1.1\r\nHost: a.test:1\r\nUser-Agent:\tcurl/8 (x)\t \r\nX-Obs: caf\xc3\xa9\r\nX-Empty:\r\nProxy-Connection: Keep-Alive\r\n\r\n";
        assert_eq!(
            request(head).unwrap().unwrap().value,
            connect(name("a.test", 1))
        );
    }

    #[test]
    fn requires_exactly_one_host_header() {
        assert_eq!(
            request(b"CONNECT a.test:1 HTTP/1.1\r\n\r\n"),
            Err(ParseError::Malformed)
        );
        assert_eq!(
            request(b"CONNECT a.test:1 HTTP/1.1\r\nHost: a.test:1\r\nhost: a.test:1\r\n\r\n"),
            Err(ParseError::Malformed)
        );
        assert_eq!(
            request(b"CONNECT a.test:1 HTTP/1.1\r\nHOST: a.test:1\r\n\r\n")
                .unwrap()
                .unwrap()
                .value
                .target,
            name("a.test", 1)
        );
    }

    #[test]
    fn rejects_request_content() {
        assert_eq!(
            request(b"CONNECT a.test:1 HTTP/1.1\r\nHost: a.test:1\r\nTransfer-Encoding: chunked\r\n\r\n"),
            Err(ParseError::Malformed)
        );
        assert_eq!(
            request(b"CONNECT a.test:1 HTTP/1.1\r\nHost: a.test:1\r\nContent-Length: 5\r\n\r\n"),
            Err(ParseError::Malformed)
        );
        assert_eq!(
            request(
                b"CONNECT a.test:1 HTTP/1.1\r\nHost: a.test:1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n"
            ),
            Err(ParseError::Malformed)
        );
        assert!(
            request(b"CONNECT a.test:1 HTTP/1.1\r\nHost: a.test:1\r\nContent-Length: 0\r\n\r\n")
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn returns_the_proxy_authorization_value() {
        let head = b"CONNECT a.test:1 HTTP/1.1\r\nHost: a.test:1\r\nproxy-authorization:  Basic dTpw \r\n\r\n";
        assert_eq!(
            request(head).unwrap().unwrap().value,
            ConnectRequest {
                target: name("a.test", 1),
                proxy_authorization: Some(b"Basic dTpw".to_vec()),
            }
        );
    }

    #[test]
    fn debug_output_redacts_the_proxy_authorization() {
        let head = b"CONNECT a.test:1 HTTP/1.1\r\nHost: a.test:1\r\nProxy-Authorization: Basic c2VjcmV0OnB3\r\n\r\n";
        let debug = format!("{:?}", request(head).unwrap().unwrap());
        assert!(!debug.contains("c2VjcmV0OnB3"), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");
    }

    #[test]
    fn rejects_more_than_one_proxy_authorization() {
        assert_eq!(
            request(
                b"CONNECT a.test:1 HTTP/1.1\r\nHost: a.test:1\r\nProxy-Authorization: Basic dTpw\r\nProxy-Authorization: Basic dTpw\r\n\r\n"
            ),
            Err(ParseError::Malformed)
        );
    }

    fn padded_request(total: usize) -> Vec<u8> {
        let prefix = b"CONNECT a.test:1 HTTP/1.1\r\nHost: a.test:1\r\nX-Pad: ";
        let suffix = b"\r\n\r\n";
        let mut head = prefix.to_vec();
        head.resize(total - suffix.len(), b'p');
        head.extend_from_slice(suffix);
        head
    }

    #[test]
    fn enforces_header_size_limit() {
        assert!(
            parse_connect_request(&padded_request(64), 64)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            parse_connect_request(&padded_request(65), 64),
            Err(ParseError::TooLarge)
        );
        assert_eq!(
            parse_connect_request(&padded_request(MAX + 1)[..MAX], MAX),
            Err(ParseError::TooLarge),
            "an unterminated head at the limit cannot become valid"
        );
        assert_eq!(
            parse_connect_request(&padded_request(MAX + 1)[..MAX - 1], MAX),
            Ok(None)
        );
        assert!(request(&padded_request(MAX)).unwrap().is_some());
        assert_eq!(request(&padded_request(MAX + 1)), Err(ParseError::TooLarge));
    }

    #[test]
    fn enforces_header_size_limit_on_the_request_line() {
        let target = format!("{}.test:65535", "a".repeat(63));
        let head = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
        let head = head.as_bytes();
        assert!(parse_connect_request(head, head.len()).unwrap().is_some());
        assert_eq!(
            parse_connect_request(head, head.len() - 1),
            Err(ParseError::TooLarge)
        );
        let line = format!("CONNECT {target} HTTP/1.1");
        let line = line.as_bytes();
        assert_eq!(
            parse_connect_request(line, line.len()),
            Err(ParseError::TooLarge),
            "an unterminated request line at the limit cannot become valid"
        );
        assert_eq!(parse_connect_request(line, line.len() + 1), Ok(None));
    }

    #[test]
    fn size_limit_ignores_bytes_after_the_head() {
        let mut buf = padded_request(64);
        buf.extend_from_slice(&[0; 1000]);
        assert_eq!(
            parse_connect_request(&buf, 64).unwrap().unwrap().head_len,
            64
        );
    }

    #[test]
    fn parses_response_status() {
        let head = b"HTTP/1.1 200 Connection established\r\n\r\ntrailing";
        assert_eq!(
            parse_response(head, MAX),
            Ok(Some(Parsed {
                value: 200,
                head_len: head.len() - b"trailing".len(),
            }))
        );
        assert_eq!(
            parse_response(
                b"HTTP/1.1 407 \r\nProxy-Authenticate: Basic realm=\"x\"\r\nContent-Length: 3\r\n\r\n",
                MAX
            )
            .unwrap()
            .unwrap()
            .value,
            407
        );
        assert_eq!(parse_response(b"HTTP/1.1 200 OK\r\n", MAX), Ok(None));
    }

    #[test]
    fn rejects_malformed_responses() {
        for head in [
            &b"HTTP/1.0 200 OK\r\n\r\n"[..],
            b"HTTP/1.1 200\r\n\r\n",
            b"HTTP/1.1 20 OK\r\n\r\n",
            b"HTTP/1.1 2000 OK\r\n\r\n",
            b"HTTP/1.1 600 OK\r\n\r\n",
            b"HTTP/1.1 099 OK\r\n\r\n",
            b"HTTP/1.1 2x0 OK\r\n\r\n",
            b"HTTP/1.1  200 OK\r\n\r\n",
            b"http/1.1 200 OK\r\n\r\n",
            b"HTTP/1.1 200 O\x01K\r\n\r\n",
            b"HTTP/1.1 200 OK\nX: y\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX: a\rb\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX: a\0b\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX: a\r\n b\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nBad Name: x\r\n\r\n",
        ] {
            assert_eq!(
                parse_response(head, MAX),
                Err(ParseError::Malformed),
                "{}",
                String::from_utf8_lossy(head)
            );
        }
    }

    #[test]
    fn enforces_response_size_limit() {
        let mut head = b"HTTP/1.1 200 OK\r\nX-Pad: ".to_vec();
        head.resize(60, b'p');
        head.extend_from_slice(b"\r\n\r\n");
        assert!(parse_response(&head, 64).unwrap().is_some());
        assert_eq!(parse_response(&head, 63), Err(ParseError::TooLarge));
        assert_eq!(parse_response(&head[..63], 63), Err(ParseError::TooLarge));
    }

    #[test]
    fn authority_parses_from_a_target_string() {
        assert_eq!(
            "example.test:443".parse::<Authority>(),
            Ok(Authority {
                host: Host::Name("example.test".to_owned()),
                port: 443
            })
        );
        assert_eq!(
            "[::1]:8443".parse::<Authority>().unwrap().to_string(),
            "[::1]:8443"
        );
        for invalid in ["example.test", "example.test:0", "a b:1", ""] {
            assert_eq!(
                invalid.parse::<Authority>(),
                Err(InvalidAuthority),
                "{invalid}"
            );
        }
    }

    #[test]
    fn status_line_is_returned_with_the_status() {
        let parsed = parse_status_line(
            b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\nbody",
            MAX,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            parsed.value,
            (407, "HTTP/1.1 407 Proxy Authentication Required".to_owned())
        );
        assert_eq!(parsed.head_len, 73);
        assert_eq!(
            parse_status_line(b"HTTP/1.0 200 OK\r\n\r\n", MAX),
            Err(ParseError::Malformed)
        );
        assert_eq!(parse_status_line(b"HTTP/1.1 200 OK\r\n", MAX), Ok(None));
    }
}
