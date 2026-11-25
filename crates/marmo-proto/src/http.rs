//! HTTP/1.1 request and CONNECT response helpers.
//!
//! The inbound is deliberately small: one request per connection, absolute-form
//! forward targets, and CONNECT tunnels. Headers are copied into bounded owned
//! values so the parser has no lifetime coupling to the read buffer and can be
//! fuzzed in isolation.

use std::fmt;

use marmo_net::Endpoint;
use thiserror::Error;

/// Largest accepted request head, including the final CRLFCRLF.
pub const HEAD_MAX: usize = 8192;
/// Largest rewritten forward head.
pub const FORWARD_HEAD_MAX: usize = HEAD_MAX + 1024;
/// Largest header count in one request or response.
pub const MAX_HEADERS: usize = 64;

/// One parsed header borrowed from the request buffer.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Header<'a> {
    /// Field name as sent by the peer.
    pub name: &'a str,
    /// Raw field value as sent by the peer.
    pub value: &'a [u8],
}

impl fmt::Debug for Header<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Header")
            .field("name", &self.name)
            .field("value_len", &self.value.len())
            .finish()
    }
}

/// A parsed request head borrowed from the input buffer.
#[derive(Clone, Eq, PartialEq)]
pub struct RequestHead<'a> {
    /// Request method.
    pub method: &'a str,
    /// Request target, in origin or absolute form.
    pub target: &'a str,
    /// HTTP minor version (`0` for HTTP/1.0, `1` for HTTP/1.1).
    pub version: u8,
    headers: [Header<'a>; MAX_HEADERS],
    count: usize,
}

impl fmt::Debug for RequestHead<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestHead")
            .field("method", &self.method)
            .field("target", &self.target)
            .field("version", &self.version)
            .field("header_count", &self.count)
            .finish()
    }
}

impl<'a> RequestHead<'a> {
    /// Parsed headers in wire order.
    #[must_use]
    pub fn headers(&self) -> &[Header<'a>] {
        &self.headers[..self.count]
    }
}

const EMPTY_HEADER: Header<'static> = Header {
    name: "",
    value: &[],
};

/// An absolute-form forward target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbsoluteTarget<'a> {
    /// Destination endpoint.
    pub endpoint: Endpoint,
    /// Original authority (`host[:port]`).
    pub authority: &'a str,
    /// Origin-form path and query.
    pub path: &'a str,
    /// Whether a bare `?query` target needs a leading slash.
    pub needs_slash: bool,
}

/// Why an HTTP/1 head was rejected.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HttpError {
    /// The head is incomplete.
    #[error("incomplete HTTP head")]
    Incomplete,
    /// The head is larger than [`HEAD_MAX`].
    #[error("HTTP head is too large")]
    TooLarge,
    /// The request or response has too many headers.
    #[error("too many HTTP headers")]
    TooManyHeaders,
    /// The request line or headers are malformed.
    #[error("invalid HTTP request")]
    BadRequest,
    /// The request target is not an absolute `http://` URI.
    #[error("unsupported HTTP scheme")]
    UnsupportedScheme,
    /// The HTTP version is not 1.0 or 1.1.
    #[error("unsupported HTTP version")]
    UnsupportedVersion,
    /// The CONNECT response is malformed.
    #[error("invalid HTTP CONNECT response")]
    InvalidResponse,
}

/// Finds the end of a head, returning the index of the final CRLFCRLF.
#[must_use]
pub fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

/// Parses and validates one request head.
///
/// `input` may contain the whole head; bytes after the head are ignored. The
/// caller should pass at most [`HEAD_MAX`] bytes.
pub fn parse_request(input: &[u8]) -> Result<RequestHead<'_>, HttpError> {
    if input.len() > HEAD_MAX {
        return Err(HttpError::TooLarge);
    }
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(input) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) => return Err(HttpError::Incomplete),
        Err(httparse::Error::TooManyHeaders) => return Err(HttpError::TooManyHeaders),
        Err(_) => return Err(HttpError::BadRequest),
    }

    let method = request.method.ok_or(HttpError::BadRequest)?;
    let target = request.path.ok_or(HttpError::BadRequest)?;
    let version = request.version.ok_or(HttpError::BadRequest)?;
    if version > 1 {
        return Err(HttpError::UnsupportedVersion);
    }
    if !is_token(method) || target.is_empty() {
        return Err(HttpError::BadRequest);
    }
    if target.bytes().any(|byte| byte <= 0x20 || byte == 0x7f) {
        return Err(HttpError::BadRequest);
    }

    let mut parsed = [EMPTY_HEADER; MAX_HEADERS];
    for (index, header) in request.headers.iter().enumerate() {
        if !is_token(header.name) || !is_valid_header_value(header.value) {
            return Err(HttpError::BadRequest);
        }
        parsed[index] = Header {
            name: header.name,
            value: header.value,
        };
    }

    Ok(RequestHead {
        method,
        target,
        version,
        headers: parsed,
        count: request.headers.len(),
    })
}

/// Parses one CONNECT response head and returns its status and head length.
///
/// Bytes after the head are not consumed by this function.
pub fn parse_connect_response(input: &[u8]) -> Result<(u16, usize), HttpError> {
    if input.len() > HEAD_MAX {
        return Err(HttpError::TooLarge);
    }
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut response = httparse::Response::new(&mut headers);
    let consumed = match response.parse(input) {
        Ok(httparse::Status::Complete(consumed)) => consumed,
        Ok(httparse::Status::Partial) => return Err(HttpError::Incomplete),
        Err(httparse::Error::TooManyHeaders) => return Err(HttpError::TooManyHeaders),
        Err(_) => return Err(HttpError::InvalidResponse),
    };
    let status = response.code.ok_or(HttpError::InvalidResponse)?;
    Ok((status, consumed))
}

/// Parses an absolute-form `http://` target.
pub fn parse_absolute(uri: &str) -> Result<AbsoluteTarget<'_>, HttpError> {
    match uri.get(..7) {
        Some(scheme) if scheme.eq_ignore_ascii_case("http://") => {}
        _ => return Err(HttpError::UnsupportedScheme),
    }
    for byte in uri.bytes() {
        if byte <= 0x20 || byte == 0x7f || byte == b'#' {
            return Err(HttpError::BadRequest);
        }
    }
    let rest = &uri[7..];
    let authority_end = rest
        .bytes()
        .position(|byte| byte == b'/' || byte == b'?')
        .unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return Err(HttpError::BadRequest);
    }
    let endpoint = parse_authority(authority)?;

    let (path, needs_slash) = if authority_end == rest.len() {
        ("/", false)
    } else if rest.as_bytes()[authority_end] == b'/' {
        (&rest[authority_end..], false)
    } else {
        (&rest[authority_end..], true)
    };

    Ok(AbsoluteTarget {
        endpoint,
        authority,
        path,
        needs_slash,
    })
}

/// Rewrites a forward request from absolute form to origin form.
pub fn build_forward_head(
    method: &str, version: u8, target: &AbsoluteTarget<'_>, headers: &[Header<'_>],
) -> Result<Vec<u8>, HttpError> {
    if !is_token(method) || version > 1 {
        return Err(HttpError::BadRequest);
    }
    // `AbsoluteTarget` has public fields. Reject control characters here so a
    // caller cannot turn the request line or Host header into an injection.
    if target.authority.is_empty()
        || target.path.is_empty()
        || target
            .authority
            .bytes()
            .any(|byte| byte <= 0x20 || byte == 0x7f)
        || target.path.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
    {
        return Err(HttpError::BadRequest);
    }
    let mut head = Vec::with_capacity(FORWARD_HEAD_MAX);
    head.extend_from_slice(method.as_bytes());
    head.push(b' ');
    if target.needs_slash {
        head.push(b'/');
    }
    head.extend_from_slice(target.path.as_bytes());
    head.extend_from_slice(b" HTTP/1.");
    head.push(b'0' + version);
    head.extend_from_slice(b"\r\n");

    let connection_tokens = connection_tokens(headers);
    let mut has_content_length = false;
    let mut has_transfer_encoding = false;
    for header in headers {
        if !is_token(header.name) || !is_valid_header_value(header.value) {
            return Err(HttpError::BadRequest);
        }
        if skip_hop_by_hop(header.name) {
            continue;
        }
        // RFC 9110: a connection option names an additional hop-by-hop field.
        // Keep the framing fields even if a peer tries to nominate them.
        if !is_framing_header(header.name)
            && connection_tokens
                .iter()
                .any(|token| header.name.eq_ignore_ascii_case(token))
        {
            continue;
        }
        if header.name.eq_ignore_ascii_case("content-length") {
            if has_content_length {
                return Err(HttpError::BadRequest);
            }
            has_content_length = true;
        }
        if header.name.eq_ignore_ascii_case("transfer-encoding") {
            if has_transfer_encoding {
                return Err(HttpError::BadRequest);
            }
            let Ok(value) = std::str::from_utf8(header.value) else {
                return Err(HttpError::BadRequest);
            };
            if !value.trim().eq_ignore_ascii_case("chunked") {
                return Err(HttpError::BadRequest);
            }
            has_transfer_encoding = true;
        }
        if has_content_length && has_transfer_encoding {
            return Err(HttpError::BadRequest);
        }

        head.extend_from_slice(header.name.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(header.value);
        head.extend_from_slice(b"\r\n");
        if head.len() > FORWARD_HEAD_MAX {
            return Err(HttpError::TooLarge);
        }
    }

    head.extend_from_slice(b"Host: ");
    head.extend_from_slice(target.authority.as_bytes());
    head.extend_from_slice(b"\r\nConnection: close\r\n\r\n");
    if head.len() > FORWARD_HEAD_MAX {
        return Err(HttpError::TooLarge);
    }
    Ok(head)
}

/// Returns true for an HTTP token (method or field name).
#[must_use]
pub fn is_token(text: &str) -> bool {
    !text.is_empty()
        && text.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Returns true for a field value without CTLs other than tab.
#[must_use]
pub fn is_valid_header_value(value: &[u8]) -> bool {
    value
        .iter()
        .all(|byte| (*byte >= 0x20 || *byte == b'\t') && *byte != 0x7f)
}

fn skip_hop_by_hop(name: &str) -> bool {
    name.eq_ignore_ascii_case("host")
        || name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailer")
        || name.eq_ignore_ascii_case("upgrade")
        || name.eq_ignore_ascii_case("proxy-authorization")
}

fn is_framing_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("transfer-encoding")
}

fn connection_tokens<'a>(headers: &'a [Header<'a>]) -> Vec<&'a str> {
    let mut tokens = Vec::new();
    for header in headers {
        if !header.name.eq_ignore_ascii_case("connection") {
            continue;
        }
        let Ok(value) = std::str::from_utf8(header.value) else {
            continue;
        };
        for token in value.split(',') {
            let token = token.trim();
            if is_token(token) {
                tokens.push(token);
            }
        }
    }
    tokens
}

fn parse_authority(authority: &str) -> Result<Endpoint, HttpError> {
    if authority.is_empty() || authority.contains('@') {
        return Err(HttpError::BadRequest);
    }
    for byte in authority.bytes() {
        if byte <= 0x20 || byte == 0x7f {
            return Err(HttpError::BadRequest);
        }
    }

    if let Some(rest) = authority.strip_prefix('[') {
        let close = rest.find(']').ok_or(HttpError::BadRequest)?;
        let host = &rest[..close];
        let tail = &rest[close + 1..];
        let port = if tail.is_empty() {
            80
        } else {
            let port = tail.strip_prefix(':').ok_or(HttpError::BadRequest)?;
            parse_port(port)?
        };
        let address = host.parse().map_err(|_| HttpError::BadRequest)?;
        return Ok(Endpoint::from_ip(std::net::IpAddr::V6(address), port));
    }

    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => {
            if host.is_empty() || port.contains(':') {
                return Err(HttpError::BadRequest);
            }
            (host, parse_port(port)?)
        }
        None => (authority, 80),
    };
    if let Ok(address) = host.parse::<std::net::Ipv4Addr>() {
        return Ok(Endpoint::from_ip(std::net::IpAddr::V4(address), port));
    }
    Endpoint::from_domain(host, port).map_err(|_| HttpError::BadRequest)
}

fn parse_port(text: &str) -> Result<u16, HttpError> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(HttpError::BadRequest);
    }
    let port: u16 = text.parse().map_err(|_| HttpError::BadRequest)?;
    if port == 0 {
        return Err(HttpError::BadRequest);
    }
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_rewrites_a_forward_request() {
        let head = parse_request(
            b"GET http://example.com:8080/a?b=1 HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\nConnection: X-Hop\r\nX-Hop: secret\r\nX-Test: 1\r\n\r\n",
        )
        .expect("head");
        assert_eq!(head.method, "GET");
        assert_eq!(head.version, 1);
        assert_eq!(head.headers().len(), 5);
        assert!(!format!("{head:?}").contains("X-Test"));

        let target = parse_absolute(head.target).expect("target");
        assert_eq!(target.endpoint.domain(), Some("example.com"));
        assert_eq!(target.endpoint.port(), 8080);
        let rewritten = build_forward_head(head.method, head.version, &target, head.headers())
            .expect("rewrite");
        let text = String::from_utf8(rewritten).expect("utf8");
        assert!(text.starts_with("GET /a?b=1 HTTP/1.1\r\n"));
        assert!(text.contains("Host: example.com:8080\r\n"));
        assert!(text.contains("X-Test: 1\r\n"));
        assert!(!text.to_ascii_lowercase().contains("proxy-connection"));
        assert!(!text.to_ascii_lowercase().contains("keep-alive"));
        assert!(!text.to_ascii_lowercase().contains("x-hop"));
        assert!(text.ends_with("Connection: close\r\n\r\n"));
    }

    #[test]
    fn parses_a_connect_response_and_leaves_the_body() {
        let input = b"HTTP/1.1 200 Connection Established\r\nX: y\r\n\r\nhello";
        let (status, consumed) = parse_connect_response(input).expect("response");
        assert_eq!(status, 200);
        assert_eq!(&input[consumed..], b"hello");
    }

    #[test]
    fn rejects_control_characters_and_bad_versions() {
        assert!(parse_request(b"GET /a\x00b HTTP/1.1\r\n\r\n").is_err());
        assert!(matches!(
            parse_request(b"GET / HTTP/2.0\r\n\r\n"),
            Err(HttpError::BadRequest | HttpError::UnsupportedVersion)
        ));
    }

    #[test]
    fn rejects_ambiguous_framing() {
        let target = parse_absolute("http://example.com/").expect("target");
        let headers = [
            Header {
                name: "Content-Length",
                value: b"1",
            },
            Header {
                name: "Transfer-Encoding",
                value: b"chunked",
            },
        ];
        assert!(matches!(
            build_forward_head("POST", 1, &target, &headers),
            Err(HttpError::BadRequest)
        ));

        for value in [b"chunked".as_slice(), b"identity".as_slice()] {
            let headers = [
                Header {
                    name: "Transfer-Encoding",
                    value: b"chunked",
                },
                Header {
                    name: "Transfer-Encoding",
                    value,
                },
            ];
            assert!(matches!(
                build_forward_head("POST", 1, &target, &headers),
                Err(HttpError::BadRequest)
            ));
        }

        let headers = [Header {
            name: "Transfer-Encoding",
            value: b"gzip, chunked",
        }];
        assert!(matches!(
            build_forward_head("POST", 1, &target, &headers),
            Err(HttpError::BadRequest)
        ));
    }

    #[test]
    fn rejects_crafted_absolute_target_controls() {
        let endpoint = Endpoint::from_domain("example.com", 80).expect("domain");
        let injected = AbsoluteTarget {
            endpoint: endpoint.clone(),
            authority: "example.com\r\nX-Injected: yes",
            path: "/",
            needs_slash: false,
        };
        assert!(matches!(
            build_forward_head("GET", 1, &injected, &[]),
            Err(HttpError::BadRequest)
        ));

        let split = AbsoluteTarget {
            endpoint: endpoint.clone(),
            authority: "example.com",
            path: "/ HTTP/1.1\r\nX-Injected: yes",
            needs_slash: false,
        };
        assert!(matches!(
            build_forward_head("GET", 1, &split, &[]),
            Err(HttpError::BadRequest)
        ));
    }

    #[test]
    fn rejects_a_truncated_head() {
        assert!(matches!(
            parse_request(b"GET / HTTP/1.1\r\nHost: example.com\r\n"),
            Err(HttpError::Incomplete)
        ));
    }

    #[test]
    fn rejects_oversized_input() {
        let mut input = vec![b'a'; HEAD_MAX + 1];
        input.truncate(HEAD_MAX + 1);
        assert!(matches!(parse_request(&input), Err(HttpError::TooLarge)));
    }
}
