//! Trojan codec: password hashes, TCP request headers, and UDP frames.
//!
//! The wire format is `hex(SHA-224(password)) CRLF CMD ATYP DST.ADDR DST.PORT
//! CRLF` followed by the payload. Decoding is incremental: callers feed bytes
//! until a state reports `Complete` so an unauthenticated probe can be replayed
//! to a fallback service.

use std::fmt;

use marmo_net::Endpoint;
use sha2::{Digest, Sha224};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroize;

/// Length of `hex(SHA-224(password))`.
pub const PASSWORD_HASH_LEN: usize = 56;
/// Length of the authentication line including CRLF.
pub const AUTH_PREFIX_LEN: usize = PASSWORD_HASH_LEN + 2;
/// TCP CONNECT command.
pub const COMMAND_CONNECT: u8 = 1;
/// UDP ASSOCIATE command.
pub const COMMAND_UDP_ASSOCIATE: u8 = 3;
/// IPv4 address type.
pub const ATYP_IPV4: u8 = 1;
/// Domain address type.
pub const ATYP_DOMAIN: u8 = 3;
/// IPv6 address type.
pub const ATYP_IPV6: u8 = 4;
/// Maximum domain name length.
pub const MAX_DOMAIN_LEN: usize = 255;
/// Maximum payload carried by one UDP frame.
pub const MAX_UDP_PAYLOAD: usize = 65_535;
/// Maximum bytes in an authenticated TCP request header.
pub const REQUEST_HEADER_MAX: usize = AUTH_PREFIX_LEN + 2 + 1 + MAX_DOMAIN_LEN + 2 + 2;
/// Maximum bytes in a UDP frame header.
pub const UDP_HEADER_MAX: usize = 1 + 1 + MAX_DOMAIN_LEN + 2 + 2 + 2;

const CRLF: [u8; 2] = *b"\r\n";

/// `hex(SHA-224(password))`, compared in constant time.
pub struct PasswordHash([u8; PASSWORD_HASH_LEN]);

impl PasswordHash {
    /// Hashes a password; the result is lower-case hex.
    #[must_use]
    pub fn derive(password: &str) -> Self {
        let digest = Sha224::digest(password.as_bytes());
        let mut hash = [0_u8; PASSWORD_HASH_LEN];
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for (index, byte) in digest.iter().enumerate() {
            hash[index * 2] = HEX[usize::from(byte >> 4)];
            hash[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
        }
        Self(hash)
    }

    /// Returns the hex hash bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PASSWORD_HASH_LEN] {
        &self.0
    }

    /// Compares a candidate hash in constant time.
    #[must_use]
    pub fn matches(&self, candidate: &[u8]) -> bool {
        self.0.as_slice().ct_eq(candidate).into()
    }
}

impl fmt::Debug for PasswordHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PasswordHash(<redacted>)")
    }
}

impl Drop for PasswordHash {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Progress of the authentication prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthState {
    /// The bytes so far are a valid prefix of `hash CRLF`.
    NeedMore,
    /// The full prefix matched.
    Matched,
    /// The bytes can no longer match; replay them to the fallback.
    Mismatched,
}

/// Evaluates the bytes read so far against the expected hash.
#[must_use]
pub fn auth_state(prefix: &[u8], expected: &PasswordHash) -> AuthState {
    let checked = prefix.len().min(AUTH_PREFIX_LEN);
    for (index, byte) in prefix[..checked].iter().enumerate() {
        let valid = match index {
            index if index < PASSWORD_HASH_LEN => is_lower_hex(*byte),
            index if index == PASSWORD_HASH_LEN => *byte == CRLF[0],
            _ => *byte == CRLF[1],
        };
        if !valid {
            return AuthState::Mismatched;
        }
    }
    if checked < AUTH_PREFIX_LEN {
        return AuthState::NeedMore;
    }
    if expected.matches(&prefix[..PASSWORD_HASH_LEN]) {
        AuthState::Matched
    } else {
        AuthState::Mismatched
    }
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

/// A decoded TCP request after the authentication line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    /// `COMMAND_CONNECT` or `COMMAND_UDP_ASSOCIATE`.
    pub command: u8,
    /// Requested destination.
    pub target: Endpoint,
    /// Bytes consumed by the request header.
    pub consumed: usize,
}

/// Progress of a TCP request after the authentication line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestProgress {
    /// More bytes are needed.
    NeedMore,
    /// The header cannot become valid.
    Invalid,
    /// A complete request header was decoded.
    Complete(Request),
}

/// Evaluates the bytes read so far as `CMD ATYP DST.ADDR DST.PORT CRLF`.
#[must_use]
pub fn request_progress(bytes: &[u8]) -> RequestProgress {
    if bytes.is_empty() {
        return RequestProgress::NeedMore;
    }
    let command = bytes[0];
    if command != COMMAND_CONNECT && command != COMMAND_UDP_ASSOCIATE {
        return RequestProgress::Invalid;
    }
    if bytes.len() < 2 {
        return RequestProgress::NeedMore;
    }
    let header_len = match bytes[1] {
        ATYP_IPV4 => 2 + 4 + 2 + 2,
        ATYP_IPV6 => 2 + 16 + 2 + 2,
        ATYP_DOMAIN => {
            if bytes.len() < 3 {
                return RequestProgress::NeedMore;
            }
            let length = usize::from(bytes[2]);
            if length == 0 {
                return RequestProgress::Invalid;
            }
            3 + length + 2 + 2
        }
        _ => return RequestProgress::Invalid,
    };
    if bytes.len() < header_len {
        return RequestProgress::NeedMore;
    }
    if bytes[header_len - 2..header_len] != CRLF {
        return RequestProgress::Invalid;
    }
    let Ok((target, consumed)) = decode_address(bytes, 1) else {
        return RequestProgress::Invalid;
    };
    if consumed + 2 != header_len {
        return RequestProgress::Invalid;
    }
    RequestProgress::Complete(Request {
        command,
        target,
        consumed: header_len,
    })
}

/// Encodes a request header after the authentication line.
pub fn encode_request(
    target: &Endpoint,
    command: u8,
    out: &mut [u8],
) -> Result<usize, TrojanError> {
    if command != COMMAND_CONNECT && command != COMMAND_UDP_ASSOCIATE {
        return Err(TrojanError::CommandUnsupported);
    }
    if out.is_empty() {
        return Err(TrojanError::NoSpace);
    }
    out[0] = command;
    Ok(1 + encode_address(target, &mut out[1..])?)
}

/// Encodes the full request header, including the authentication line.
pub fn encode_request_header(
    hash: &PasswordHash,
    target: &Endpoint,
    command: u8,
    out: &mut [u8],
) -> Result<usize, TrojanError> {
    if out.len() < AUTH_PREFIX_LEN + 2 {
        return Err(TrojanError::NoSpace);
    }
    out[..PASSWORD_HASH_LEN].copy_from_slice(hash.as_bytes());
    out[PASSWORD_HASH_LEN..AUTH_PREFIX_LEN].copy_from_slice(&CRLF);
    let request = encode_request(target, command, &mut out[AUTH_PREFIX_LEN..])?;
    let end = AUTH_PREFIX_LEN + request;
    if out.len() < end + 2 {
        return Err(TrojanError::NoSpace);
    }
    out[end..end + 2].copy_from_slice(&CRLF);
    Ok(end + 2)
}

/// Encodes one UDP frame header; the payload follows.
pub fn encode_udp_header(
    endpoint: &Endpoint,
    payload_len: usize,
    out: &mut [u8],
) -> Result<usize, TrojanError> {
    if payload_len > MAX_UDP_PAYLOAD {
        return Err(TrojanError::MessageTooBig);
    }
    let address = encode_address(endpoint, out)?;
    if out.len() < address + 4 {
        return Err(TrojanError::NoSpace);
    }
    let length = u16::try_from(payload_len).map_err(|_| TrojanError::MessageTooBig)?;
    out[address..address + 2].copy_from_slice(&length.to_be_bytes());
    out[address + 2..address + 4].copy_from_slice(&CRLF);
    Ok(address + 4)
}

/// Decodes one UDP frame header, returning the source and payload length.
pub fn decode_udp_header(bytes: &[u8]) -> Result<(Endpoint, usize, usize), TrojanError> {
    let (endpoint, offset) = decode_address(bytes, 0)?;
    if bytes.len() < offset + 4 {
        return Err(TrojanError::Malformed);
    }
    let length = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
    if bytes[offset + 2..offset + 4] != CRLF {
        return Err(TrojanError::Malformed);
    }
    Ok((endpoint, usize::from(length), offset + 4))
}

/// Progress of a UDP frame header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UdpFrameProgress {
    /// More bytes are needed.
    NeedMore,
    /// The frame cannot become valid.
    Invalid,
    /// The header is complete; `header_len + payload_len` bytes form the frame.
    Complete {
        /// Source or destination address.
        source: Endpoint,
        /// Length of the payload after the header.
        payload_len: usize,
        /// Length of the header before the payload.
        header_len: usize,
    },
}

/// Evaluates the bytes read so far as `ATYP ADDR PORT LEN CRLF`.
#[must_use]
pub fn udp_frame_progress(bytes: &[u8]) -> UdpFrameProgress {
    if bytes.is_empty() {
        return UdpFrameProgress::NeedMore;
    }
    let address_len = match bytes[0] {
        ATYP_IPV4 => 1 + 4 + 2,
        ATYP_IPV6 => 1 + 16 + 2,
        ATYP_DOMAIN => {
            if bytes.len() < 2 {
                return UdpFrameProgress::NeedMore;
            }
            let length = usize::from(bytes[1]);
            if length == 0 {
                return UdpFrameProgress::Invalid;
            }
            2 + length + 2
        }
        _ => return UdpFrameProgress::Invalid,
    };
    let header_len = address_len + 4;
    if bytes.len() < header_len {
        return UdpFrameProgress::NeedMore;
    }
    let Ok((source, offset)) = decode_address(bytes, 0) else {
        return UdpFrameProgress::Invalid;
    };
    if offset != address_len || bytes[offset + 2..offset + 4] != CRLF {
        return UdpFrameProgress::Invalid;
    }
    let payload_len = usize::from(u16::from_be_bytes([bytes[offset], bytes[offset + 1]]));
    UdpFrameProgress::Complete {
        source,
        payload_len,
        header_len,
    }
}

/// Encodes an `ATYP` address.
pub fn encode_address(endpoint: &Endpoint, out: &mut [u8]) -> Result<usize, TrojanError> {
    match endpoint.ip() {
        Some(std::net::IpAddr::V4(address)) => {
            if out.len() < 7 {
                return Err(TrojanError::NoSpace);
            }
            out[0] = ATYP_IPV4;
            out[1..5].copy_from_slice(&address.octets());
            out[5..7].copy_from_slice(&endpoint.port().to_be_bytes());
            Ok(7)
        }
        Some(std::net::IpAddr::V6(address)) => {
            if out.len() < 19 {
                return Err(TrojanError::NoSpace);
            }
            out[0] = ATYP_IPV6;
            out[1..17].copy_from_slice(&address.octets());
            out[17..19].copy_from_slice(&endpoint.port().to_be_bytes());
            Ok(19)
        }
        None => {
            let domain = endpoint.domain().ok_or(TrojanError::InvalidDomain)?;
            let length = u8::try_from(domain.len()).map_err(|_| TrojanError::InvalidDomain)?;
            if length == 0 {
                return Err(TrojanError::InvalidDomain);
            }
            let needed = 1 + 1 + domain.len() + 2;
            if out.len() < needed {
                return Err(TrojanError::NoSpace);
            }
            out[0] = ATYP_DOMAIN;
            out[1] = length;
            out[2..2 + domain.len()].copy_from_slice(domain.as_bytes());
            out[2 + domain.len()..needed].copy_from_slice(&endpoint.port().to_be_bytes());
            Ok(needed)
        }
    }
}

/// Decodes an `ATYP` address at `start`, returning the endpoint and next offset.
pub fn decode_address(bytes: &[u8], start: usize) -> Result<(Endpoint, usize), TrojanError> {
    if start >= bytes.len() {
        return Err(TrojanError::Malformed);
    }
    let mut offset = start;
    let address_type = bytes[offset];
    offset += 1;
    match address_type {
        ATYP_IPV4 => {
            if offset + 6 > bytes.len() {
                return Err(TrojanError::Malformed);
            }
            let address = std::net::Ipv4Addr::from([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]);
            let port = u16::from_be_bytes([bytes[offset + 4], bytes[offset + 5]]);
            Ok((Endpoint::from_ip(address.into(), port), offset + 6))
        }
        ATYP_IPV6 => {
            if offset + 18 > bytes.len() {
                return Err(TrojanError::Malformed);
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&bytes[offset..offset + 16]);
            let port = u16::from_be_bytes([bytes[offset + 16], bytes[offset + 17]]);
            Ok((
                Endpoint::from_ip(std::net::Ipv6Addr::from(octets).into(), port),
                offset + 18,
            ))
        }
        ATYP_DOMAIN => {
            if offset + 3 > bytes.len() {
                return Err(TrojanError::Malformed);
            }
            let length = usize::from(bytes[offset]);
            offset += 1;
            if length == 0 || offset + length + 2 > bytes.len() {
                return Err(TrojanError::InvalidDomain);
            }
            let name = std::str::from_utf8(&bytes[offset..offset + length])
                .map_err(|_| TrojanError::InvalidDomain)?;
            offset += length;
            let port = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            let endpoint =
                Endpoint::from_domain(name, port).map_err(|_| TrojanError::InvalidDomain)?;
            Ok((endpoint, offset + 2))
        }
        _ => Err(TrojanError::UnsupportedAddress),
    }
}

/// Why a Trojan operation failed.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum TrojanError {
    /// The output buffer was too small.
    #[error("output buffer is too small")]
    NoSpace,
    /// The command is not CONNECT or UDP ASSOCIATE.
    #[error("unsupported command")]
    CommandUnsupported,
    /// The address type is unknown.
    #[error("unsupported address type")]
    UnsupportedAddress,
    /// The address or domain is invalid.
    #[error("invalid address")]
    InvalidDomain,
    /// The frame was truncated or had the wrong framing bytes.
    #[error("malformed frame")]
    Malformed,
    /// The payload does not fit in one UDP frame.
    #[error("message too big")]
    MessageTooBig,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn endpoint(port: u16) -> Endpoint {
        Endpoint::from_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), port)
    }

    #[test]
    fn hashes_passwords_like_the_reference() {
        let hash = PasswordHash::derive("password");
        assert_eq!(
            hash.as_bytes(),
            b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
        let other = PasswordHash::derive("marmo");
        assert_eq!(
            other.as_bytes(),
            b"374a03e7b7a4edaf9475e6053a8113a7397aef14e5b284a27d54211a"
        );
    }

    #[test]
    fn probes_the_authentication_prefix() {
        let hash = PasswordHash::derive("password");
        let mut auth = [0_u8; AUTH_PREFIX_LEN];
        auth[..PASSWORD_HASH_LEN].copy_from_slice(hash.as_bytes());
        auth[PASSWORD_HASH_LEN..].copy_from_slice(b"\r\n");

        assert_eq!(auth_state(&[], &hash), AuthState::NeedMore);
        assert_eq!(auth_state(&auth[..20], &hash), AuthState::NeedMore);
        assert_eq!(auth_state(&auth[..56], &hash), AuthState::NeedMore);
        assert_eq!(auth_state(&auth, &hash), AuthState::Matched);

        let mut wrong = auth;
        wrong[0] = b'0';
        assert_eq!(auth_state(&wrong, &hash), AuthState::Mismatched);

        let mut early = auth;
        early[3] = b'X';
        assert_eq!(auth_state(&early[..4], &hash), AuthState::Mismatched);

        let mut bad_crlf = auth;
        bad_crlf[PASSWORD_HASH_LEN] = b'x';
        assert_eq!(
            auth_state(&bad_crlf[..AUTH_PREFIX_LEN], &hash),
            AuthState::Mismatched
        );
    }

    #[test]
    fn round_trips_request_headers() {
        for target in [
            endpoint(443),
            Endpoint::from_ip(IpAddr::V6(Ipv6Addr::LOCALHOST), 80),
            Endpoint::from_domain("example.com", 8443).expect("domain"),
        ] {
            let hash = PasswordHash::derive("password");
            let mut buffer = [0_u8; REQUEST_HEADER_MAX];
            let length = encode_request_header(&hash, &target, COMMAND_CONNECT, &mut buffer)
                .expect("encode");
            let RequestProgress::Complete(request) =
                request_progress(&buffer[AUTH_PREFIX_LEN..length])
            else {
                panic!("expected a complete request");
            };
            assert_eq!(request.target, target);
            assert_eq!(request.consumed + AUTH_PREFIX_LEN, length);
            assert_eq!(request.command, COMMAND_CONNECT);
        }
    }

    #[test]
    fn reports_partial_and_invalid_requests() {
        let target = endpoint(80);
        let mut buffer = [0_u8; 64];
        let request_len = encode_request(&target, COMMAND_CONNECT, &mut buffer).expect("encode");
        buffer[request_len..request_len + 2].copy_from_slice(b"\r\n");
        let length = request_len + 2;
        for split in 0..length {
            assert_eq!(
                request_progress(&buffer[..split]),
                RequestProgress::NeedMore,
                "split {split}"
            );
        }
        let RequestProgress::Complete(request) = request_progress(&buffer[..length]) else {
            panic!("expected a complete request");
        };
        assert_eq!(request.target, target);

        let mut bad_command = buffer;
        bad_command[0] = 2;
        assert_eq!(
            request_progress(&bad_command[..length]),
            RequestProgress::Invalid
        );

        let mut bad_atyp = buffer;
        bad_atyp[1] = 9;
        assert_eq!(
            request_progress(&bad_atyp[..length]),
            RequestProgress::Invalid
        );

        let mut bad_crlf = buffer;
        bad_crlf[length - 1] = b'x';
        assert_eq!(
            request_progress(&bad_crlf[..length]),
            RequestProgress::Invalid
        );
    }

    #[test]
    fn round_trips_udp_headers() {
        let target = Endpoint::from_domain("example.com", 53).expect("domain");
        let mut buffer = [0_u8; UDP_HEADER_MAX];
        let length = encode_udp_header(&target, 4096, &mut buffer).expect("encode");
        let (decoded, payload_len, consumed) =
            decode_udp_header(&buffer[..length]).expect("decode");
        assert_eq!(decoded, target);
        assert_eq!(payload_len, 4096);
        assert_eq!(consumed, length);
        assert!(matches!(
            encode_udp_header(&target, MAX_UDP_PAYLOAD + 1, &mut buffer),
            Err(TrojanError::MessageTooBig)
        ));
    }
    #[test]
    fn reports_udp_frame_progress() {
        let target = endpoint(53);
        let mut buffer = [0_u8; UDP_HEADER_MAX];
        let header = encode_udp_header(&target, 7, &mut buffer).expect("encode");
        for split in 0..header {
            assert_eq!(
                udp_frame_progress(&buffer[..split]),
                UdpFrameProgress::NeedMore,
                "split {split}"
            );
        }
        assert_eq!(
            udp_frame_progress(&buffer[..header]),
            UdpFrameProgress::Complete {
                source: target,
                payload_len: 7,
                header_len: header,
            }
        );

        let mut bad_crlf = buffer;
        bad_crlf[header - 1] = b'x';
        assert_eq!(
            udp_frame_progress(&bad_crlf[..header]),
            UdpFrameProgress::Invalid
        );

        let mut bad_atyp = buffer;
        bad_atyp[0] = 9;
        assert_eq!(
            udp_frame_progress(&bad_atyp[..header]),
            UdpFrameProgress::Invalid
        );

        let mut zero_domain = [0_u8; 4];
        zero_domain[0] = ATYP_DOMAIN;
        zero_domain[1] = 0;
        assert_eq!(udp_frame_progress(&zero_domain), UdpFrameProgress::Invalid);
    }
}
