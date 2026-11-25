//! VLESS codec: UUIDs, TCP/UDP request headers, responses, and UoT frames.
//!
//! Request decoding is incremental so the stream layer can read a bounded
//! header and keep any early payload. Simple UDP-over-TCP frames are a
//! two-byte big-endian length followed by the payload.

use std::fmt;

use marmo_net::Endpoint;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroize;

/// Protocol version.
pub const VERSION: u8 = 0;
/// UUID length.
pub const UUID_LEN: usize = 16;
/// Maximum addon bytes.
pub const ADDON_LEN_MAX: usize = 255;
/// Maximum request header: version, UUID, addons, command, port, address.
///
/// Includes the largest protocol-valid addon block. The address length byte
/// and the maximum domain are counted separately.
pub const REQUEST_HEADER_MAX: usize =
    1 + UUID_LEN + 1 + ADDON_LEN_MAX + 1 + 2 + 1 + 1 + MAX_DOMAIN_LEN;
/// Maximum response header: version and addons.
pub const RESPONSE_HEADER_MAX: usize = 2 + ADDON_LEN_MAX;
/// TCP command.
pub const COMMAND_TCP: u8 = 1;
/// UDP-over-TCP command.
pub const COMMAND_UDP: u8 = 2;
/// Mux/XUDP command.
pub const COMMAND_MUX: u8 = 3;
/// Reverse command.
pub const COMMAND_RVS: u8 = 4;
/// Maximum payload carried by one UoT frame.
pub const MAX_UDP_PAYLOAD: usize = 65_535;
/// IPv4 address type.
pub const ATYP_IPV4: u8 = 1;
/// Domain address type.
pub const ATYP_DOMAIN: u8 = 2;
/// IPv6 address type.
pub const ATYP_IPV6: u8 = 3;
/// Maximum domain name length.
pub const MAX_DOMAIN_LEN: usize = 255;

/// Synthetic target carried by a Mux/XUDP request.
pub const MUX_DOMAIN: &str = "v1.mux.cool";
/// Synthetic Mux/XUDP port.
pub const MUX_PORT: u16 = 666;

/// Returns true for the synthetic Mux/XUDP target.
#[must_use]
pub fn is_mux_target(endpoint: &Endpoint) -> bool {
    endpoint.port() == MUX_PORT && endpoint.domain() == Some(MUX_DOMAIN)
}

/// A parsed VLESS UUID, compared in constant time.
#[derive(Clone)]
pub struct Uuid([u8; UUID_LEN]);

impl Uuid {
    /// Parses a canonical `8-4-4-4-12` UUID or 32 hexadecimal digits.
    pub fn parse(text: &str) -> Result<Self, VlessError> {
        let bytes = text.as_bytes();
        let mut uuid = [0_u8; UUID_LEN];
        match bytes.len() {
            32 => {
                for index in 0..UUID_LEN {
                    let high = bytes[index * 2];
                    let low = bytes[index * 2 + 1];
                    uuid[index] = (hex_value(high)? << 4) | hex_value(low)?;
                }
            }
            36 => {
                let mut digits = 0;
                let mut high = 0_u8;
                for (index, byte) in bytes.iter().enumerate() {
                    if matches!(index, 8 | 13 | 18 | 23) {
                        if *byte != b'-' {
                            return Err(VlessError::InvalidUuid);
                        }
                        continue;
                    }
                    let value = hex_value(*byte)?;
                    if digits % 2 == 0 {
                        high = value;
                    } else {
                        uuid[digits / 2] = (high << 4) | value;
                    }
                    digits += 1;
                }
                if digits != 32 {
                    return Err(VlessError::InvalidUuid);
                }
            }
            _ => return Err(VlessError::InvalidUuid),
        }
        Ok(Self(uuid))
    }

    /// Returns the raw UUID bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; UUID_LEN] {
        &self.0
    }

    /// Compares a candidate UUID in constant time.
    #[must_use]
    pub fn matches(&self, candidate: &[u8]) -> bool {
        self.0.as_slice().ct_eq(candidate).into()
    }
}

impl PartialEq for Uuid {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice().ct_eq(&other.0).into()
    }
}

impl Eq for Uuid {}

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Uuid(<redacted>)")
    }
}

impl Drop for Uuid {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn hex_value(byte: u8) -> Result<u8, VlessError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(VlessError::InvalidUuid),
    }
}

/// A decoded VLESS request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    /// Client UUID from the request.
    pub uuid: Uuid,
    /// `COMMAND_TCP` or `COMMAND_UDP`.
    pub command: u8,
    /// Requested destination.
    pub target: Endpoint,
    /// Bytes consumed by the header.
    pub consumed: usize,
}

/// Progress of a VLESS request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestProgress {
    /// More bytes are needed.
    NeedMore,
    /// The header cannot become valid.
    Invalid,
    /// A complete request header was decoded.
    Complete(Request),
}

/// Evaluates the bytes read so far as a VLESS request.
///
/// Only TCP and UDP commands are accepted; Mux/XUDP and Reverse are added by
/// later slices. The caller must compare the returned UUID.
#[must_use]
pub fn request_progress(bytes: &[u8]) -> RequestProgress {
    if bytes.is_empty() {
        return RequestProgress::NeedMore;
    }
    if bytes[0] != VERSION {
        return RequestProgress::Invalid;
    }
    let fixed = 1 + UUID_LEN + 1;
    if bytes.len() < fixed {
        return RequestProgress::NeedMore;
    }
    let addon_len = usize::from(bytes[1 + UUID_LEN]);
    let command_index = fixed + addon_len;
    if bytes.len() <= command_index {
        return RequestProgress::NeedMore;
    }
    let command = bytes[command_index];
    if command == COMMAND_MUX {
        let mut uuid = [0_u8; UUID_LEN];
        uuid.copy_from_slice(&bytes[1..1 + UUID_LEN]);
        return RequestProgress::Complete(Request {
            uuid: Uuid(uuid),
            command,
            target: Endpoint::from_domain(MUX_DOMAIN, MUX_PORT)
                .expect("static mux target is valid"),
            consumed: command_index + 1,
        });
    }
    if command != COMMAND_TCP && command != COMMAND_UDP {
        return RequestProgress::Invalid;
    }
    let port_index = command_index + 1;
    if bytes.len() < port_index + 2 {
        return RequestProgress::NeedMore;
    }
    let port = u16::from_be_bytes([bytes[port_index], bytes[port_index + 1]]);
    let address_index = port_index + 2;
    if bytes.len() <= address_index {
        return RequestProgress::NeedMore;
    }
    let (target, consumed) = match decode_address(bytes, address_index, port) {
        Ok(Some(value)) => value,
        Ok(None) => return RequestProgress::NeedMore,
        Err(_) => return RequestProgress::Invalid,
    };
    let mut uuid = [0_u8; UUID_LEN];
    uuid.copy_from_slice(&bytes[1..1 + UUID_LEN]);
    RequestProgress::Complete(Request {
        uuid: Uuid(uuid),
        command,
        target,
        consumed,
    })
}

/// Encodes a request header with no addons.
pub fn encode_request(
    uuid: &Uuid, target: &Endpoint, command: u8, out: &mut [u8],
) -> Result<usize, VlessError> {
    if command != COMMAND_TCP && command != COMMAND_UDP {
        return Err(VlessError::CommandUnsupported);
    }
    let fixed = 1 + UUID_LEN + 1 + 1 + 2;
    if out.len() < fixed {
        return Err(VlessError::NoSpace);
    }
    out[0] = VERSION;
    out[1..1 + UUID_LEN].copy_from_slice(&uuid.0);
    out[1 + UUID_LEN] = 0;
    out[1 + UUID_LEN + 1] = command;
    out[1 + UUID_LEN + 2..fixed].copy_from_slice(&target.port().to_be_bytes());
    let address = encode_address(target, &mut out[fixed..])?;
    Ok(fixed + address)
}

/// Encodes a Mux/XUDP request header; the target is carried by the first frame.
pub fn encode_mux_request(uuid: &Uuid, out: &mut [u8]) -> Result<usize, VlessError> {
    let length = 1 + UUID_LEN + 1 + 1;
    if out.len() < length {
        return Err(VlessError::NoSpace);
    }
    out[0] = VERSION;
    out[1..1 + UUID_LEN].copy_from_slice(&uuid.0);
    out[1 + UUID_LEN] = 0;
    out[1 + UUID_LEN + 1] = COMMAND_MUX;
    Ok(length)
}

/// Encodes the empty response header.
pub fn encode_response(out: &mut [u8]) -> Result<usize, VlessError> {
    if out.len() < 2 {
        return Err(VlessError::NoSpace);
    }
    out[0] = VERSION;
    out[1] = 0;
    Ok(2)
}

/// Validates a two-byte response header and returns its addon length.
pub fn response_addons(header: &[u8]) -> Result<usize, VlessError> {
    if header.len() < 2 || header[0] != VERSION {
        return Err(VlessError::ProtocolViolation);
    }
    Ok(usize::from(header[1]))
}

/// Progress of a UoT frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpProgress {
    /// The two-byte length is incomplete.
    NeedMore,
    /// The length is known; `payload_len` bytes follow.
    Complete {
        /// Payload length from the frame header.
        payload_len: usize,
    },
}

/// Evaluates the first two bytes of a UoT frame.
#[must_use]
pub fn udp_progress(bytes: &[u8]) -> UdpProgress {
    if bytes.len() < 2 {
        return UdpProgress::NeedMore;
    }
    UdpProgress::Complete {
        payload_len: usize::from(u16::from_be_bytes([bytes[0], bytes[1]])),
    }
}

/// Encodes a UoT frame length.
pub fn encode_udp_header(payload_len: usize, out: &mut [u8; 2]) -> Result<(), VlessError> {
    let length = u16::try_from(payload_len).map_err(|_| VlessError::MessageTooBig)?;
    out.copy_from_slice(&length.to_be_bytes());
    Ok(())
}

/// Encodes a VLESS address, excluding the port.
pub fn encode_address(endpoint: &Endpoint, out: &mut [u8]) -> Result<usize, VlessError> {
    match endpoint.ip() {
        Some(std::net::IpAddr::V4(address)) => {
            if out.len() < 5 {
                return Err(VlessError::NoSpace);
            }
            out[0] = ATYP_IPV4;
            out[1..5].copy_from_slice(&address.octets());
            Ok(5)
        }
        Some(std::net::IpAddr::V6(address)) => {
            if out.len() < 17 {
                return Err(VlessError::NoSpace);
            }
            out[0] = ATYP_IPV6;
            out[1..17].copy_from_slice(&address.octets());
            Ok(17)
        }
        None => {
            let domain = endpoint.domain().ok_or(VlessError::InvalidDomain)?;
            let length = u8::try_from(domain.len()).map_err(|_| VlessError::InvalidDomain)?;
            if length == 0 {
                return Err(VlessError::InvalidDomain);
            }
            let needed = 2 + domain.len();
            if out.len() < needed {
                return Err(VlessError::NoSpace);
            }
            out[0] = ATYP_DOMAIN;
            out[1] = length;
            out[2..needed].copy_from_slice(domain.as_bytes());
            Ok(needed)
        }
    }
}

/// Decodes an address starting at `start`; `Ok(None)` means more bytes.
pub fn decode_address(
    bytes: &[u8], start: usize, port: u16,
) -> Result<Option<(Endpoint, usize)>, VlessError> {
    if start >= bytes.len() {
        return Ok(None);
    }
    let address_type = bytes[start];
    match address_type {
        ATYP_IPV4 => {
            let end = start + 1 + 4;
            if bytes.len() < end {
                return Ok(None);
            }
            let address = std::net::Ipv4Addr::from([
                bytes[start + 1],
                bytes[start + 2],
                bytes[start + 3],
                bytes[start + 4],
            ]);
            Ok(Some((Endpoint::from_ip(address.into(), port), end)))
        }
        ATYP_IPV6 => {
            let end = start + 1 + 16;
            if bytes.len() < end {
                return Ok(None);
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&bytes[start + 1..end]);
            Ok(Some((
                Endpoint::from_ip(std::net::Ipv6Addr::from(octets).into(), port),
                end,
            )))
        }
        ATYP_DOMAIN => {
            if bytes.len() < start + 2 {
                return Ok(None);
            }
            let length = usize::from(bytes[start + 1]);
            if length == 0 {
                return Err(VlessError::InvalidDomain);
            }
            let end = start + 2 + length;
            if bytes.len() < end {
                return Ok(None);
            }
            let name = std::str::from_utf8(&bytes[start + 2..end])
                .map_err(|_| VlessError::InvalidDomain)?;
            let endpoint =
                Endpoint::from_domain(name, port).map_err(|_| VlessError::InvalidDomain)?;
            Ok(Some((endpoint, end)))
        }
        _ => Err(VlessError::UnsupportedAddress),
    }
}

/// Why a VLESS operation failed.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum VlessError {
    /// The UUID was not 32 hex digits or a canonical hyphenated UUID.
    #[error("invalid UUID")]
    InvalidUuid,
    /// The output buffer was too small.
    #[error("output buffer is too small")]
    NoSpace,
    /// The address or domain is invalid.
    #[error("invalid address")]
    InvalidDomain,
    /// The address type is unknown.
    #[error("unsupported address type")]
    UnsupportedAddress,
    /// The command is not supported by this slice.
    #[error("unsupported command")]
    CommandUnsupported,
    /// The header was malformed.
    #[error("protocol violation")]
    ProtocolViolation,
    /// The payload does not fit in one frame.
    #[error("message too big")]
    MessageTooBig,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn uuid() -> Uuid {
        Uuid::parse("00112233-4455-6677-8899-aabbccddeeff").expect("uuid")
    }

    fn endpoint(port: u16) -> Endpoint {
        Endpoint::from_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), port)
    }

    #[test]
    fn formats_uuids_canonically() {
        assert_eq!(uuid().to_string(), "00112233-4455-6677-8899-aabbccddeeff");
        let compact = Uuid::parse("00112233445566778899aabbccddeeff").expect("uuid");
        assert_eq!(compact.to_string(), uuid().to_string());
    }

    #[test]
    fn parses_uuids() {
        let expected = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        assert_eq!(uuid().as_bytes(), &expected);
        let compact = Uuid::parse("00112233445566778899AABBCCDDEEFF").expect("compact");
        assert_eq!(compact.as_bytes(), &expected);
        assert!(Uuid::parse("").is_err());
        assert!(Uuid::parse("00112233-4455-6677-8899-aabbccddeef").is_err());
        assert!(Uuid::parse("00112233-4455-6677-8899-aabbccddeefg").is_err());
    }

    #[test]
    fn compares_uuids_in_constant_time() {
        let value = uuid();
        assert!(value.matches(value.as_bytes()));
        let mut other = *value.as_bytes();
        other[15] ^= 1;
        assert!(!value.matches(&other));
        assert!(!value.matches(&other[..15]));
    }

    #[test]
    fn round_trips_requests() {
        for target in [
            endpoint(443),
            Endpoint::from_ip(IpAddr::V6(Ipv6Addr::LOCALHOST), 80),
            Endpoint::from_domain("example.com", 8443).expect("domain"),
        ] {
            for command in [COMMAND_TCP, COMMAND_UDP] {
                let mut buffer = [0_u8; REQUEST_HEADER_MAX];
                let length =
                    encode_request(&uuid(), &target, command, &mut buffer).expect("encode");
                let RequestProgress::Complete(request) = request_progress(&buffer[..length]) else {
                    panic!("expected a complete request");
                };
                assert_eq!(request.target, target);
                assert_eq!(request.command, command);
                assert_eq!(request.consumed, length);
                assert!(request.uuid.matches(uuid().as_bytes()));
            }
        }
    }

    #[test]
    fn request_header_bound_covers_maximum_addons() {
        let mut buffer = vec![0_u8; REQUEST_HEADER_MAX];
        buffer[0] = VERSION;
        buffer[1..1 + UUID_LEN].copy_from_slice(uuid().as_bytes());
        buffer[1 + UUID_LEN] = ADDON_LEN_MAX as u8;
        let mut offset = 1 + UUID_LEN + 1 + ADDON_LEN_MAX;
        buffer[offset] = COMMAND_TCP;
        offset += 1;
        buffer[offset..offset + 2].copy_from_slice(&443_u16.to_be_bytes());
        offset += 2;
        buffer[offset] = ATYP_DOMAIN;
        offset += 1;
        // `DomainName` accepts at most 253 bytes; the protocol length byte can
        // carry up to 255.
        let domain_len = 253;
        buffer[offset] = domain_len as u8;
        offset += 1;
        buffer[offset..offset + domain_len].fill(b'a');
        offset += domain_len;

        assert!(offset <= REQUEST_HEADER_MAX);
        let progress = request_progress(&buffer[..offset]);
        let RequestProgress::Complete(request) = progress else {
            panic!("expected a complete request, got {progress:?}");
        };
        assert_eq!(request.target.domain().map(str::len), Some(domain_len));
    }

    #[test]
    fn reports_partial_and_invalid_requests() {
        let target = endpoint(80);
        let mut buffer = [0_u8; REQUEST_HEADER_MAX];
        let length = encode_request(&uuid(), &target, COMMAND_TCP, &mut buffer).expect("encode");
        for split in 0..length {
            assert_eq!(
                request_progress(&buffer[..split]),
                RequestProgress::NeedMore,
                "split {split}"
            );
        }

        let mut bad_version = buffer;
        bad_version[0] = 1;
        assert_eq!(
            request_progress(&bad_version[..length]),
            RequestProgress::Invalid
        );

        let mut bad_command = buffer;
        bad_command[1 + UUID_LEN + 1] = COMMAND_RVS;
        assert_eq!(
            request_progress(&bad_command[..length]),
            RequestProgress::Invalid
        );

        let mut mux = [0_u8; REQUEST_HEADER_MAX];
        let mux_len = encode_mux_request(&uuid(), &mut mux).expect("mux");
        let RequestProgress::Complete(request) = request_progress(&mux[..mux_len]) else {
            panic!("expected a mux request");
        };
        assert_eq!(request.command, COMMAND_MUX);
        assert!(is_mux_target(&request.target));

        let mut bad_address = buffer;
        bad_address[1 + UUID_LEN + 4] = 9;
        assert_eq!(
            request_progress(&bad_address[..length]),
            RequestProgress::Invalid
        );

        let mut addons = [0_u8; REQUEST_HEADER_MAX];
        let target = endpoint(80);
        let length = encode_request(&uuid(), &target, COMMAND_TCP, &mut addons).expect("encode");
        let mut with_addons = addons.to_vec();
        with_addons[1 + UUID_LEN] = 1;
        with_addons.insert(1 + UUID_LEN + 1, 0xaa);
        let RequestProgress::Complete(request) = request_progress(&with_addons[..length + 1])
        else {
            panic!("expected addons to be skipped");
        };
        assert_eq!(request.target, target);
    }

    #[test]
    fn validates_responses_and_uot_headers() {
        let mut response = [0_u8; 2];
        assert_eq!(encode_response(&mut response).expect("response"), 2);
        assert_eq!(response_addons(&response).expect("valid"), 0);
        assert_eq!(response_addons(&[1, 0]), Err(VlessError::ProtocolViolation));

        let mut header = [0_u8; 2];
        encode_udp_header(4096, &mut header).expect("header");
        assert_eq!(
            udp_progress(&header),
            UdpProgress::Complete { payload_len: 4096 }
        );
        assert_eq!(udp_progress(&header[..1]), UdpProgress::NeedMore);
        assert_eq!(
            encode_udp_header(MAX_UDP_PAYLOAD + 1, &mut header),
            Err(VlessError::MessageTooBig)
        );
    }
}
