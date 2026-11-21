//! SOCKS5 wire codec (RFC 1928).
//!
//! No I/O: the caller reads exactly the bytes for a greeting, request, or
//! reply and invokes these parsers/encoders. Every parser is bounded and
//! rejects trailing data so a fuzz target can assert a canonical encoding.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str;

use marmo_net::Endpoint;
use thiserror::Error;

/// SOCKS version byte.
pub const VERSION: u8 = 0x05;

/// "No authentication required" method.
pub const METHOD_NO_AUTH: u8 = 0x00;

/// "No acceptable methods" sentinel.
pub const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// A client greeting: the methods the client supports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Greeting<'a> {
    methods: &'a [u8],
}

impl<'a> Greeting<'a> {
    /// Parses a complete greeting (`VER`, `NMETHODS`, methods).
    pub fn parse(input: &'a [u8]) -> Result<Self, Socks5Error> {
        if input.len() < 2 {
            return Err(Socks5Error::Truncated);
        }
        if input[0] != VERSION {
            return Err(Socks5Error::UnsupportedVersion(input[0]));
        }
        let count = usize::from(input[1]);
        if count == 0 {
            return Err(Socks5Error::EmptyGreeting);
        }
        let expected = 2 + count;
        match input.len().cmp(&expected) {
            std::cmp::Ordering::Less => return Err(Socks5Error::Truncated),
            std::cmp::Ordering::Greater => return Err(Socks5Error::TrailingData),
            std::cmp::Ordering::Equal => {}
        }
        Ok(Self {
            methods: &input[2..],
        })
    }

    /// Returns the offered methods.
    #[must_use]
    pub fn methods(&self) -> &'a [u8] {
        self.methods
    }

    /// Returns true if the client offered no-auth.
    #[must_use]
    pub fn accepts_no_auth(&self) -> bool {
        self.methods.contains(&METHOD_NO_AUTH)
    }
}

/// A SOCKS5 command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    /// `CONNECT`.
    Connect,
    /// `BIND` (not supported by marmo).
    Bind,
    /// `UDP ASSOCIATE`.
    UdpAssociate,
}

impl Command {
    fn parse(byte: u8) -> Result<Self, Socks5Error> {
        match byte {
            0x01 => Ok(Self::Connect),
            0x02 => Ok(Self::Bind),
            0x03 => Ok(Self::UdpAssociate),
            other => Err(Socks5Error::UnsupportedCommand(other)),
        }
    }
}

/// A parsed SOCKS5 request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    /// Requested command.
    pub command: Command,
    /// Destination address and port.
    pub destination: Endpoint,
}

impl Request {
    /// Parses a complete request (`VER`, `CMD`, `RSV`, `ATYP`, address, port).
    pub fn parse(input: &[u8]) -> Result<Self, Socks5Error> {
        if input.len() < 4 {
            return Err(Socks5Error::Truncated);
        }
        if input[0] != VERSION {
            return Err(Socks5Error::UnsupportedVersion(input[0]));
        }
        let command = Command::parse(input[1])?;
        if input[2] != 0 {
            return Err(Socks5Error::InvalidReserved);
        }

        match input[3] {
            ATYP_IPV4 => {
                let expected = 10;
                check_length(input.len(), expected)?;
                let address = Ipv4Addr::from([input[4], input[5], input[6], input[7]]);
                let port = u16::from_be_bytes([input[8], input[9]]);
                Ok(Self {
                    command,
                    destination: Endpoint::from_ip(IpAddr::V4(address), port),
                })
            }
            ATYP_IPV6 => {
                let expected = 22;
                check_length(input.len(), expected)?;
                let mut octets = [0_u8; 16];
                octets.copy_from_slice(&input[4..20]);
                let port = u16::from_be_bytes([input[20], input[21]]);
                Ok(Self {
                    command,
                    destination: Endpoint::from_ip(IpAddr::V6(Ipv6Addr::from(octets)), port),
                })
            }
            ATYP_DOMAIN => {
                if input.len() < 5 {
                    return Err(Socks5Error::Truncated);
                }
                let length = usize::from(input[4]);
                let expected = 7 + length;
                check_length(input.len(), expected)?;
                let name = str::from_utf8(&input[5..5 + length])
                    .map_err(|_| Socks5Error::InvalidDomain)?;
                let port = u16::from_be_bytes([input[5 + length], input[6 + length]]);
                let destination =
                    Endpoint::from_domain(name, port).map_err(|_| Socks5Error::InvalidDomain)?;
                Ok(Self {
                    command,
                    destination,
                })
            }
            other => Err(Socks5Error::UnsupportedAddressType(other)),
        }
    }
}

fn check_length(actual: usize, expected: usize) -> Result<(), Socks5Error> {
    match actual.cmp(&expected) {
        std::cmp::Ordering::Less => Err(Socks5Error::Truncated),
        std::cmp::Ordering::Greater => Err(Socks5Error::TrailingData),
        std::cmp::Ordering::Equal => Ok(()),
    }
}

/// Reply status codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplyStatus {
    /// `0x00` succeeded.
    Succeeded,
    /// `0x01` general failure.
    GeneralFailure,
    /// `0x02` connection not allowed.
    NotAllowed,
    /// `0x03` network unreachable.
    NetworkUnreachable,
    /// `0x04` host unreachable.
    HostUnreachable,
    /// `0x05` connection refused.
    ConnectionRefused,
    /// `0x06` TTL expired.
    TtlExpired,
    /// `0x07` command not supported.
    CommandNotSupported,
    /// `0x08` address type not supported.
    AddressNotSupported,
}

impl ReplyStatus {
    /// Returns the wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Succeeded => 0x00,
            Self::GeneralFailure => 0x01,
            Self::NotAllowed => 0x02,
            Self::NetworkUnreachable => 0x03,
            Self::HostUnreachable => 0x04,
            Self::ConnectionRefused => 0x05,
            Self::TtlExpired => 0x06,
            Self::CommandNotSupported => 0x07,
            Self::AddressNotSupported => 0x08,
        }
    }
}

/// Encodes the server's method selection.
pub fn encode_method_selection(method: u8, out: &mut [u8]) -> Result<usize, Socks5Error> {
    if out.len() < 2 {
        return Err(Socks5Error::OutputTooSmall);
    }
    out[0] = VERSION;
    out[1] = method;
    Ok(2)
}

/// Encodes a reply. `bound` is the server-side address; `None` encodes
/// `0.0.0.0:0`, which is valid for failures and unbound sockets.
pub fn encode_reply(
    status: ReplyStatus, bound: Option<SocketAddr>, out: &mut [u8],
) -> Result<usize, Socks5Error> {
    let bound = bound.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
    match bound {
        SocketAddr::V4(address) => {
            if out.len() < 10 {
                return Err(Socks5Error::OutputTooSmall);
            }
            out[..4].copy_from_slice(&[VERSION, status.code(), 0, ATYP_IPV4]);
            out[4..8].copy_from_slice(&address.ip().octets());
            out[8..10].copy_from_slice(&address.port().to_be_bytes());
            Ok(10)
        }
        SocketAddr::V6(address) => {
            if out.len() < 22 {
                return Err(Socks5Error::OutputTooSmall);
            }
            out[..4].copy_from_slice(&[VERSION, status.code(), 0, ATYP_IPV6]);
            out[4..20].copy_from_slice(&address.ip().octets());
            out[20..22].copy_from_slice(&address.port().to_be_bytes());
            Ok(22)
        }
    }
}

/// A parsed SOCKS5 UDP request datagram.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpRequest<'a> {
    /// Destination address and port.
    pub destination: Endpoint,
    /// Payload after the SOCKS5 UDP header.
    pub payload: &'a [u8],
}

/// Parses a SOCKS5 UDP datagram (`RSV`, `FRAG`, address, port, payload).
pub fn parse_udp(input: &[u8]) -> Result<UdpRequest<'_>, Socks5Error> {
    if input.len() < 4 {
        return Err(Socks5Error::Truncated);
    }
    if input[0] != 0 || input[1] != 0 {
        return Err(Socks5Error::InvalidReserved);
    }
    if input[2] != 0 {
        return Err(Socks5Error::Fragmented);
    }

    match input[3] {
        ATYP_IPV4 => {
            if input.len() < 10 {
                return Err(Socks5Error::Truncated);
            }
            let address = Ipv4Addr::from([input[4], input[5], input[6], input[7]]);
            let port = u16::from_be_bytes([input[8], input[9]]);
            Ok(UdpRequest {
                destination: Endpoint::from_ip(IpAddr::V4(address), port),
                payload: &input[10..],
            })
        }
        ATYP_IPV6 => {
            if input.len() < 22 {
                return Err(Socks5Error::Truncated);
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&input[4..20]);
            let port = u16::from_be_bytes([input[20], input[21]]);
            Ok(UdpRequest {
                destination: Endpoint::from_ip(IpAddr::V6(Ipv6Addr::from(octets)), port),
                payload: &input[22..],
            })
        }
        ATYP_DOMAIN => {
            if input.len() < 5 {
                return Err(Socks5Error::Truncated);
            }
            let length = usize::from(input[4]);
            if length == 0 {
                return Err(Socks5Error::InvalidDomain);
            }
            let header = 7 + length;
            if input.len() < header {
                return Err(Socks5Error::Truncated);
            }
            let name =
                str::from_utf8(&input[5..5 + length]).map_err(|_| Socks5Error::InvalidDomain)?;
            let port = u16::from_be_bytes([input[5 + length], input[6 + length]]);
            let destination =
                Endpoint::from_domain(name, port).map_err(|_| Socks5Error::InvalidDomain)?;
            Ok(UdpRequest {
                destination,
                payload: &input[header..],
            })
        }
        other => Err(Socks5Error::UnsupportedAddressType(other)),
    }
}

/// Encodes a SOCKS5 UDP datagram into `out`.
pub fn encode_udp(
    destination: &Endpoint, payload: &[u8], out: &mut [u8],
) -> Result<usize, Socks5Error> {
    let header = match destination.ip() {
        Some(IpAddr::V4(_)) => 10,
        Some(IpAddr::V6(_)) => 22,
        None => {
            let domain = destination.domain().ok_or(Socks5Error::InvalidDomain)?;
            7 + domain.len()
        }
    };
    let total = header + payload.len();
    if out.len() < total {
        return Err(Socks5Error::OutputTooSmall);
    }

    out[0] = 0;
    out[1] = 0;
    out[2] = 0;
    match destination.ip() {
        Some(IpAddr::V4(address)) => {
            out[3] = ATYP_IPV4;
            out[4..8].copy_from_slice(&address.octets());
            out[8..10].copy_from_slice(&destination.port().to_be_bytes());
        }
        Some(IpAddr::V6(address)) => {
            out[3] = ATYP_IPV6;
            out[4..20].copy_from_slice(&address.octets());
            out[20..22].copy_from_slice(&destination.port().to_be_bytes());
        }
        None => {
            let domain = destination.domain().ok_or(Socks5Error::InvalidDomain)?;
            let length = u8::try_from(domain.len()).map_err(|_| Socks5Error::InvalidDomain)?;
            out[3] = ATYP_DOMAIN;
            out[4] = length;
            out[5..5 + domain.len()].copy_from_slice(domain.as_bytes());
            out[5 + domain.len()..7 + domain.len()]
                .copy_from_slice(&destination.port().to_be_bytes());
        }
    }
    out[header..total].copy_from_slice(payload);
    Ok(total)
}

/// Why a SOCKS5 message was rejected.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum Socks5Error {
    /// The message ended before all fields were present.
    #[error("message is truncated")]
    Truncated,
    /// Bytes followed the end of the message.
    #[error("message has trailing data")]
    TrailingData,
    /// The version byte was not 5.
    #[error("unsupported SOCKS version {0}")]
    UnsupportedVersion(u8),
    /// The greeting offered no methods.
    #[error("greeting has no methods")]
    EmptyGreeting,
    /// The reserved byte was not zero.
    #[error("reserved byte is not zero")]
    InvalidReserved,
    /// The command byte is unknown.
    #[error("unsupported command {0}")]
    UnsupportedCommand(u8),
    /// The address type is unknown.
    #[error("unsupported address type {0}")]
    UnsupportedAddressType(u8),
    /// The domain was not valid UTF-8 or not a valid endpoint.
    #[error("invalid domain")]
    InvalidDomain,
    /// The output buffer was too small.
    #[error("output buffer is too small")]
    OutputTooSmall,
    /// SOCKS5 UDP fragmentation is not supported.
    #[error("fragmented UDP datagram")]
    Fragmented,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_greeting() {
        let greeting = Greeting::parse(&[VERSION, 2, METHOD_NO_AUTH, 0x02]).expect("greeting");
        assert_eq!(greeting.methods(), &[METHOD_NO_AUTH, 0x02]);
        assert!(greeting.accepts_no_auth());
    }

    #[test]
    fn rejects_bad_greetings() {
        assert_eq!(Greeting::parse(&[]), Err(Socks5Error::Truncated));
        assert_eq!(
            Greeting::parse(&[4, 1, 0]),
            Err(Socks5Error::UnsupportedVersion(4))
        );
        assert_eq!(
            Greeting::parse(&[VERSION, 0]),
            Err(Socks5Error::EmptyGreeting)
        );
        assert_eq!(
            Greeting::parse(&[VERSION, 2, 0]),
            Err(Socks5Error::Truncated)
        );
        assert_eq!(
            Greeting::parse(&[VERSION, 1, 0, 1]),
            Err(Socks5Error::TrailingData)
        );
    }

    #[test]
    fn parses_ipv4_connect() {
        let request = Request::parse(&[VERSION, 0x01, 0, ATYP_IPV4, 127, 0, 0, 1, 0x01, 0xbb])
            .expect("request");
        assert_eq!(request.command, Command::Connect);
        assert_eq!(request.destination.port(), 443);
        assert_eq!(
            request.destination.ip(),
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
        );
    }

    #[test]
    fn parses_domain_connect() {
        let mut message = vec![VERSION, 0x01, 0, ATYP_DOMAIN, 11];
        message.extend_from_slice(b"example.com");
        message.extend_from_slice(&443_u16.to_be_bytes());
        let request = Request::parse(&message).expect("request");
        assert_eq!(request.command, Command::Connect);
        assert_eq!(request.destination.domain(), Some("example.com"));
        assert_eq!(request.destination.port(), 443);
    }

    #[test]
    fn parses_ipv6_connect() {
        let mut message = vec![VERSION, 0x01, 0, ATYP_IPV6];
        message.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        message.extend_from_slice(&8443_u16.to_be_bytes());
        let request = Request::parse(&message).expect("request");
        assert_eq!(
            request.destination.ip(),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert_eq!(request.destination.port(), 8443);
    }

    #[test]
    fn parses_other_commands() {
        let bind = Request::parse(&[VERSION, 0x02, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0]).expect("bind");
        assert_eq!(bind.command, Command::Bind);
        let udp = Request::parse(&[VERSION, 0x03, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0]).expect("udp");
        assert_eq!(udp.command, Command::UdpAssociate);
    }

    #[test]
    fn rejects_bad_requests() {
        assert_eq!(Request::parse(&[]), Err(Socks5Error::Truncated));
        assert_eq!(
            Request::parse(&[4, 1, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0]),
            Err(Socks5Error::UnsupportedVersion(4))
        );
        assert_eq!(
            Request::parse(&[VERSION, 0x09, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0]),
            Err(Socks5Error::UnsupportedCommand(0x09))
        );
        assert_eq!(
            Request::parse(&[VERSION, 0x01, 1, ATYP_IPV4, 0, 0, 0, 0, 0, 0]),
            Err(Socks5Error::InvalidReserved)
        );
        assert_eq!(
            Request::parse(&[VERSION, 0x01, 0, 0x02, 0, 0, 0, 0, 0, 0]),
            Err(Socks5Error::UnsupportedAddressType(0x02))
        );
        assert_eq!(
            Request::parse(&[VERSION, 0x01, 0, ATYP_IPV4, 127, 0, 0]),
            Err(Socks5Error::Truncated)
        );
        assert_eq!(
            Request::parse(&[VERSION, 0x01, 0, ATYP_IPV4, 127, 0, 0, 1, 0, 80, 1]),
            Err(Socks5Error::TrailingData)
        );
    }

    #[test]
    fn rejects_invalid_domains() {
        let mut message = vec![VERSION, 0x01, 0, ATYP_DOMAIN, 1, 0xff];
        message.extend_from_slice(&80_u16.to_be_bytes());
        assert_eq!(Request::parse(&message), Err(Socks5Error::InvalidDomain));

        let empty = [VERSION, 0x01, 0, ATYP_DOMAIN, 0, 0, 80];
        assert_eq!(Request::parse(&empty), Err(Socks5Error::InvalidDomain));
    }

    #[test]
    fn encodes_method_selection() {
        let mut out = [0_u8; 2];
        assert_eq!(encode_method_selection(METHOD_NO_AUTH, &mut out), Ok(2));
        assert_eq!(out, [VERSION, METHOD_NO_AUTH]);
        assert_eq!(
            encode_method_selection(METHOD_NO_AUTH, &mut [0_u8; 1]),
            Err(Socks5Error::OutputTooSmall)
        );
    }

    #[test]
    fn encodes_replies() {
        let mut out = [0_u8; 22];
        let length = encode_reply(
            ReplyStatus::Succeeded,
            Some(SocketAddr::from(([127, 0, 0, 1], 1080))),
            &mut out,
        )
        .expect("reply");
        assert_eq!(length, 10);
        assert_eq!(&out[..4], &[VERSION, 0, 0, ATYP_IPV4]);
        assert_eq!(&out[4..8], &[127, 0, 0, 1]);
        assert_eq!(&out[8..10], &1080_u16.to_be_bytes());

        let length = encode_reply(ReplyStatus::NotAllowed, None, &mut out).expect("reply");
        assert_eq!(length, 10);
        assert_eq!(
            &out[..4],
            &[VERSION, ReplyStatus::NotAllowed.code(), 0, ATYP_IPV4]
        );
        assert_eq!(&out[4..10], &[0, 0, 0, 0, 0, 0]);

        let length = encode_reply(
            ReplyStatus::Succeeded,
            Some(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 443))),
            &mut out,
        )
        .expect("reply");
        assert_eq!(length, 22);
        assert_eq!(&out[..4], &[VERSION, 0, 0, ATYP_IPV6]);
        assert_eq!(&out[20..22], &443_u16.to_be_bytes());

        assert_eq!(
            encode_reply(ReplyStatus::Succeeded, None, &mut [0_u8; 9]),
            Err(Socks5Error::OutputTooSmall)
        );
    }

    #[test]
    fn status_codes_match_rfc() {
        assert_eq!(ReplyStatus::Succeeded.code(), 0x00);
        assert_eq!(ReplyStatus::GeneralFailure.code(), 0x01);
        assert_eq!(ReplyStatus::NotAllowed.code(), 0x02);
        assert_eq!(ReplyStatus::NetworkUnreachable.code(), 0x03);
        assert_eq!(ReplyStatus::HostUnreachable.code(), 0x04);
        assert_eq!(ReplyStatus::ConnectionRefused.code(), 0x05);
        assert_eq!(ReplyStatus::TtlExpired.code(), 0x06);
        assert_eq!(ReplyStatus::CommandNotSupported.code(), 0x07);
        assert_eq!(ReplyStatus::AddressNotSupported.code(), 0x08);
    }
    #[test]
    fn parses_udp_ipv4() {
        let mut packet = vec![0, 0, 0, ATYP_IPV4, 127, 0, 0, 1, 0, 53];
        packet.extend_from_slice(b"dns");
        let request = parse_udp(&packet).expect("udp");
        assert_eq!(
            request.destination.ip(),
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
        );
        assert_eq!(request.destination.port(), 53);
        assert_eq!(request.payload, b"dns");
    }

    #[test]
    fn parses_udp_domain_and_ipv6() {
        let mut packet = vec![0, 0, 0, ATYP_DOMAIN, 11];
        packet.extend_from_slice(b"example.com");
        packet.extend_from_slice(&443_u16.to_be_bytes());
        packet.extend_from_slice(b"payload");
        let request = parse_udp(&packet).expect("domain udp");
        assert_eq!(request.destination.domain(), Some("example.com"));
        assert_eq!(request.payload, b"payload");

        let mut packet = vec![0, 0, 0, ATYP_IPV6];
        packet.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet.extend_from_slice(&5353_u16.to_be_bytes());
        let request = parse_udp(&packet).expect("ipv6 udp");
        assert_eq!(
            request.destination.ip(),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert!(request.payload.is_empty());
    }

    #[test]
    fn rejects_malformed_udp() {
        assert_eq!(parse_udp(&[]), Err(Socks5Error::Truncated));
        assert_eq!(
            parse_udp(&[1, 0, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0]),
            Err(Socks5Error::InvalidReserved)
        );
        assert_eq!(
            parse_udp(&[0, 0, 1, ATYP_IPV4, 0, 0, 0, 0, 0, 0]),
            Err(Socks5Error::Fragmented)
        );
        assert_eq!(
            parse_udp(&[0, 0, 0, ATYP_IPV4, 0, 0, 0]),
            Err(Socks5Error::Truncated)
        );
        assert_eq!(
            parse_udp(&[0, 0, 0, 0x02, 0]),
            Err(Socks5Error::UnsupportedAddressType(0x02))
        );
        assert_eq!(
            parse_udp(&[0, 0, 0, ATYP_DOMAIN, 0, 0, 80]),
            Err(Socks5Error::InvalidDomain)
        );
    }

    #[test]
    fn encodes_udp_round_trip() {
        let endpoint = Endpoint::from_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 53);
        let mut out = [0_u8; 64];
        let length = encode_udp(&endpoint, b"data", &mut out).expect("encode");
        let parsed = parse_udp(&out[..length]).expect("parse");
        assert_eq!(parsed.destination, endpoint);
        assert_eq!(parsed.payload, b"data");

        let endpoint = Endpoint::from_domain("example.com", 443).expect("domain");
        let length = encode_udp(&endpoint, b"x", &mut out).expect("encode domain");
        let parsed = parse_udp(&out[..length]).expect("parse domain");
        assert_eq!(parsed.destination, endpoint);
        assert_eq!(parsed.payload, b"x");

        assert_eq!(
            encode_udp(&endpoint, b"x", &mut [0_u8; 4]),
            Err(Socks5Error::OutputTooSmall)
        );
    }
}
