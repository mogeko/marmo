//! Destinations and sources: an IP literal or a validated domain, plus a port.
//!
//! Parsing accepts `host:port`, `1.2.3.4:port`, or `[::1]:port`.
//! Unbracketed IPv6 is rejected because the port separator is ambiguous.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use thiserror::Error;

/// A validated DNS name.
///
/// The constructor rejects empty names, names longer than 253 bytes, ASCII
/// control characters, whitespace, and characters that cannot appear in an
/// authority (`/`, `?`, `#`, `@`, `[`, `]`, `:`). Internationalized names are
/// accepted as UTF-8; IDNA conversion is the resolver's job.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DomainName(Box<str>);

impl DomainName {
    /// Maximum length of a DNS name, matching the wire-format limit.
    pub const MAX_LEN: usize = 253;

    /// Validates and stores a domain name.
    pub fn parse(name: &str) -> Result<Self, EndpointError> {
        if name.is_empty() {
            return Err(EndpointError::EmptyHost);
        }
        if name.len() > Self::MAX_LEN {
            return Err(EndpointError::DomainTooLong);
        }
        for byte in name.bytes() {
            if byte <= 0x20 || byte == 0x7f {
                return Err(EndpointError::InvalidHost);
            }
            if matches!(byte, b'/' | b'?' | b'#' | b'@' | b'[' | b']' | b':') {
                return Err(EndpointError::InvalidHost);
            }
        }
        Ok(Self(name.to_ascii_lowercase().into_boxed_str()))
    }

    /// Returns the name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for DomainName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DomainName {
    type Err = EndpointError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

/// The host half of an endpoint: an IP literal or a validated domain.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Host {
    /// An IP literal.
    Ip(IpAddr),
    /// A validated domain name.
    Domain(DomainName),
}

impl Host {
    /// Wraps an IP literal.
    pub fn ip(addr: IpAddr) -> Self {
        Self::Ip(addr)
    }

    /// Wraps an already validated domain.
    pub fn domain(name: DomainName) -> Self {
        Self::Domain(name)
    }

    /// Returns the IP literal, if this host is an IP.
    pub fn as_ip(&self) -> Option<IpAddr> {
        match self {
            Self::Ip(addr) => Some(*addr),
            Self::Domain(_) => None,
        }
    }

    /// Returns the domain, if this host is a domain.
    pub fn as_domain(&self) -> Option<&DomainName> {
        match self {
            Self::Ip(_) => None,
            Self::Domain(name) => Some(name),
        }
    }

    /// Returns true if this host is an IP literal.
    pub fn is_ip(&self) -> bool {
        matches!(self, Self::Ip(_))
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(addr) => write!(f, "{addr}"),
            Self::Domain(name) => write!(f, "{name}"),
        }
    }
}

/// A destination or source address: host plus port.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Endpoint {
    host: Host,
    port: u16,
}

impl Endpoint {
    /// Builds an endpoint from an already validated host and a port.
    pub fn new(host: Host, port: u16) -> Self {
        Self { host, port }
    }

    /// Builds an IP endpoint.
    pub fn from_ip(addr: IpAddr, port: u16) -> Self {
        Self {
            host: Host::Ip(addr),
            port,
        }
    }

    /// Validates a domain name and builds an endpoint.
    pub fn from_domain(name: &str, port: u16) -> Result<Self, EndpointError> {
        Ok(Self {
            host: Host::Domain(DomainName::parse(name)?),
            port,
        })
    }

    /// Parses `host:port`, `1.2.3.4:port`, or `[::1]:port`.
    ///
    /// A host that is not a valid IPv4 literal is treated as a domain.
    /// Unbracketed IPv6 is rejected.
    pub fn parse(text: &str) -> Result<Self, EndpointError> {
        if text.is_empty() {
            return Err(EndpointError::EmptyEndpoint);
        }

        if let Some(rest) = text.strip_prefix('[') {
            let (host, tail) = rest.split_once(']').ok_or(EndpointError::InvalidAddress)?;
            let port = tail.strip_prefix(':').ok_or(EndpointError::MissingPort)?;
            let addr = Ipv6Addr::from_str(host).map_err(|_| EndpointError::InvalidAddress)?;
            return Ok(Self {
                host: Host::Ip(IpAddr::V6(addr)),
                port: parse_port(port)?,
            });
        }

        let (host, port) = text.split_once(':').ok_or(EndpointError::MissingPort)?;
        if port.contains(':') {
            return Err(EndpointError::InvalidEndpoint);
        }
        if host.is_empty() {
            return Err(EndpointError::EmptyHost);
        }

        let port = parse_port(port)?;
        if let Ok(addr) = Ipv4Addr::from_str(host) {
            return Ok(Self {
                host: Host::Ip(IpAddr::V4(addr)),
                port,
            });
        }
        Ok(Self {
            host: Host::Domain(DomainName::parse(host)?),
            port,
        })
    }

    /// Returns the host.
    pub fn host(&self) -> &Host {
        &self.host
    }

    /// Returns the port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Returns the IP literal, if this endpoint is an IP.
    pub fn ip(&self) -> Option<IpAddr> {
        self.host.as_ip()
    }

    /// Returns the domain, if this endpoint is a domain.
    pub fn domain(&self) -> Option<&str> {
        self.host.as_domain().map(DomainName::as_str)
    }

    /// Returns true if this endpoint is an IP literal.
    pub fn is_ip(&self) -> bool {
        self.host.is_ip()
    }

    /// Converts an IP endpoint to a socket address; domains return `None`.
    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        self.ip().map(|addr| SocketAddr::new(addr, self.port))
    }
}

impl From<SocketAddr> for Endpoint {
    fn from(addr: SocketAddr) -> Self {
        Self::from_ip(addr.ip(), addr.port())
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Host::Ip(IpAddr::V6(addr)) => write!(f, "[{addr}]:{}", self.port),
            Host::Ip(IpAddr::V4(addr)) => write!(f, "{addr}:{}", self.port),
            Host::Domain(name) => write!(f, "{name}:{}", self.port),
        }
    }
}

impl FromStr for Endpoint {
    type Err = EndpointError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

fn parse_port(text: &str) -> Result<u16, EndpointError> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(EndpointError::InvalidPort);
    }
    text.parse::<u16>().map_err(|_| EndpointError::InvalidPort)
}

/// Why an endpoint or domain could not be parsed.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum EndpointError {
    /// The input was empty.
    #[error("endpoint is empty")]
    EmptyEndpoint,
    /// The input had no port separator.
    #[error("endpoint is missing a port")]
    MissingPort,
    /// The host part was empty.
    #[error("host is empty")]
    EmptyHost,
    /// The port was not a decimal `u16`.
    #[error("port is not a decimal u16")]
    InvalidPort,
    /// The bracketed IPv6 literal was invalid.
    #[error("IP literal is invalid")]
    InvalidAddress,
    /// The host contained a forbidden byte.
    #[error("host is invalid")]
    InvalidHost,
    /// The domain exceeded [`DomainName::MAX_LEN`].
    #[error("domain name is longer than 253 bytes")]
    DomainTooLong,
    /// The endpoint shape was invalid (for example unbracketed IPv6).
    #[error("endpoint has an invalid shape")]
    InvalidEndpoint,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_domain() {
        let endpoint = Endpoint::parse("example.com:443").expect("parse");
        assert_eq!(endpoint.port(), 443);
        assert_eq!(endpoint.domain(), Some("example.com"));
        assert!(!endpoint.is_ip());
    }

    #[test]
    fn parses_ipv4() {
        let endpoint = Endpoint::parse("127.0.0.1:8080").expect("parse");
        assert_eq!(endpoint.port(), 8080);
        assert_eq!(endpoint.ip(), Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[test]
    fn parses_bracketed_ipv6() {
        let endpoint = Endpoint::parse("[::1]:8443").expect("parse");
        assert_eq!(endpoint.port(), 8443);
        assert_eq!(endpoint.ip(), Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert_eq!(endpoint.to_string(), "[::1]:8443");
    }

    #[test]
    fn parses_port_zero() {
        let endpoint = Endpoint::parse("127.0.0.1:0").expect("parse");
        assert_eq!(endpoint.port(), 0);
    }

    #[test]
    fn treats_invalid_ipv4_as_domain() {
        let endpoint = Endpoint::parse("256.0.0.1:80").expect("parse");
        assert_eq!(endpoint.domain(), Some("256.0.0.1"));
    }

    #[test]
    fn rejects_malformed_endpoints() {
        assert_eq!(Endpoint::parse(""), Err(EndpointError::EmptyEndpoint));
        assert_eq!(
            Endpoint::parse("example.com"),
            Err(EndpointError::MissingPort)
        );
        assert_eq!(Endpoint::parse(":443"), Err(EndpointError::EmptyHost));
        assert_eq!(
            Endpoint::parse("example.com:https"),
            Err(EndpointError::InvalidPort)
        );
        assert_eq!(
            Endpoint::parse("example.com:+80"),
            Err(EndpointError::InvalidPort)
        );
        assert_eq!(
            Endpoint::parse("::1:443"),
            Err(EndpointError::InvalidEndpoint)
        );
        assert_eq!(
            Endpoint::parse("example.com\n:443"),
            Err(EndpointError::InvalidHost)
        );
        assert_eq!(
            Endpoint::parse("[::1:443"),
            Err(EndpointError::InvalidAddress)
        );
        assert_eq!(Endpoint::parse("[::1]"), Err(EndpointError::MissingPort));
    }

    #[test]
    fn validates_domains() {
        assert!(DomainName::parse("example.com").is_ok());
        assert!(DomainName::parse("例え.テスト").is_ok());
        assert_eq!(
            DomainName::parse("Example.COM").expect("domain").as_str(),
            "example.com"
        );
        assert_eq!(DomainName::parse(""), Err(EndpointError::EmptyHost));
        assert_eq!(DomainName::parse("a/b"), Err(EndpointError::InvalidHost));
        let long = "a".repeat(DomainName::MAX_LEN + 1);
        assert_eq!(DomainName::parse(&long), Err(EndpointError::DomainTooLong));
    }

    #[test]
    fn formats_endpoints() {
        let endpoint = Endpoint::from_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 80);
        assert_eq!(endpoint.to_string(), "192.0.2.1:80");
        let endpoint = Endpoint::from_domain("example.com", 443).expect("domain");
        assert_eq!(endpoint.to_string(), "example.com:443");
    }

    #[test]
    fn converts_socket_addresses() {
        let addr = SocketAddr::from(([192, 0, 2, 1], 8080));
        let endpoint = Endpoint::from(addr);
        assert_eq!(endpoint.to_socket_addr(), Some(addr));
    }
}
