//! IPv4/IPv6 CIDR matching for routing rules.
//!
//! The network address is canonicalized on parse, so `10.1.2.3/8` and
//! `10.0.0.0/8` compare and display identically.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use thiserror::Error;

/// An IPv4 or IPv6 CIDR block.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parses `address/prefix`.
    pub fn parse(text: &str) -> Result<Self, CidrError> {
        let (address, prefix) = text.split_once('/').ok_or(CidrError::MissingPrefix)?;
        if address.is_empty() {
            return Err(CidrError::EmptyAddress);
        }
        if prefix.is_empty() {
            return Err(CidrError::EmptyPrefix);
        }
        if prefix.contains('/') || !prefix.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(CidrError::InvalidPrefix);
        }

        let address: IpAddr = address.parse().map_err(|_| CidrError::InvalidAddress)?;
        let prefix: u8 = prefix.parse().map_err(|_| CidrError::InvalidPrefix)?;
        let max = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max {
            return Err(CidrError::PrefixOutOfRange);
        }

        Ok(Self {
            network: mask(address, prefix),
            prefix,
        })
    }

    /// Returns true if `address` is in the block.
    pub fn contains(&self, address: IpAddr) -> bool {
        if self.network.is_ipv4() != address.is_ipv4() {
            return false;
        }
        mask(address, self.prefix) == self.network
    }

    /// Returns the canonical network address.
    pub fn network(&self) -> IpAddr {
        self.network
    }

    /// Returns the prefix length in bits.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

impl FromStr for Cidr {
    type Err = CidrError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

fn mask(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => {
            let bits = u32::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix))
            };
            IpAddr::V4(Ipv4Addr::from(bits & mask))
        }
        IpAddr::V6(address) => {
            let bits = u128::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix))
            };
            IpAddr::V6(Ipv6Addr::from(bits & mask))
        }
    }
}

/// Why a CIDR block could not be parsed.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum CidrError {
    /// The input had no `/`.
    #[error("CIDR is missing a prefix")]
    MissingPrefix,
    /// The address part was empty.
    #[error("CIDR address is empty")]
    EmptyAddress,
    /// The prefix part was empty.
    #[error("CIDR prefix is empty")]
    EmptyPrefix,
    /// The address was not an IP literal.
    #[error("CIDR address is invalid")]
    InvalidAddress,
    /// The prefix was not a decimal number.
    #[error("CIDR prefix is invalid")]
    InvalidPrefix,
    /// The prefix exceeded 32 for IPv4 or 128 for IPv6.
    #[error("CIDR prefix is out of range")]
    PrefixOutOfRange,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("test address")
    }

    #[test]
    fn matches_ipv4_range() {
        let cidr = Cidr::parse("10.0.0.0/8").expect("parse");
        assert!(cidr.contains(ip("10.1.2.3")));
        assert!(!cidr.contains(ip("11.0.0.1")));
    }

    #[test]
    fn matches_ipv6_range() {
        let cidr = Cidr::parse("2001:db8::/32").expect("parse");
        assert!(cidr.contains(ip("2001:db8::1")));
        assert!(!cidr.contains(ip("2001:db9::1")));
    }

    #[test]
    fn canonicalizes_the_network() {
        let cidr = Cidr::parse("10.1.2.3/8").expect("parse");
        assert_eq!(cidr.network(), ip("10.0.0.0"));
        assert_eq!(cidr.to_string(), "10.0.0.0/8");
    }

    #[test]
    fn handles_boundary_prefixes() {
        let all = Cidr::parse("0.0.0.0/0").expect("parse");
        assert!(all.contains(ip("192.0.2.1")));
        let one = Cidr::parse("192.0.2.1/32").expect("parse");
        assert!(one.contains(ip("192.0.2.1")));
        assert!(!one.contains(ip("192.0.2.2")));

        let all_v6 = Cidr::parse("::/0").expect("parse");
        assert!(all_v6.contains(ip("2001:db8::1")));
        let one_v6 = Cidr::parse("2001:db8::1/128").expect("parse");
        assert!(one_v6.contains(ip("2001:db8::1")));
    }

    #[test]
    fn keeps_families_separate() {
        let v4 = Cidr::parse("0.0.0.0/0").expect("parse");
        assert!(!v4.contains(ip("::1")));
        let v6 = Cidr::parse("::/0").expect("parse");
        assert!(!v6.contains(ip("127.0.0.1")));
    }

    #[test]
    fn rejects_malformed_cidrs() {
        assert_eq!(Cidr::parse("10.0.0.0"), Err(CidrError::MissingPrefix));
        assert_eq!(Cidr::parse("/8"), Err(CidrError::EmptyAddress));
        assert_eq!(Cidr::parse("10.0.0.0/"), Err(CidrError::EmptyPrefix));
        assert_eq!(Cidr::parse("not-an-ip/8"), Err(CidrError::InvalidAddress));
        assert_eq!(Cidr::parse("10.0.0.0/nope"), Err(CidrError::InvalidPrefix));
        assert_eq!(Cidr::parse("10.0.0.0/+8"), Err(CidrError::InvalidPrefix));
        assert_eq!(Cidr::parse("10.0.0.0/33"), Err(CidrError::PrefixOutOfRange));
        assert_eq!(Cidr::parse("::/129"), Err(CidrError::PrefixOutOfRange));
        assert_eq!(Cidr::parse("10.0.0.0/8/9"), Err(CidrError::InvalidPrefix));
    }
}
