//! Wire codecs for SOCKS5, HTTP/1, Shadowsocks 2022, Trojan, VLESS, and XUDP.
//!
//! No I/O and no tokio: decoders take bounded bytes and return typed errors so
//! they can be fuzzed in isolation. See `docs/architecture.md` §8.8.
#![forbid(unsafe_code)]

/// Shadowsocks 2022 primitives and UDP packets.
pub mod shadowsocks;

/// SOCKS5 wire codec (RFC 1928).
pub mod socks5;
