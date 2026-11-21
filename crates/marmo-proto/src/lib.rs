//! Wire codecs for SOCKS5, HTTP/1, Shadowsocks 2022, Trojan, VLESS, VMess,
//! and Mux.Cool.
//!
//! No I/O and no tokio: decoders take bounded bytes and return typed errors so
//! they can be fuzzed in isolation. See `docs/architecture.md` §8.8.
#![forbid(unsafe_code)]

/// HTTP/1.1 request and CONNECT response helpers.
pub mod http;

/// Mux.Cool framing for the VMess and VLESS mux commands.
pub mod mux;

/// Shadowsocks 2022 primitives and UDP packets.
pub mod shadowsocks;

/// SOCKS5 wire codec (RFC 1928).
pub mod socks5;

/// Trojan codec: password hashes, request headers, and UDP frames.
pub mod trojan;

/// VLESS codec: UUIDs, request and response headers, and UoT frames.
pub mod vless;

/// VMess AEAD codec: auth IDs, instructions, responses, and chunked bodies.
pub mod vmess;
