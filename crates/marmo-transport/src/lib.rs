//! Transport traits, adapters, and the bidirectional relay.
//!
//! The `AsyncStream` bound and the relay contract are specified in
//! `docs/architecture.md` §8.2 and §9.1. This crate owns the relay and the
//! adapters; it does not implement TLS, HTTP/2, or WebSocket.
#![deny(unsafe_code)]

mod relay;

use tokio::io::{AsyncRead, AsyncWrite};

pub use relay::{RELAY_BUFFER_SIZE, RelayError, RelayOptions, RelayStats, relay};

/// Duplex, ordered bytes with half-close support.
///
/// This is a bound, not a bespoke vtable: any `AsyncRead + AsyncWrite` is a
/// stream, and dropping it closes it.
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

/// A boxed stream used at layer boundaries.
pub type BoxStream = Box<dyn AsyncStream>;
