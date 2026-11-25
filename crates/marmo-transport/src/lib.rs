//! Stream layers, HTTP/2 connection adapters, and the bidirectional relay.
//!
//! The `AsyncStream` bound and the relay contract are specified in
//! `docs/architecture.md` §8.2 and §9.1. TLS, HTTP/2, and WebSocket come from
//! upstream crates; this crate owns the relay and the adapter boundaries.
#![deny(unsafe_code)]

pub mod h2;
mod relay;
pub mod tls;
pub mod ws;

use std::future::Future;
use std::pin::Pin;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

pub use h2::{
    H2Client, H2ClientConnection, H2ClientOptions, H2Error, H2Server, H2ServerConnection,
    H2ServerOptions,
};
pub use relay::{
    RELAY_BUFFER_SIZE, RelayCounters, RelayError, RelayOptions, RelayStats, relay,
    relay_with_counters,
};
pub use tls::{
    AcceptedTls, ClientAuth, TlsClient, TlsClientOptions, TlsError, TlsServer, TlsServerOptions,
};
pub use ws::{WsClient, WsClientOptions, WsConnection, WsError, WsServer, WsServerOptions};

/// Duplex, ordered bytes with half-close support.
///
/// This is a bound, not a bespoke vtable: any `AsyncRead + AsyncWrite` is a
/// stream, and dropping it closes it.
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

/// A boxed stream used at layer boundaries.
pub type BoxStream = Box<dyn AsyncStream>;

/// A boxed future used by the object-safe layer boundary.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// An accepted stream plus transport metadata that later layers preserve.
pub struct AcceptedStream {
    /// The wrapped stream.
    pub stream: BoxStream,
    /// ALPN selected by the transport, if any.
    pub alpn: Option<Vec<u8>>,
}

/// One transport layer wrapped around a stream.
///
/// Layers are built from config at startup and applied in order, so the hot
/// path sees only the resulting [`BoxStream`] (ADR-0004, ADR-0017).
pub trait Layer: Send + Sync {
    /// Wraps an outbound stream.
    fn wrap<'a>(&'a self, inner: BoxStream) -> BoxFuture<'a, Result<BoxStream, LayerError>>;

    /// Wraps an inbound stream. Client-only layers return
    /// [`LayerError::Unsupported`].
    fn accept<'a>(&'a self, _inner: BoxStream) -> BoxFuture<'a, Result<BoxStream, LayerError>> {
        Box::pin(async { Err(LayerError::Unsupported) })
    }

    /// Wraps an inbound stream while preserving transport metadata.
    ///
    /// Layers that do not inspect metadata use this default, which keeps the
    /// ALPN selected by an inner TLS layer.
    fn accept_stream<'a>(
        &'a self, inner: AcceptedStream,
    ) -> BoxFuture<'a, Result<AcceptedStream, LayerError>> {
        let alpn = inner.alpn;
        Box::pin(async move {
            self.accept(inner.stream)
                .await
                .map(|stream| AcceptedStream { stream, alpn })
        })
    }
}

/// Why a transport layer rejected a stream.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LayerError {
    /// The layer does not implement this direction.
    #[error("transport layer does not support this direction")]
    Unsupported,
    /// TLS setup or the handshake failed.
    #[error(transparent)]
    Tls(#[from] TlsError),
    /// WebSocket setup or the handshake failed.
    #[error(transparent)]
    Ws(#[from] WsError),
}

impl Layer for TlsClient {
    fn wrap<'a>(&'a self, inner: BoxStream) -> BoxFuture<'a, Result<BoxStream, LayerError>> {
        Box::pin(async move { self.connect(inner).await.map_err(LayerError::Tls) })
    }
}

impl Layer for TlsServer {
    fn wrap<'a>(&'a self, _inner: BoxStream) -> BoxFuture<'a, Result<BoxStream, LayerError>> {
        Box::pin(async { Err(LayerError::Unsupported) })
    }

    fn accept<'a>(&'a self, inner: BoxStream) -> BoxFuture<'a, Result<BoxStream, LayerError>> {
        Box::pin(async move {
            self.accept(inner)
                .await
                .map(|accepted| accepted.stream)
                .map_err(LayerError::Tls)
        })
    }

    fn accept_stream<'a>(
        &'a self, inner: AcceptedStream,
    ) -> BoxFuture<'a, Result<AcceptedStream, LayerError>> {
        Box::pin(async move {
            self.accept(inner.stream)
                .await
                .map(|accepted| AcceptedStream {
                    stream: accepted.stream,
                    alpn: accepted.alpn,
                })
                .map_err(LayerError::Tls)
        })
    }
}

impl Layer for WsClient {
    fn wrap<'a>(&'a self, inner: BoxStream) -> BoxFuture<'a, Result<BoxStream, LayerError>> {
        Box::pin(async move {
            self.connect(inner)
                .await
                .map(|connection| connection.stream)
                .map_err(LayerError::Ws)
        })
    }
}

impl Layer for WsServer {
    fn wrap<'a>(&'a self, _inner: BoxStream) -> BoxFuture<'a, Result<BoxStream, LayerError>> {
        Box::pin(async { Err(LayerError::Unsupported) })
    }

    fn accept<'a>(&'a self, inner: BoxStream) -> BoxFuture<'a, Result<BoxStream, LayerError>> {
        Box::pin(async move {
            self.accept(inner)
                .await
                .map(|connection| connection.stream)
                .map_err(LayerError::Ws)
        })
    }
}
