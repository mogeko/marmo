//! HTTP/2 connection factory and pool instantiation (ADR-0031).
//!
//! The pool machinery lives in [`stream_pool`](super::stream_pool) because a
//! future QUIC adapter reuses it. This module only knows how to dial TCP + TLS
//! and perform the HTTP/2 handshake.

use std::io;
use std::sync::Arc;

use marmo_net::Endpoint;
use marmo_transport::h2::{H2Client, H2ClientConnection, H2ClientOptions};
use marmo_transport::{BoxFuture, BoxStream, Layer};

use crate::direct::Dialer;
use crate::outbound::stream_pool::{StreamConnection, StreamDialer, StreamPool, StreamPoolConfig};

/// Physical HTTP/2 connections per outbound.
const MAX_CONNECTIONS: usize = 4;
/// Concurrent streams per HTTP/2 connection.
const MAX_STREAMS: usize = 16;
/// Logical streams in flight per outbound.
const MAX_IN_FLIGHT: usize = MAX_CONNECTIONS * MAX_STREAMS;

/// The HTTP/2 outbound pool.
pub(crate) type H2Pool = StreamPool<H2ClientConnection>;

/// Fixed HTTP/2 pool bounds.
pub(crate) fn pool_config() -> StreamPoolConfig {
    StreamPoolConfig {
        max_connections: MAX_CONNECTIONS,
        max_streams_per_connection: MAX_STREAMS,
        max_in_flight: MAX_IN_FLIGHT,
    }
}

/// Dials TCP, applies TLS, and performs the HTTP/2 handshake.
pub(crate) struct H2Dialer {
    pub(crate) server: Endpoint,
    pub(crate) options: H2ClientOptions,
    pub(crate) layers: Vec<Arc<dyn Layer>>,
    pub(crate) dialer: Dialer,
}

impl StreamDialer<H2ClientConnection> for H2Dialer {
    fn dial(&self) -> BoxFuture<'_, io::Result<H2ClientConnection>> {
        Box::pin(async move {
            let inner = self.dialer.connect(&self.server).await?;
            let mut stream: BoxStream = Box::new(inner);
            for layer in &self.layers {
                stream = layer.wrap(stream).await.map_err(io::Error::other)?;
            }
            H2Client::new(self.options.clone())
                .handshake(stream)
                .await
                .map_err(io::Error::other)
        })
    }
}

impl StreamConnection for H2ClientConnection {
    fn open_stream(&self) -> BoxFuture<'_, io::Result<BoxStream>> {
        Box::pin(async move {
            H2ClientConnection::open_stream(self)
                .await
                .map_err(io::Error::other)
        })
    }
}
