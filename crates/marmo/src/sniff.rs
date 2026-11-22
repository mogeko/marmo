//! Buffered, replayed protocol sniffing for inbound streams.
//!
//! The sniffer reads a bounded prefix, asks the pure decoder in
//! `marmo_proto::sniff` for a domain, and wraps the stream so the consumed
//! bytes are replayed to the relay. It performs no allocation on the relay
//! path beyond the one handshake buffer.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use marmo_proto::sniff::{self, SNIFF_MAX, SniffError};
use marmo_transport::BoxStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use crate::config::{SniffProtocol, Sniffing};

/// Compiled per-inbound sniffing policy.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Policy {
    tls: bool,
    http: bool,
    http2: bool,
}

impl Policy {
    /// Compiles the config object, or returns `None` when sniffing is off.
    pub(crate) fn from_config(sniffing: Option<&Sniffing>) -> Option<Self> {
        let sniffing = sniffing?;
        if !sniffing.enabled {
            return None;
        }
        let Some(protocols) = sniffing.protocols.as_deref() else {
            return Some(Self {
                tls: true,
                http: true,
                http2: true,
            });
        };
        let mut policy = Self {
            tls: false,
            http: false,
            http2: false,
        };
        for protocol in protocols {
            match protocol {
                SniffProtocol::Tls => policy.tls = true,
                SniffProtocol::Http => policy.http = true,
                SniffProtocol::Http2 => policy.http2 = true,
            }
        }
        Some(policy)
    }
}

/// A stream with the sniffed prefix replayed ahead of its live bytes.
pub(crate) struct Sniffed {
    /// The wrapped client stream.
    pub(crate) stream: BoxStream,
    /// The sniffed domain, if a recognised protocol carried one.
    pub(crate) domain: Option<String>,
}

/// Reads until the prefix is recognised or the sniff window is full.
///
/// The caller owns cancellation and the handshake deadline. On EOF, I/O error,
/// or an unrecognised prefix every byte read is replayed; sniffing never drops
/// data.
pub(crate) async fn sniff_stream(
    mut stream: BoxStream, prefix: Vec<u8>, policy: Policy,
) -> Sniffed {
    let mut buffer = prefix;
    loop {
        match sniff::detect(&buffer, policy.tls, policy.http, policy.http2) {
            Ok(domain) => {
                return Sniffed {
                    stream: replay(stream, buffer),
                    domain,
                };
            }
            Err(SniffError::NeedMore) => {}
            Err(_) => {
                return Sniffed {
                    stream: replay(stream, buffer),
                    domain: None,
                };
            }
        }
        if buffer.len() >= SNIFF_MAX {
            return Sniffed {
                stream: replay(stream, buffer),
                domain: None,
            };
        }
        let mut chunk = [0_u8; 1024];
        let want = (SNIFF_MAX - buffer.len()).min(chunk.len());
        match stream.read(&mut chunk[..want]).await {
            Ok(0) | Err(_) => {
                return Sniffed {
                    stream: replay(stream, buffer),
                    domain: None,
                };
            }
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
        }
    }
}

fn replay(stream: BoxStream, prefix: Vec<u8>) -> BoxStream {
    if prefix.is_empty() {
        return stream;
    }
    Box::new(PrefixedStream {
        prefix,
        offset: 0,
        inner: stream,
    })
}

struct PrefixedStream {
    prefix: Vec<u8>,
    offset: usize,
    inner: BoxStream,
}

impl AsyncRead for PrefixedStream {
    fn poll_read(
        self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let remaining = &this.prefix[this.offset..];
        if !remaining.is_empty() {
            let read = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..read]);
            this.offset += read;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedStream {
    fn poll_write(
        self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
