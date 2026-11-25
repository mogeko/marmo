//! RFC 6455 WebSocket adapters on the `ws-net` sans-IO engine.
//!
//! Spike branch: same public shape as the tokio-tungstenite version, plus
//! perframe-deflate through `ws-net`'s `deflate` feature. The caller drives
//! the socket; this module owns the handshake and the byte-stream pump.

use std::io;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll, ready};

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use ws_net::{
    AcceptPolicy, Acceptor, ClientHandshake, Connection, DeflateConfig, Event, HeadReader, Limits,
    OriginPolicy, WsError as WsNetError,
};

use crate::BoxStream;

/// Largest WebSocket message accepted.
const MAX_MESSAGE: u64 = 1024 * 1024;
/// Largest WebSocket frame accepted and emitted.
const MAX_FRAME: u64 = 64 * 1024;
/// Largest pending output buffer.
const MAX_OUTPUT: u64 = 1024 * 1024;
/// Largest handshake head.
const MAX_HEAD: usize = 8 * 1024;

fn connection_limits() -> Limits {
    Limits::new()
        .with_max_message(MAX_MESSAGE)
        .with_max_frame(MAX_FRAME)
        .with_max_output(MAX_OUTPUT)
}

/// Parameters for a WebSocket client.
#[derive(Clone, Debug)]
pub struct WsClientOptions {
    /// `Host`/authority header value.
    pub host: String,
    /// Request path, starting with `/`.
    pub path: String,
    /// Subprotocols offered in preference order.
    pub subprotocols: Vec<String>,
    /// Offer permessage-deflate.
    pub compression: bool,
}

/// Validates a configured WebSocket origin allowlist.
pub fn validate_origins(origins: &[String]) -> Result<(), String> {
    if origins.len() > 16 {
        return Err("too many origins".into());
    }
    let values: Vec<&str> = origins.iter().map(String::as_str).collect();
    OriginPolicy::allow(&values)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// Parameters for a WebSocket server.
#[derive(Clone, Debug)]
pub struct WsServerOptions {
    /// Accepted request path.
    pub path: String,
    /// Subprotocols in server preference order.
    pub subprotocols: Vec<String>,
    /// Accept permessage-deflate.
    pub compression: bool,
    /// Allowed browser origins; empty keeps the compatibility `Any` policy.
    pub origins: Vec<String>,
}

/// A connected WebSocket stream and its negotiated parameters.
pub struct WsConnection {
    /// The byte stream over WebSocket messages.
    pub stream: BoxStream,
    /// The selected subprotocol, if any.
    pub subprotocol: Option<String>,
    /// Whether permessage-deflate was negotiated.
    pub compression: bool,
}

impl std::fmt::Debug for WsConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsConnection")
            .field("subprotocol", &self.subprotocol)
            .field("compression", &self.compression)
            .finish_non_exhaustive()
    }
}

/// A WebSocket client with a fixed host, path, and subprotocol list.
#[derive(Clone, Debug)]
pub struct WsClient {
    options: WsClientOptions,
}

impl WsClient {
    /// Builds a client from config values.
    #[must_use]
    pub fn new(options: WsClientOptions) -> Self {
        Self { options }
    }

    /// Performs the opening handshake over `inner`.
    pub async fn connect(&self, mut inner: BoxStream) -> Result<WsConnection, WsError> {
        let mut handshake =
            ClientHandshake::try_new().map_err(|error| WsError::Handshake(error.to_string()))?;
        let protocols: Vec<&str> = self
            .options
            .subprotocols
            .iter()
            .map(String::as_str)
            .collect();
        if !protocols.is_empty() {
            handshake = handshake.with_protocols(&protocols);
        }
        if self.options.compression {
            handshake = handshake.with_deflate(DeflateConfig::new());
        }

        let mut request = Vec::new();
        handshake
            .write_request(&self.options.host, &self.options.path, &mut request)
            .map_err(|error| WsError::Handshake(error.to_string()))?;
        inner.write_all(&request).await?;

        let mut buffer = Vec::new();
        let (verified, consumed) = loop {
            read_more(&mut inner, &mut buffer).await?;
            if let Some(found) = HeadReader::new()
                .client(&handshake, &buffer)
                .map_err(|error| WsError::Handshake(error.to_string()))?
            {
                break found;
            }
            if buffer.len() > MAX_HEAD {
                return Err(WsError::Handshake("response head is too large".into()));
            }
        };
        let selected = verified.protocol.map(str::to_owned);
        if let Some(selected) = selected.as_deref()
            && !self
                .options
                .subprotocols
                .iter()
                .any(|protocol| protocol == selected)
        {
            return Err(WsError::Subprotocol(selected.to_owned()));
        }
        let compression = verified.extensions.deflate().is_some();
        let mut conn = handshake
            .connection(&verified)
            .with_limits(connection_limits());
        if consumed < buffer.len() {
            let _ = conn.feed(&buffer[consumed..]);
        }
        Ok(WsConnection {
            stream: Box::new(WsStream::new(inner, conn)),
            subprotocol: selected,
            compression,
        })
    }
}

/// A WebSocket server with a fixed path and subprotocol list.
#[derive(Clone, Debug)]
pub struct WsServer {
    options: WsServerOptions,
}

impl WsServer {
    /// Builds a server from config values.
    #[must_use]
    pub fn new(options: WsServerOptions) -> Self {
        Self { options }
    }

    /// Performs the opening handshake over `inner`.
    pub async fn accept(&self, mut inner: BoxStream) -> Result<WsConnection, WsError> {
        let origins = if self.options.origins.is_empty() {
            OriginPolicy::any_origin()
        } else {
            let values: Vec<&str> = self.options.origins.iter().map(String::as_str).collect();
            OriginPolicy::allow(&values).map_err(|error| WsError::Handshake(error.to_string()))?
        };
        let mut policy = AcceptPolicy::new()
            .with_origins(origins)
            .with_limits(connection_limits());
        let protocols: Vec<&str> = self
            .options
            .subprotocols
            .iter()
            .map(String::as_str)
            .collect();
        if !protocols.is_empty() {
            policy = policy
                .with_protocols(&protocols)
                .map_err(|error| WsError::Handshake(error.to_string()))?
                .require_protocol();
        }
        if self.options.compression {
            policy = policy.with_deflate(DeflateConfig::new());
        }

        let mut acceptor = Acceptor::with_policy(policy);
        let mut buffer = Vec::new();
        loop {
            read_more(&mut inner, &mut buffer).await?;
            match acceptor.accept(&buffer) {
                Ok(Some(accepted)) => {
                    if accepted.handshake.target() != self.options.path {
                        inner
                            .write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n")
                            .await?;
                        return Err(WsError::Path);
                    }
                    inner.write_all(&accepted.response).await?;
                    let selected = accepted
                        .handshake
                        .select_protocol(&protocols)
                        .map(str::to_owned);
                    let compression = accepted.connection.negotiated().deflate().is_some();
                    return Ok(WsConnection {
                        stream: Box::new(WsStream::new(inner, accepted.connection)),
                        subprotocol: selected,
                        compression,
                    });
                }
                Ok(None) => {}
                Err(error) => {
                    let mut out = Vec::new();
                    error.write_response(&mut out);
                    let _ = inner.write_all(&out).await;
                    return Err(WsError::Handshake(error.to_string()));
                }
            }
            if buffer.len() > MAX_HEAD {
                return Err(WsError::Handshake("request head is too large".into()));
            }
        }
    }
}

/// Why a WebSocket handshake or stream failed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WsError {
    /// The request URI or headers were invalid.
    #[error("invalid WebSocket request: {0}")]
    Request(String),
    /// The server selected a subprotocol the client did not offer.
    #[error("unexpected WebSocket subprotocol '{0}'")]
    Subprotocol(String),
    /// The server rejected the request path.
    #[error("wrong WebSocket path")]
    Path,
    /// The opening handshake failed.
    #[error("WebSocket handshake failed: {0}")]
    Handshake(String),
    /// The byte stream failed.
    #[error("WebSocket stream failed: {0}")]
    Io(#[from] io::Error),
}

async fn read_more<S>(stream: &mut S, buffer: &mut Vec<u8>) -> Result<(), WsError>
where
    S: AsyncRead + Unpin,
{
    let mut chunk = [0_u8; 4096];
    let read = stream.read(&mut chunk).await?;
    if read == 0 {
        return Err(WsError::Handshake(
            "connection closed during handshake".into(),
        ));
    }
    buffer.extend_from_slice(&chunk[..read]);
    Ok(())
}

struct WsStream<S> {
    inner: S,
    conn: Connection,
    read: Vec<u8>,
    read_pos: usize,
    flush: Vec<u8>,
    flush_pos: usize,
    /// Plaintext bytes already encoded into `conn` but not yet reported as
    /// accepted because flushing the frame returned `Pending`.
    pending_write: usize,
    eof: bool,
}

impl<S> WsStream<S> {
    fn new(inner: S, conn: Connection) -> Self {
        Self {
            inner,
            conn,
            read: Vec::new(),
            read_pos: 0,
            flush: Vec::new(),
            flush_pos: 0,
            pending_write: 0,
            eof: false,
        }
    }

    fn poll_flush_output(&mut self, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        loop {
            if self.flush_pos == self.flush.len() {
                self.flush.clear();
                self.flush_pos = 0;
                let output = self.conn.output();
                if output.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                self.flush.extend_from_slice(output);
                let length = self.flush.len();
                self.conn.advance_output(length);
            }
            let Self {
                inner,
                flush,
                flush_pos,
                ..
            } = self;
            match Pin::new(inner).poll_write(cx, &flush[*flush_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "WebSocket stream closed",
                    )));
                }
                Poll::Ready(Ok(written)) => *flush_pos += written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncRead for WsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            if me.read_pos < me.read.len() {
                let copied = (me.read.len() - me.read_pos).min(buf.remaining());
                buf.put_slice(&me.read[me.read_pos..me.read_pos + copied]);
                me.read_pos += copied;
                return Poll::Ready(Ok(()));
            }
            if me.eof {
                return Poll::Ready(Ok(()));
            }
            match me.conn.poll() {
                Ok(Event::Binary(data)) => {
                    me.read.clear();
                    me.read.extend_from_slice(data);
                    me.read_pos = 0;
                }
                Ok(Event::Text(_)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected WebSocket text message",
                    )));
                }
                Ok(Event::Ping(_) | Event::Pong(_)) => {
                    if let Poll::Ready(Err(error)) = me.poll_flush_output(cx) {
                        return Poll::Ready(Err(error));
                    }
                }
                Ok(Event::Close(_) | Event::Closed) => {
                    me.eof = true;
                    let _ = me.poll_flush_output(cx);
                    return Poll::Ready(Ok(()));
                }
                Ok(Event::NeedInput) => {
                    if let Poll::Ready(Err(error)) = me.poll_flush_output(cx) {
                        return Poll::Ready(Err(error));
                    }
                    let mut chunk = [0_u8; 16 * 1024];
                    let mut bound = ReadBuf::new(&mut chunk);
                    match Pin::new(&mut me.inner).poll_read(cx, &mut bound) {
                        Poll::Ready(Ok(())) => {
                            let filled = bound.filled().len();
                            if filled == 0 {
                                me.conn.feed_eof();
                            } else {
                                let _ = me.conn.feed(&chunk[..filled]);
                            }
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                Err(WsNetError::UnexpectedEof) => {
                    // A TCP FIN without a Close frame is a clean transport
                    // EOF, not a malformed WebSocket stream. Let the relay
                    // apply its half-close grace instead of discarding the
                    // opposite direction.
                    me.eof = true;
                    let _ = me.poll_flush_output(cx);
                    return Poll::Ready(Ok(()));
                }
                Err(error) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        error.to_string(),
                    )));
                }
                Ok(_) => {}
            }
        }
    }
}

impl<S> AsyncWrite for WsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let me = self.get_mut();

        // A previous write queued its frame but could not flush it. Keep the
        // task registered on the socket and report the original byte count
        // once the queued output drains. Re-encoding `buf` here would make
        // `write_all` transmit the same plaintext again on every retry.
        if me.pending_write > 0 {
            return match me.poll_flush_output(cx) {
                Poll::Ready(Ok(())) => {
                    let accepted = me.pending_write;
                    me.pending_write = 0;
                    Poll::Ready(Ok(accepted))
                }
                Poll::Ready(Err(error)) => {
                    me.pending_write = 0;
                    Poll::Ready(Err(error))
                }
                Poll::Pending => Poll::Pending,
            };
        }

        ready!(me.poll_flush_output(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let length = buf.len().min(MAX_FRAME as usize);
        me.conn
            .send_binary(&buf[..length])
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        me.pending_write = length;
        match me.poll_flush_output(cx) {
            Poll::Ready(Ok(())) => {
                me.pending_write = 0;
                Poll::Ready(Ok(length))
            }
            Poll::Ready(Err(error)) => {
                me.pending_write = 0;
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_flush_output(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        let _ = me.conn.close(ws_net::CloseCode::NORMAL, "");
        ready!(me.poll_flush_output(cx))?;
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    fn client(path: &str, protocols: &[&str], compression: bool) -> WsClient {
        WsClient::new(WsClientOptions {
            host: "localhost".into(),
            path: path.into(),
            subprotocols: protocols.iter().map(|value| value.to_string()).collect(),
            compression,
        })
    }

    fn server(path: &str, protocols: &[&str], compression: bool) -> WsServer {
        WsServer::new(WsServerOptions {
            path: path.into(),
            subprotocols: protocols.iter().map(|value| value.to_string()).collect(),
            compression,
            origins: Vec::new(),
        })
    }

    #[test]
    fn validates_origin_allowlist() {
        assert!(validate_origins(&["https://app.example".into()]).is_ok());
        assert!(validate_origins(&["https://app.example/".into()]).is_err());
        assert!(validate_origins(&["app.example".into()]).is_err());
    }

    #[tokio::test]
    async fn backpressure_does_not_duplicate_stream_bytes() {
        use std::time::Duration;

        let (client_io, server_io) = duplex(1024);
        let (go_tx, go_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            let connection = server("/ws", &[], false)
                .accept(Box::new(server_io))
                .await
                .expect("accept");
            let mut stream = connection.stream;
            go_rx.await.expect("go");
            let mut total = 0_usize;
            let mut buffer = [0_u8; 4096];
            loop {
                let read = stream.read(&mut buffer).await.expect("read");
                if read == 0 {
                    break;
                }
                total += read;
            }
            total
        });

        let connection = client("/ws", &[], false)
            .connect(Box::new(client_io))
            .await
            .expect("connect");
        let mut stream = connection.stream;
        let payload = vec![0x5a_u8; 256 * 1024];
        let expected = payload.len();
        let writer = tokio::spawn(async move {
            stream.write_all(&payload).await.expect("write");
            stream.shutdown().await.expect("shutdown");
        });
        // Let the writer fill the small duplex pipe and hit backpressure
        // before the server starts draining it.
        tokio::time::sleep(Duration::from_millis(50)).await;
        go_tx.send(()).expect("signal");
        tokio::time::timeout(Duration::from_secs(5), writer)
            .await
            .expect("writer timeout")
            .expect("writer");
        let total = tokio::time::timeout(Duration::from_secs(5), server_task)
            .await
            .expect("server timeout")
            .expect("server");
        assert_eq!(total, expected, "backpressure duplicated stream bytes");
    }

    #[tokio::test]
    async fn tcp_eof_without_a_close_frame_is_a_clean_eof() {
        let (client_io, server_io) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            let connection = server("/ws", &[], false)
                .accept(Box::new(server_io))
                .await
                .expect("accept");
            let mut stream = connection.stream;
            let mut buffer = [0_u8; 1];
            stream.read(&mut buffer).await.expect("read")
        });

        let connection = client("/ws", &[], false)
            .connect(Box::new(client_io))
            .await
            .expect("connect");
        drop(connection);
        let read = tokio::time::timeout(std::time::Duration::from_secs(1), server_task)
            .await
            .expect("server timeout")
            .expect("server");
        assert_eq!(read, 0);
    }

    #[tokio::test]
    async fn echoes_over_websocket() {
        let (client_io, server_io) = duplex(64 * 1024);
        let task = tokio::spawn(async move {
            let connection = server("/ws", &["marmo", "other"], false)
                .accept(Box::new(server_io))
                .await
                .expect("accept");
            assert_eq!(connection.subprotocol.as_deref(), Some("marmo"));
            assert!(!connection.compression);
            let mut stream = connection.stream;
            let mut buffer = [0_u8; 4];
            stream.read_exact(&mut buffer).await.expect("read");
            stream.write_all(&buffer).await.expect("write");
        });

        let connection = client("/ws", &["other", "marmo"], false)
            .connect(Box::new(client_io))
            .await
            .expect("connect");
        assert_eq!(connection.subprotocol.as_deref(), Some("marmo"));
        let mut stream = connection.stream;
        stream.write_all(b"ping").await.expect("write");
        let mut buffer = [0_u8; 4];
        stream.read_exact(&mut buffer).await.expect("read");
        assert_eq!(&buffer, b"ping");
        task.await.expect("server task");
    }

    #[tokio::test]
    async fn negotiates_compression() {
        let (client_io, server_io) = duplex(2 * 1024 * 1024);
        let task = tokio::spawn(async move {
            let connection = server("/", &[], true)
                .accept(Box::new(server_io))
                .await
                .expect("accept");
            assert!(connection.compression);
            let mut stream = connection.stream;
            let mut buffer = vec![0_u8; 100_000];
            stream.read_exact(&mut buffer).await.expect("read");
            stream.write_all(&buffer).await.expect("write");
        });

        let connection = client("/", &[], true)
            .connect(Box::new(client_io))
            .await
            .expect("connect");
        assert!(connection.compression);
        let mut stream = connection.stream;
        let payload = vec![b'a'; 100_000];
        stream.write_all(&payload).await.expect("write");
        let mut buffer = vec![0_u8; payload.len()];
        stream.read_exact(&mut buffer).await.expect("read");
        assert_eq!(buffer, payload);
        task.await.expect("server task");
    }

    #[tokio::test]
    async fn works_without_subprotocols() {
        let (client_io, server_io) = duplex(16 * 1024);
        let task = tokio::spawn(async move {
            let connection = server("/", &[], false)
                .accept(Box::new(server_io))
                .await
                .expect("accept");
            assert!(connection.subprotocol.is_none());
            let mut stream = connection.stream;
            let mut buffer = [0_u8; 3];
            stream.read_exact(&mut buffer).await.expect("read");
            stream.write_all(&buffer).await.expect("write");
        });

        let connection = client("/", &[], false)
            .connect(Box::new(client_io))
            .await
            .expect("connect");
        let mut stream = connection.stream;
        stream.write_all(b"abc").await.expect("write");
        let mut buffer = [0_u8; 3];
        stream.read_exact(&mut buffer).await.expect("read");
        assert_eq!(&buffer, b"abc");
        task.await.expect("server task");
    }

    #[tokio::test]
    async fn rejects_a_wrong_path() {
        let (client_io, server_io) = duplex(16 * 1024);
        let task = tokio::spawn(async move {
            assert!(
                server("/expected", &[], false)
                    .accept(Box::new(server_io))
                    .await
                    .is_err()
            );
        });
        assert!(
            client("/other", &[], false)
                .connect(Box::new(client_io))
                .await
                .is_err()
        );
        task.await.expect("server task");
    }

    #[tokio::test]
    async fn rejects_a_missing_subprotocol() {
        let (client_io, server_io) = duplex(16 * 1024);
        let task = tokio::spawn(async move {
            assert!(
                server("/", &["marmo"], false)
                    .accept(Box::new(server_io))
                    .await
                    .is_err()
            );
        });
        assert!(
            client("/", &[], false)
                .connect(Box::new(client_io))
                .await
                .is_err()
        );
        task.await.expect("server task");
    }

    #[tokio::test]
    async fn carries_a_large_message() {
        let (client_io, server_io) = duplex(2 * 1024 * 1024);
        let task = tokio::spawn(async move {
            let connection = server("/", &[], false)
                .accept(Box::new(server_io))
                .await
                .expect("accept");
            let mut stream = connection.stream;
            let mut buffer = vec![0_u8; 200_000];
            stream.read_exact(&mut buffer).await.expect("read");
            stream.write_all(&buffer).await.expect("write");
        });

        let connection = client("/", &[], false)
            .connect(Box::new(client_io))
            .await
            .expect("connect");
        let mut stream = connection.stream;
        let payload: Vec<u8> = (0..200_000).map(|index| (index % 251) as u8).collect();
        stream.write_all(&payload).await.expect("write");
        let mut buffer = vec![0_u8; payload.len()];
        stream.read_exact(&mut buffer).await.expect("read");
        assert_eq!(buffer, payload);
        task.await.expect("server task");
    }
}
