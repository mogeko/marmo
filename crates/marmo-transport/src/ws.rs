//! RFC 6455 WebSocket adapters on `tokio-tungstenite` (ADR-0016).
//!
//! The adapters expose a byte stream: text messages are rejected, binary
//! messages are concatenated on read, and writes become binary messages.
//! Path and subprotocol negotiation are enforced for the server; the client
//! rejects a selection it did not offer. Permessage-deflate is not supported
//! by the current backend and is rejected during configuration.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll, ready};

use futures_util::{Sink, Stream};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::Bytes;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::header::SEC_WEBSOCKET_PROTOCOL;
use tokio_tungstenite::tungstenite::http::{HeaderValue, Response as HttpResponse, StatusCode};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{WebSocketStream, accept_hdr_async_with_config, client_async_with_config};

use crate::BoxStream;

/// Largest WebSocket message accepted, matching the Zig package.
const MAX_MESSAGE: usize = 1024 * 1024;
/// Largest WebSocket frame accepted, matching the Zig package.
const MAX_FRAME: usize = 64 * 1024;
/// Read buffer for the underlying WebSocket stream.
const READ_BUFFER: usize = 16 * 1024;
/// Write buffer for the underlying WebSocket stream.
const WRITE_BUFFER: usize = 16 * 1024;

/// Parameters for a WebSocket client.
#[derive(Clone, Debug)]
pub struct WsClientOptions {
    /// `Host`/authority header value.
    pub host: String,
    /// Request path, starting with `/`.
    pub path: String,
    /// Subprotocols offered in preference order.
    pub subprotocols: Vec<String>,
}

/// Parameters for a WebSocket server.
#[derive(Clone, Debug)]
pub struct WsServerOptions {
    /// Accepted request path.
    pub path: String,
    /// Subprotocols in server preference order.
    pub subprotocols: Vec<String>,
}

/// A connected WebSocket stream and its negotiated subprotocol.
pub struct WsConnection {
    /// The byte stream over WebSocket messages.
    pub stream: BoxStream,
    /// The selected subprotocol, if any.
    pub subprotocol: Option<String>,
}

impl std::fmt::Debug for WsConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsConnection")
            .field("subprotocol", &self.subprotocol)
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
    pub async fn connect(&self, inner: BoxStream) -> Result<WsConnection, WsError> {
        let uri = format!("ws://{}{}", self.options.host, self.options.path);
        let mut request = uri
            .into_client_request()
            .map_err(|error| WsError::Request(error.to_string()))?;
        if !self.options.subprotocols.is_empty() {
            let value = self.options.subprotocols.join(", ");
            let value = HeaderValue::from_str(&value)
                .map_err(|error| WsError::Request(error.to_string()))?;
            request.headers_mut().insert(SEC_WEBSOCKET_PROTOCOL, value);
        }

        let (stream, response) = client_async_with_config(request, inner, Some(ws_config()))
            .await
            .map_err(WsError::Handshake)?;
        let selected = response
            .headers()
            .get(SEC_WEBSOCKET_PROTOCOL)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        if let Some(selected) = selected.as_deref() {
            if !self
                .options
                .subprotocols
                .iter()
                .any(|protocol| protocol == selected)
            {
                return Err(WsError::Subprotocol(selected.to_owned()));
            }
        }
        Ok(WsConnection {
            stream: Box::new(WsStream::new(stream)),
            subprotocol: selected,
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
    #[allow(clippy::result_large_err)]
    pub async fn accept(&self, inner: BoxStream) -> Result<WsConnection, WsError> {
        let path = self.options.path.clone();
        let protocols = self.options.subprotocols.clone();
        let selected = Arc::new(Mutex::new(None));
        let recorded = Arc::clone(&selected);
        let stream = accept_hdr_async_with_config(
            inner,
            move |request: &Request, mut response: Response| {
                if request.uri().path() != path {
                    return Err(error_response(StatusCode::NOT_FOUND));
                }
                if protocols.is_empty() {
                    return Ok(response);
                }
                let offered = offered_subprotocols(request);
                let Some(chosen) = protocols
                    .iter()
                    .find(|protocol| offered.iter().any(|value| value == *protocol))
                else {
                    return Err(error_response(StatusCode::BAD_REQUEST));
                };
                let value = HeaderValue::from_str(chosen)
                    .map_err(|_| error_response(StatusCode::BAD_REQUEST))?;
                response.headers_mut().insert(SEC_WEBSOCKET_PROTOCOL, value);
                if let Ok(mut slot) = recorded.lock() {
                    *slot = Some(chosen.clone());
                }
                Ok(response)
            },
            Some(ws_config()),
        )
        .await
        .map_err(WsError::Handshake)?;
        let subprotocol = selected.lock().ok().and_then(|slot| slot.clone());
        Ok(WsConnection {
            stream: Box::new(WsStream::new(stream)),
            subprotocol,
        })
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
    /// The opening handshake failed.
    #[error("WebSocket handshake failed: {0}")]
    Handshake(#[source] tokio_tungstenite::tungstenite::Error),
    /// The byte stream failed.
    #[error("WebSocket stream failed: {0}")]
    Io(#[from] io::Error),
}

fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE))
        .max_frame_size(Some(MAX_FRAME))
        .read_buffer_size(READ_BUFFER)
        .write_buffer_size(WRITE_BUFFER)
        .max_write_buffer_size(MAX_MESSAGE)
}

fn error_response(status: StatusCode) -> ErrorResponse {
    let mut response = HttpResponse::new(Some("websocket handshake rejected".into()));
    *response.status_mut() = status;
    response
}

fn offered_subprotocols(request: &Request) -> Vec<String> {
    request
        .headers()
        .get_all(SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

fn ws_io(error: tokio_tungstenite::tungstenite::Error) -> io::Error {
    match error {
        tokio_tungstenite::tungstenite::Error::Io(error) => error,
        other => io::Error::new(io::ErrorKind::InvalidData, other),
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

struct WsStream<S> {
    inner: WebSocketStream<S>,
    read: Vec<u8>,
    read_pos: usize,
}

impl<S> WsStream<S> {
    fn new(inner: WebSocketStream<S>) -> Self {
        Self {
            inner,
            read: Vec::new(),
            read_pos: 0,
        }
    }
}

impl<S> AsyncRead for WsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            if me.read_pos < me.read.len() {
                let copied = (me.read.len() - me.read_pos).min(buf.remaining());
                buf.put_slice(&me.read[me.read_pos..me.read_pos + copied]);
                me.read_pos += copied;
                return Poll::Ready(Ok(()));
            }
            match ready!(Pin::new(&mut me.inner).poll_next(cx)) {
                Some(Ok(Message::Binary(data))) => {
                    me.read.clear();
                    me.read.extend_from_slice(&data);
                    me.read_pos = 0;
                }
                Some(Ok(Message::Text(_))) => {
                    return Poll::Ready(Err(invalid("unexpected WebSocket text message")));
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => continue,
                Some(Ok(Message::Close(_))) => return Poll::Ready(Ok(())),
                Some(Err(error)) => return Poll::Ready(Err(ws_io(error))),
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl<S> AsyncWrite for WsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let me = self.get_mut();
        ready!(Pin::new(&mut me.inner).poll_ready(cx)).map_err(ws_io)?;
        let length = buf.len().min(MAX_FRAME);
        Pin::new(&mut me.inner)
            .start_send(Message::Binary(Bytes::copy_from_slice(&buf[..length])))
            .map_err(ws_io)?;
        ready!(Pin::new(&mut me.inner).poll_flush(cx)).map_err(ws_io)?;
        Poll::Ready(Ok(length))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner)
            .poll_flush(cx)
            .map_err(ws_io)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner)
            .poll_close(cx)
            .map_err(ws_io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    fn client(path: &str, protocols: &[&str]) -> WsClient {
        WsClient::new(WsClientOptions {
            host: "localhost".into(),
            path: path.into(),
            subprotocols: protocols.iter().map(|value| value.to_string()).collect(),
        })
    }

    fn server(path: &str, protocols: &[&str]) -> WsServer {
        WsServer::new(WsServerOptions {
            path: path.into(),
            subprotocols: protocols.iter().map(|value| value.to_string()).collect(),
        })
    }

    #[tokio::test]
    async fn echoes_over_websocket() {
        let (client_io, server_io) = duplex(64 * 1024);
        let server = server("/ws", &["marmo", "other"]);
        let client = client("/ws", &["other", "marmo"]);
        let task = tokio::spawn(async move {
            let connection = server.accept(Box::new(server_io)).await.expect("accept");
            assert_eq!(connection.subprotocol.as_deref(), Some("marmo"));
            let mut stream = connection.stream;
            let mut buffer = [0_u8; 4];
            stream.read_exact(&mut buffer).await.expect("read");
            stream.write_all(&buffer).await.expect("write");
        });

        let connection = client.connect(Box::new(client_io)).await.expect("connect");
        assert_eq!(connection.subprotocol.as_deref(), Some("marmo"));
        let mut stream = connection.stream;
        stream.write_all(b"ping").await.expect("write");
        let mut buffer = [0_u8; 4];
        stream.read_exact(&mut buffer).await.expect("read");
        assert_eq!(&buffer, b"ping");
        task.await.expect("server task");
    }

    #[tokio::test]
    async fn works_without_subprotocols() {
        let (client_io, server_io) = duplex(16 * 1024);
        let task = tokio::spawn(async move {
            let connection = server("/", &[])
                .accept(Box::new(server_io))
                .await
                .expect("accept");
            assert!(connection.subprotocol.is_none());
            let mut stream = connection.stream;
            let mut buffer = [0_u8; 3];
            stream.read_exact(&mut buffer).await.expect("read");
            stream.write_all(&buffer).await.expect("write");
        });

        let connection = client("/", &[])
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
                server("/expected", &[])
                    .accept(Box::new(server_io))
                    .await
                    .is_err()
            );
        });
        assert!(
            client("/other", &[])
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
                server("/", &["marmo"])
                    .accept(Box::new(server_io))
                    .await
                    .is_err()
            );
        });
        assert!(client("/", &[]).connect(Box::new(client_io)).await.is_err());
        task.await.expect("server task");
    }

    #[tokio::test]
    async fn carries_a_large_message() {
        let (client_io, server_io) = duplex(2 * 1024 * 1024);
        let task = tokio::spawn(async move {
            let connection = server("/", &[])
                .accept(Box::new(server_io))
                .await
                .expect("accept");
            let mut stream = connection.stream;
            let mut buffer = vec![0_u8; 200_000];
            stream.read_exact(&mut buffer).await.expect("read");
            stream.write_all(&buffer).await.expect("write");
        });

        let connection = client("/", &[])
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
