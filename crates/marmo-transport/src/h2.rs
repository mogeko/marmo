//! HTTP/2 transport on the `h2` crate (ADR-0016, ADR-0022, ADR-0031).
//!
//! A `PUT` request carries a byte stream over the request body; the response
//! body is the other direction. [`H2ClientConnection`] and
//! [`H2ServerConnection`] expose connection-level multiplexing: many logical
//! byte streams share one HTTP/2 connection. [`H2Client::connect`] and
//! [`H2Server::accept`] remain one-shot wrappers for standalone callers and
//! tests.
//!
//! Pooling policy (connection and stream counts, admission, deadlines) lives in
//! `marmo`; this crate owns framing, HPACK, flow control, and per-stream
//! bridging. Dropping one stream resets only that stream. Dropping a connection
//! object closes the connection and fails every stream on it.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use bytes::Bytes;
use h2::{RecvStream, SendStream};
use http::{Method, Request, Response, StatusCode};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::BoxStream;

/// Largest HTTP/2 frame advertised.
const MAX_FRAME: u32 = 16 * 1024;
/// Largest header list accepted.
const MAX_HEADER_LIST: u32 = 8 * 1024;
/// Concurrent streams advertised by the server.
const MAX_STREAMS: u32 = 16;

/// Parameters for an HTTP/2 client.
#[derive(Clone, Debug)]
pub struct H2ClientOptions {
    /// `:authority`/`Host` value.
    pub host: String,
    /// Request path, starting with `/`.
    pub path: String,
}

/// Parameters for an HTTP/2 server.
#[derive(Clone, Debug)]
pub struct H2ServerOptions {
    /// Accepted request path.
    pub path: String,
}

/// An HTTP/2 client with a fixed authority and path.
#[derive(Clone, Debug)]
pub struct H2Client {
    options: H2ClientOptions,
}

impl H2Client {
    /// Builds a client from config values.
    #[must_use]
    pub fn new(options: H2ClientOptions) -> Self {
        Self { options }
    }

    /// Performs the HTTP/2 handshake and opens one stream over `inner`.
    pub async fn connect(&self, inner: BoxStream) -> Result<BoxStream, H2Error> {
        self.handshake(inner).await?.open_stream().await
    }

    /// Performs the HTTP/2 handshake and returns a multiplexed connection.
    pub async fn handshake(&self, inner: BoxStream) -> Result<H2ClientConnection, H2Error> {
        let mut builder = h2::client::Builder::new();
        builder
            .max_frame_size(MAX_FRAME)
            .max_header_list_size(MAX_HEADER_LIST);
        let (sender, connection) = builder
            .handshake(inner)
            .await
            .map_err(|error| H2Error::Handshake(error.to_string()))?;
        let task = tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(H2ClientConnection {
            inner: Arc::new(ClientInner {
                options: self.options.clone(),
                sender,
                task,
            }),
        })
    }
}

struct ClientInner {
    options: H2ClientOptions,
    sender: h2::client::SendRequest<Bytes>,
    task: JoinHandle<()>,
}

impl Drop for ClientInner {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// One HTTP/2 client connection that can open multiple streams.
///
/// Cloning shares the same connection. A stream holds a reference to the
/// connection, so dropping the last [`H2ClientConnection`] handle does not
/// abort streams that are still active.
#[derive(Clone)]
pub struct H2ClientConnection {
    inner: Arc<ClientInner>,
}

impl H2ClientConnection {
    /// Opens one HTTP/2 stream and waits for the `200` response head.
    pub async fn open_stream(&self) -> Result<BoxStream, H2Error> {
        let mut sender = self
            .inner
            .sender
            .clone()
            .ready()
            .await
            .map_err(|error| H2Error::Handshake(error.to_string()))?;
        let uri = format!(
            "https://{}{}",
            self.inner.options.host, self.inner.options.path
        );
        let request = Request::builder()
            .method(Method::PUT)
            .uri(uri)
            .body(())
            .map_err(|error| H2Error::Request(error.to_string()))?;
        let (response, send) = sender
            .send_request(request, false)
            .map_err(|error| H2Error::Handshake(error.to_string()))?;
        let response = response
            .await
            .map_err(|error| H2Error::Handshake(error.to_string()))?;
        if response.status() != StatusCode::OK {
            return Err(H2Error::Status(response.status().as_u16()));
        }
        Ok(bridge(
            send,
            response.into_body(),
            KeepAlive::Client {
                _connection: Arc::clone(&self.inner),
            },
        ))
    }

    /// Whether the connection driver has finished.
    ///
    /// A finished driver means every later [`open_stream`](Self::open_stream)
    /// call fails; active streams fail independently.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.task.is_finished()
    }
}

/// An HTTP/2 server with a fixed path.
#[derive(Clone, Debug)]
pub struct H2Server {
    options: H2ServerOptions,
}

impl H2Server {
    /// Builds a server from config values.
    #[must_use]
    pub fn new(options: H2ServerOptions) -> Self {
        Self { options }
    }

    /// Accepts the first `PUT` or `POST` stream over `inner`.
    ///
    /// The connection stays open until the returned stream is dropped, so a
    /// standalone caller can use the stream as a one-shot tunnel.
    pub async fn accept(&self, inner: BoxStream) -> Result<BoxStream, H2Error> {
        let mut builder = h2::server::Builder::new();
        builder
            .max_frame_size(MAX_FRAME)
            .max_header_list_size(MAX_HEADER_LIST)
            .max_concurrent_streams(MAX_STREAMS);
        let mut connection = builder
            .handshake(inner)
            .await
            .map_err(|error| H2Error::Handshake(error.to_string()))?;
        let Some(accepted) = connection.accept().await else {
            return Err(H2Error::Closed);
        };
        let (request, mut respond) =
            accepted.map_err(|error| H2Error::Handshake(error.to_string()))?;
        let (send, recv) = match accept_request(request, &mut respond, &self.options.path) {
            Ok(value) => value,
            Err(error) => {
                tokio::spawn(async move {
                    connection.graceful_shutdown();
                    while connection.accept().await.is_some() {}
                });
                return Err(error);
            }
        };

        let path = self.options.path.clone();
        let (stop, mut stopped) = oneshot::channel();
        let connection_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut stopped => {
                        connection.graceful_shutdown();
                        while connection.accept().await.is_some() {}
                        break;
                    }
                    accepted = connection.accept() => {
                        let Some(accepted) = accepted else {
                            break;
                        };
                        let Ok((request, mut respond)) = accepted else {
                            break;
                        };
                        // Extra streams are drained, matching the one-shot
                        // tunnel contract. A bad request is reset with 400.
                        let _ = accept_request(request, &mut respond, &path);
                    }
                }
            }
        });
        Ok(bridge(
            send,
            recv,
            KeepAlive::Server {
                connection: connection_task,
                stop: Some(stop),
            },
        ))
    }

    /// Performs the HTTP/2 handshake and returns a multiplexed server
    /// connection.
    pub async fn accept_connection(&self, inner: BoxStream) -> Result<H2ServerConnection, H2Error> {
        let mut builder = h2::server::Builder::new();
        builder
            .max_frame_size(MAX_FRAME)
            .max_header_list_size(MAX_HEADER_LIST)
            .max_concurrent_streams(MAX_STREAMS);
        let connection = builder
            .handshake(inner)
            .await
            .map_err(|error| H2Error::Handshake(error.to_string()))?;
        let path = self.options.path.clone();
        let (sender, streams) = mpsc::channel(MAX_STREAMS as usize);
        let driver = tokio::spawn(async move {
            drive_server(connection, path, sender).await;
        });
        Ok(H2ServerConnection { streams, driver })
    }
}

/// One HTTP/2 server connection that accepts multiple streams.
pub struct H2ServerConnection {
    streams: mpsc::Receiver<Result<BoxStream, H2Error>>,
    driver: JoinHandle<()>,
}

impl Drop for H2ServerConnection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

impl H2ServerConnection {
    /// Accepts the next request stream.
    ///
    /// Returns `None` when the peer closed the connection. An invalid method
    /// or path is answered with `400` and reported as [`H2Error::Protocol`];
    /// that error applies to one stream only and the caller may accept again.
    /// Every stream is independent: dropping one does not close the
    /// connection.
    pub async fn accept_stream(&mut self) -> Option<Result<BoxStream, H2Error>> {
        self.streams.recv().await
    }
}

async fn drive_server(
    mut connection: h2::server::Connection<BoxStream, Bytes>, path: String,
    streams: mpsc::Sender<Result<BoxStream, H2Error>>,
) {
    loop {
        let Some(accepted) = connection.accept().await else {
            break;
        };
        let (request, mut respond) = match accepted {
            Ok(value) => value,
            Err(error) => {
                let _ = streams
                    .send(Err(H2Error::Handshake(error.to_string())))
                    .await;
                break;
            }
        };
        match accept_request(request, &mut respond, &path) {
            Ok((send, recv)) => {
                let stream = bridge(send, recv, KeepAlive::None);
                if streams.send(Ok(stream)).await.is_err() {
                    break;
                }
            }
            Err(error) => {
                if streams.send(Err(error)).await.is_err() {
                    break;
                }
            }
        }
    }
}

/// Why the HTTP/2 transport failed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum H2Error {
    /// The request head could not be built.
    #[error("invalid HTTP/2 request: {0}")]
    Request(String),
    /// The response head could not be built.
    #[error("invalid HTTP/2 response: {0}")]
    Response(String),
    /// The handshake or stream failed.
    #[error("HTTP/2 handshake failed: {0}")]
    Handshake(String),
    /// The server answered with a status other than 200.
    #[error("HTTP/2 server returned status {0}")]
    Status(u16),
    /// The request did not match the configured method, path, or type.
    ///
    /// [`H2ServerConnection::accept_stream`] returns this for one rejected
    /// stream; the connection remains usable.
    #[error("invalid HTTP/2 request")]
    Protocol,
    /// The peer closed the connection before a stream was accepted.
    #[error("HTTP/2 connection is closed")]
    Closed,
    /// The byte stream failed.
    #[error("HTTP/2 stream failed: {0}")]
    Io(#[from] io::Error),
}

enum KeepAlive {
    None,
    Client {
        _connection: Arc<ClientInner>,
    },
    Server {
        connection: JoinHandle<()>,
        stop: Option<oneshot::Sender<()>>,
    },
}

struct H2Stream {
    send: SendStream<Bytes>,
    recv: RecvStream,
    read: Option<Bytes>,
    closed: bool,
    keepalive: KeepAlive,
}

impl Drop for H2Stream {
    fn drop(&mut self) {
        match std::mem::replace(&mut self.keepalive, KeepAlive::None) {
            KeepAlive::None | KeepAlive::Client { .. } => {}
            KeepAlive::Server { connection, stop } => {
                if let Some(stop) = stop {
                    let _ = stop.send(());
                } else {
                    connection.abort();
                }
            }
        }
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(
        self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if let Some(chunk) = me.read.take() {
                if chunk.is_empty() {
                    continue;
                }
                let copied = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..copied]);
                if copied < chunk.len() {
                    me.read = Some(chunk.slice(copied..));
                }
                me.recv
                    .flow_control()
                    .release_capacity(copied)
                    .map_err(io::Error::other)?;
                return Poll::Ready(Ok(()));
            }
            match me.recv.poll_data(cx) {
                Poll::Ready(Some(Ok(chunk))) => me.read = Some(chunk),
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Err(io::Error::other(error)));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if me.closed {
            return Poll::Ready(Err(closed()));
        }
        loop {
            let capacity = me.send.capacity();
            if capacity > 0 {
                let length = buf.len().min(capacity);
                let data = Bytes::copy_from_slice(&buf[..length]);
                me.send.send_data(data, false).map_err(io::Error::other)?;
                return Poll::Ready(Ok(length));
            }
            me.send.reserve_capacity(buf.len());
            match me.send.poll_capacity(cx) {
                Poll::Ready(Some(Ok(_))) => {}
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Err(io::Error::other(error)));
                }
                Poll::Ready(None) => return Poll::Ready(Err(closed())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if me.closed {
            return Poll::Ready(Ok(()));
        }
        me.send
            .send_data(Bytes::new(), true)
            .map_err(io::Error::other)?;
        me.closed = true;
        Poll::Ready(Ok(()))
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "HTTP/2 stream is closed")
}

fn accept_request(
    request: Request<RecvStream>, respond: &mut h2::server::SendResponse<Bytes>, path: &str,
) -> Result<(SendStream<Bytes>, RecvStream), H2Error> {
    let valid =
        matches!(*request.method(), Method::POST | Method::PUT) && request.uri().path() == path;
    if !valid {
        let response = Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(())
            .map_err(|error| H2Error::Response(error.to_string()))?;
        let _ = respond.send_response(response, true);
        return Err(H2Error::Protocol);
    }

    let response = Response::builder()
        .status(StatusCode::OK)
        .body(())
        .map_err(|error| H2Error::Response(error.to_string()))?;
    let send = respond
        .send_response(response, false)
        .map_err(|error| H2Error::Handshake(error.to_string()))?;
    let recv = request.into_body();
    Ok((send, recv))
}

fn bridge(send: SendStream<Bytes>, recv: RecvStream, keepalive: KeepAlive) -> BoxStream {
    Box::new(H2Stream {
        send,
        recv,
        read: None,
        closed: false,
        keepalive,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    fn client(path: &str) -> H2Client {
        H2Client::new(H2ClientOptions {
            host: "localhost".into(),
            path: path.into(),
        })
    }

    fn server(path: &str) -> H2Server {
        H2Server::new(H2ServerOptions { path: path.into() })
    }

    #[tokio::test]
    async fn echoes_over_http2() {
        let (client_io, server_io) = duplex(1024 * 1024);
        let task = tokio::spawn(async move {
            let mut stream = server("/stream")
                .accept(Box::new(server_io))
                .await
                .expect("accept");
            let mut buffer = [0_u8; 4];
            stream.read_exact(&mut buffer).await.expect("read");
            stream.write_all(&buffer).await.expect("write");
            stream.shutdown().await.expect("shutdown");
        });

        let mut stream = client("/stream")
            .connect(Box::new(client_io))
            .await
            .expect("connect");
        stream.write_all(b"ping").await.expect("write");
        let mut buffer = [0_u8; 4];
        stream.read_exact(&mut buffer).await.expect("read");
        assert_eq!(&buffer, b"ping");
        task.await.expect("server task");
    }

    #[tokio::test]
    async fn carries_a_large_message() {
        let (client_io, server_io) = duplex(4 * 1024 * 1024);
        let task = tokio::spawn(async move {
            let mut stream = server("/")
                .accept(Box::new(server_io))
                .await
                .expect("accept");
            let mut buffer = vec![0_u8; 200_000];
            stream.read_exact(&mut buffer).await.expect("read");
            stream.write_all(&buffer).await.expect("write");
            stream.shutdown().await.expect("shutdown");
        });

        let mut stream = client("/")
            .connect(Box::new(client_io))
            .await
            .expect("connect");
        let payload: Vec<u8> = (0..200_000).map(|index| (index % 251) as u8).collect();
        stream.write_all(&payload).await.expect("write");
        let mut buffer = vec![0_u8; payload.len()];
        stream.read_exact(&mut buffer).await.expect("read");
        assert_eq!(buffer, payload);
        task.await.expect("server task");
    }

    #[tokio::test]
    async fn multiplexes_streams_on_one_connection() {
        let (client_io, server_io) = duplex(1024 * 1024);
        let server_task = tokio::spawn(async move {
            let mut connection = server("/stream")
                .accept_connection(Box::new(server_io))
                .await
                .expect("accept connection");
            let mut tasks = Vec::new();
            for _ in 0..3 {
                let mut stream = connection
                    .accept_stream()
                    .await
                    .expect("connection")
                    .expect("stream");
                tasks.push(tokio::spawn(async move {
                    let mut buffer = [0_u8; 4];
                    stream.read_exact(&mut buffer).await.expect("read");
                    stream.write_all(&buffer).await.expect("write");
                    // Keep the stream open until the client half-closes so a
                    // drop cannot reset the response before it is read.
                    let mut eof = [0_u8; 1];
                    let _ = stream.read(&mut eof).await;
                    stream.shutdown().await.expect("shutdown");
                }));
            }
            for task in tasks {
                task.await.expect("echo");
            }
        });

        let connection = client("/stream")
            .handshake(Box::new(client_io))
            .await
            .expect("handshake");
        let mut streams = Vec::new();
        for _ in 0..3 {
            streams.push(connection.open_stream().await.expect("open stream"));
        }
        for (index, stream) in streams.iter_mut().enumerate() {
            let payload = [b'a' + index as u8; 4];
            stream.write_all(&payload).await.expect("write");
            let mut buffer = [0_u8; 4];
            stream.read_exact(&mut buffer).await.expect("read");
            assert_eq!(buffer, payload);
            stream.shutdown().await.expect("shutdown");
        }
        drop(connection);
        server_task.await.expect("server task");
    }

    #[tokio::test]
    async fn closing_one_stream_keeps_the_connection() {
        let (client_io, server_io) = duplex(1024 * 1024);
        let server_task = tokio::spawn(async move {
            let mut connection = server("/")
                .accept_connection(Box::new(server_io))
                .await
                .expect("accept connection");
            let mut first = connection
                .accept_stream()
                .await
                .expect("connection")
                .expect("first stream");
            let mut second = connection
                .accept_stream()
                .await
                .expect("connection")
                .expect("second stream");
            // The first stream is reset by the client; the second still works.
            let _ = first.read(&mut [0_u8; 4]).await;
            let mut buffer = [0_u8; 4];
            second.read_exact(&mut buffer).await.expect("read second");
            second.write_all(&buffer).await.expect("write second");
            let mut eof = [0_u8; 1];
            let _ = second.read(&mut eof).await;
            let _ = second.shutdown().await;
        });

        let connection = client("/")
            .handshake(Box::new(client_io))
            .await
            .expect("handshake");
        let first = connection.open_stream().await.expect("open first");
        let mut second = connection.open_stream().await.expect("open second");
        drop(first);
        second.write_all(b"pong").await.expect("write");
        let mut buffer = [0_u8; 4];
        second.read_exact(&mut buffer).await.expect("read");
        assert_eq!(&buffer, b"pong");
        second.shutdown().await.expect("shutdown");
        drop(connection);
        server_task.await.expect("server task");
    }

    #[tokio::test]
    async fn rejects_a_wrong_path() {
        let (client_io, server_io) = duplex(64 * 1024);
        let task = tokio::spawn(async move {
            assert!(
                server("/expected")
                    .accept(Box::new(server_io))
                    .await
                    .is_err()
            );
        });
        assert!(client("/other").connect(Box::new(client_io)).await.is_err());
        task.await.expect("server task");
    }

    #[tokio::test]
    async fn accepts_post_and_ignores_content_type() {
        use http::header::CONTENT_TYPE;

        let (client_io, server_io) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            let mut stream = server("/")
                .accept(Box::new(server_io))
                .await
                .expect("accept");
            let mut buffer = [0_u8; 4];
            stream.read_exact(&mut buffer).await.expect("read");
            stream.write_all(&buffer).await.expect("write");
            stream.shutdown().await.expect("shutdown");
        });

        let (mut sender, connection) = h2::client::handshake(client_io).await.expect("handshake");
        let connection_task = tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = Request::builder()
            .method(Method::POST)
            .uri("https://localhost/")
            .header(CONTENT_TYPE, "text/plain")
            .body(())
            .expect("request");
        let (response, mut send) = sender.send_request(request, false).expect("send");
        let response = response.await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let mut recv = response.into_body();
        send.send_data(Bytes::from_static(b"ping"), false)
            .expect("data");
        let chunk = recv.data().await.expect("chunk").expect("bytes");
        assert_eq!(&chunk[..], b"ping");
        recv.flow_control()
            .release_capacity(chunk.len())
            .expect("release");
        connection_task.abort();
        server_task.await.expect("server task");
    }

    #[tokio::test]
    async fn a_bad_path_does_not_close_the_connection() {
        let (client_io, server_io) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            let mut connection = server("/ok")
                .accept_connection(Box::new(server_io))
                .await
                .expect("accept connection");
            assert!(matches!(
                connection.accept_stream().await,
                Some(Err(H2Error::Protocol))
            ));
            let mut stream = connection
                .accept_stream()
                .await
                .expect("connection")
                .expect("valid stream");
            let mut buffer = [0_u8; 4];
            stream.read_exact(&mut buffer).await.expect("read");
            stream.write_all(&buffer).await.expect("write");
            stream.shutdown().await.expect("shutdown");
        });

        let (mut sender, connection) = h2::client::handshake(client_io).await.expect("handshake");
        let connection_task = tokio::spawn(async move {
            let _ = connection.await;
        });

        let request = Request::builder()
            .method(Method::PUT)
            .uri("https://localhost/wrong")
            .body(())
            .expect("request");
        let (response, _send) = sender.send_request(request, true).expect("send");
        assert_eq!(
            response.await.expect("response").status(),
            StatusCode::BAD_REQUEST
        );

        let request = Request::builder()
            .method(Method::PUT)
            .uri("https://localhost/ok")
            .body(())
            .expect("request");
        let (response, mut send) = sender.send_request(request, false).expect("send");
        assert_eq!(response.await.expect("response").status(), StatusCode::OK);
        send.send_data(Bytes::from_static(b"ping"), false)
            .expect("data");
        server_task.await.expect("server task");
        connection_task.abort();
    }

    #[tokio::test]
    async fn rejects_a_wrong_method() {
        let (client_io, server_io) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            assert!(server("/").accept(Box::new(server_io)).await.is_err());
        });
        let (mut sender, connection) = h2::client::handshake(client_io).await.expect("handshake");
        let connection_task = tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://localhost/")
            .body(())
            .expect("request");
        let (response, _send) = sender.send_request(request, false).expect("send");
        let response = response.await.expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        connection_task.abort();
        server_task.await.expect("server task");
    }
}
