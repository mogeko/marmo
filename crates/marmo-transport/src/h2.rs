//! HTTP/2 transport on the `h2` crate (ADR-0016).
//!
//! One POST (`content-type: application/octet-stream`) carries a byte stream
//! over the request body; the response body is the other direction. The
//! adapter exposes the same [`BoxStream`] boundary as TLS and WebSocket so
//! protocol layers do not know which transport they run on.
//!
//! `Instance` consumes one stream per HTTP/2 connection. The server still
//! advertises the package limit of 16 concurrent streams; extra streams are
//! reset when the connection drops.

use std::io;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll, ready};

use bytes::Bytes;
use h2::{RecvStream, SendStream};
use http::{Method, Request, Response, StatusCode};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::BoxStream;

/// Largest HTTP/2 frame advertised.
const MAX_FRAME: u32 = 16 * 1024;
/// Largest header list accepted.
const MAX_HEADER_LIST: u32 = 8 * 1024;
/// Concurrent streams advertised by the server.
const MAX_STREAMS: u32 = 16;
/// Bytes copied between the h2 stream and the byte-stream adapter.
const COPY_BUFFER: usize = 32 * 1024;
/// Buffer of the duplex pipe handed to the protocol layer.
const DUPLEX_BUFFER: usize = 32 * 1024;

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

    /// Performs the HTTP/2 handshake and opens the PUT stream over `inner`.
    pub async fn connect(&self, inner: BoxStream) -> Result<BoxStream, H2Error> {
        let mut builder = h2::client::Builder::new();
        builder
            .max_frame_size(MAX_FRAME)
            .max_header_list_size(MAX_HEADER_LIST);
        let (mut sender, connection) = builder
            .handshake(inner)
            .await
            .map_err(|error| H2Error::Handshake(error.to_string()))?;
        let connection_task = tokio::spawn(async move {
            let _ = connection.await;
        });

        let uri = format!("https://{}{}", self.options.host, self.options.path);
        let request = Request::builder()
            .method(Method::PUT)
            .uri(uri)
            .body(())
            .map_err(|error| H2Error::Request(error.to_string()))?;
        let (response, send) = match sender.send_request(request, false) {
            Ok(value) => value,
            Err(error) => {
                connection_task.abort();
                return Err(H2Error::Handshake(error.to_string()));
            }
        };
        let response = match response.await {
            Ok(response) => response,
            Err(error) => {
                connection_task.abort();
                return Err(H2Error::Handshake(error.to_string()));
            }
        };
        if response.status() != StatusCode::OK {
            connection_task.abort();
            return Err(H2Error::Status(response.status().as_u16()));
        }
        Ok(bridge(send, response.into_body(), connection_task, None))
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

    /// Accepts the first PUT or POST stream over `inner`.
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
            return Err(H2Error::Handshake("connection closed".into()));
        };
        let (request, mut respond) =
            accepted.map_err(|error| H2Error::Handshake(error.to_string()))?;

        let valid = matches!(*request.method(), Method::POST | Method::PUT)
            && request.uri().path() == self.options.path;
        if !valid {
            let response = Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(())
                .map_err(|error| H2Error::Response(error.to_string()))?;
            let _ = respond.send_response(response, true);
            tokio::spawn(async move {
                connection.graceful_shutdown();
                while connection.accept().await.is_some() {}
            });
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
                        if accepted.is_none() {
                            break;
                        }
                    }
                }
            }
        });
        Ok(bridge(send, recv, connection_task, Some(stop)))
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
    #[error("invalid HTTP/2 request")]
    Protocol,
    /// The byte stream failed.
    #[error("HTTP/2 stream failed: {0}")]
    Io(#[from] io::Error),
}

struct H2Stream {
    inner: DuplexStream,
    bridge: JoinHandle<()>,
    connection: JoinHandle<()>,
    stop: Option<oneshot::Sender<()>>,
    finished: oneshot::Receiver<()>,
}

impl Drop for H2Stream {
    fn drop(&mut self) {
        self.bridge.abort();
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        } else {
            self.connection.abort();
        }
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        ready!(Pin::new(&mut me.inner).poll_shutdown(cx))?;
        match Pin::new(&mut me.finished).poll(cx) {
            Poll::Ready(_) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn bridge(
    send: SendStream<Bytes>,
    recv: RecvStream,
    connection: JoinHandle<()>,
    stop: Option<oneshot::Sender<()>>,
) -> BoxStream {
    let (client, server) = tokio::io::duplex(DUPLEX_BUFFER);
    let (finished, receiver) = oneshot::channel();
    let bridge = tokio::spawn(async move {
        pump(send, recv, server, finished).await;
    });
    Box::new(H2Stream {
        inner: client,
        bridge,
        connection,
        stop,
        finished: receiver,
    })
}

async fn pump(
    send: SendStream<Bytes>,
    recv: RecvStream,
    stream: DuplexStream,
    finished: oneshot::Sender<()>,
) {
    let (reader, writer) = tokio::io::split(stream);
    let upload = async {
        let result = upload_side(send, reader).await;
        let _ = finished.send(());
        result
    };
    let download = download_side(recv, writer);
    let _ = tokio::join!(upload, download);
}

async fn upload_side(
    mut send: SendStream<Bytes>,
    mut reader: tokio::io::ReadHalf<DuplexStream>,
) -> io::Result<()> {
    let mut buffer = vec![0_u8; COPY_BUFFER];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let data = Bytes::copy_from_slice(&buffer[..read]);
        send.reserve_capacity(data.len());
        while send.capacity() < data.len() {
            match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
                Some(Ok(_)) => {}
                Some(Err(error)) => return Err(io::Error::other(error)),
                None => return Ok(()),
            }
        }
        send.send_data(data, false).map_err(io::Error::other)?;
    }
    send.send_data(Bytes::new(), true)
        .map_err(io::Error::other)?;
    Ok(())
}

async fn download_side(
    mut recv: RecvStream,
    mut writer: tokio::io::WriteHalf<DuplexStream>,
) -> io::Result<()> {
    while let Some(chunk) = recv.data().await {
        let chunk = chunk.map_err(io::Error::other)?;
        writer.write_all(&chunk).await?;
        recv.flow_control()
            .release_capacity(chunk.len())
            .map_err(io::Error::other)?;
    }
    Ok(())
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
