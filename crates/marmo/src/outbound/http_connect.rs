//! HTTP CONNECT outbound.

use std::io;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll, ready};

use marmo_net::Endpoint;
use marmo_proto::http::{self, HEAD_MAX, find_head_end};
use marmo_transport::BoxStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use crate::direct::Dialer;

/// Dials `server` and tunnels to `target` through HTTP CONNECT.
///
/// Any bytes the proxy sends after its `200` response head are tunnel data and
/// are replayed before the socket, so a target that speaks first still works.
pub(crate) async fn connect(
    dialer: &Dialer, server: &Endpoint, target: &Endpoint,
) -> io::Result<(BoxStream, Option<std::net::SocketAddr>)> {
    let mut stream = dialer.connect(server).await?;
    let bound = stream.local_addr().ok();
    let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;
    let prefix = read_response(&mut stream).await?;
    let stream: BoxStream = Box::new(PrefixedStream {
        prefix,
        offset: 0,
        inner: stream,
    });
    Ok((stream, bound))
}

/// An HTTP CONNECT outbound node.
pub(crate) struct HttpOutbound {
    pub(crate) server: Endpoint,
    pub(crate) dialer: Dialer,
}

impl crate::outbound::Outbound for HttpOutbound {
    fn connect<'a>(
        &'a self, target: &'a Endpoint,
    ) -> marmo_transport::BoxFuture<'a, io::Result<crate::outbound::Connected>> {
        Box::pin(async move {
            let (stream, bound) = connect(&self.dialer, &self.server, target).await?;
            Ok(crate::outbound::Connected::with_bound(stream, bound))
        })
    }

    fn connect_datagram<'a>(
        &'a self, _target: &'a Endpoint, _ipv4: bool,
    ) -> marmo_transport::BoxFuture<'a, io::Result<Option<crate::outbound::udp::UdpOutbound>>> {
        Box::pin(async { Ok(None) })
    }
}

async fn read_response(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut buffer = Vec::with_capacity(1024);
    loop {
        let mut chunk = [0_u8; 1024];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "HTTP CONNECT proxy closed before responding",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);

        if let Some(position) = find_head_end(&buffer) {
            let head_len = position + 4;
            if head_len > HEAD_MAX {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP CONNECT response is too large",
                ));
            }
            let (code, _) = http::parse_connect_response(&buffer[..head_len])
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            if !(200..300).contains(&code) {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("HTTP CONNECT failed with status {code}"),
                ));
            }
            return Ok(buffer[head_len..].to_vec());
        }
        if buffer.len() >= HEAD_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP CONNECT response is too large",
            ));
        }
    }
}

/// A stream that yields `prefix` before reading from `inner`.
struct PrefixedStream<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if me.offset < me.prefix.len() {
            let remaining = &me.prefix[me.offset..];
            let take = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..take]);
            me.offset += take;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut me.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        ready!(Pin::new(&mut self.get_mut().inner).poll_shutdown(cx))?;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn replays_bytes_after_the_connect_response() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
        let address = listener.local_addr().expect("addr");
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut request = [0_u8; 1024];
            let _ = socket.read(&mut request).await.expect("request");
            socket
                .write_all(b"HTTP/1.1 200 OK\r\n\r\nhello")
                .await
                .expect("response");
            let mut tail = [0_u8; 1];
            let _ = socket.read(&mut tail).await;
        });

        let server = Endpoint::from(address);
        let target = Endpoint::from_domain("example.com", 80).expect("target");
        let (mut stream, _) = connect(&Dialer::default(), &server, &target)
            .await
            .expect("connect");
        let mut greeting = [0_u8; 5];
        stream.read_exact(&mut greeting).await.expect("greeting");
        assert_eq!(&greeting, b"hello");
        drop(stream);
        task.await.expect("task");
    }
}
