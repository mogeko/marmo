//! Trojan outbound: TLS, authentication line, and CONNECT request.

use std::io;
use std::net::SocketAddr;

use marmo_net::Endpoint;
use marmo_proto::trojan::{
    COMMAND_CONNECT, COMMAND_UDP_ASSOCIATE, PasswordHash, REQUEST_HEADER_MAX, encode_request_header,
};
use marmo_transport::BoxStream;
use marmo_transport::tls::TlsClient;
use tokio::io::AsyncWriteExt;
use zeroize::Zeroize;

use crate::trojan::{FrameReader, write_frame};

/// Dials `server` over TLS and sends a CONNECT request for `target`.
pub(crate) async fn connect(
    server: &Endpoint,
    tls: &TlsClient,
    password: &PasswordHash,
    target: &Endpoint,
) -> io::Result<(BoxStream, Option<SocketAddr>)> {
    let inner = crate::direct::connect(server).await?;
    let bound = inner.local_addr().ok();
    let mut stream = tls.connect(Box::new(inner)).await.map_err(tls_error)?;

    let mut header = [0_u8; REQUEST_HEADER_MAX];
    let length = encode_request_header(password, target, COMMAND_CONNECT, &mut header)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let written = stream.write_all(&header[..length]).await;
    header.zeroize();
    written?;
    Ok((stream, bound))
}

/// A Trojan UDP association carried over one TLS stream.
pub(crate) struct TrojanUdpClient {
    stream: BoxStream,
    frames: FrameReader,
}

impl TrojanUdpClient {
    /// Writes one address and payload frame.
    pub(crate) async fn send_to(&mut self, target: &Endpoint, payload: &[u8]) -> io::Result<()> {
        write_frame(&mut self.stream, target, payload).await
    }

    /// Reads one frame and copies its payload into `buffer`.
    pub(crate) async fn recv_from(&mut self, buffer: &mut [u8]) -> io::Result<(usize, Endpoint)> {
        let Some((source, payload)) = self.frames.next(&mut self.stream).await? else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "trojan association closed",
            ));
        };
        if payload.len() > buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trojan datagram exceeds the output buffer",
            ));
        }
        buffer[..payload.len()].copy_from_slice(&payload);
        Ok((payload.len(), source))
    }
}

/// Dials `server` over TLS and opens a UDP association for `target`.
pub(crate) async fn connect_udp(
    server: &Endpoint,
    tls: &TlsClient,
    password: &PasswordHash,
    target: &Endpoint,
) -> io::Result<TrojanUdpClient> {
    let inner = crate::direct::connect(server).await?;
    let mut stream = tls.connect(Box::new(inner)).await.map_err(tls_error)?;
    let mut header = [0_u8; REQUEST_HEADER_MAX];
    let length = encode_request_header(password, target, COMMAND_UDP_ASSOCIATE, &mut header)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let written = stream.write_all(&header[..length]).await;
    header.zeroize();
    written?;
    Ok(TrojanUdpClient {
        stream,
        frames: FrameReader::new(&[])?,
    })
}

pub(crate) fn tls_error(error: marmo_transport::tls::TlsError) -> io::Error {
    io::Error::other(error)
}
