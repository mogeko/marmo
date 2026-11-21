//! VLESS outbound: TCP streams and simple UDP-over-TCP associations.

use std::io;
use std::net::SocketAddr;

use marmo_net::Endpoint;
use marmo_proto::vless::{COMMAND_TCP, COMMAND_UDP, REQUEST_HEADER_MAX, Uuid, encode_request};
use marmo_transport::BoxStream;
use marmo_transport::tls::TlsClient;
use tokio::io::AsyncWriteExt;
use zeroize::Zeroize;

use crate::outbound::trojan::tls_error;
use crate::vless::{ClientStream, UotReader, read_response_header, write_udp_frame};

/// Dials `server` and opens a VLESS TCP stream to `target`.
pub(crate) async fn connect(
    server: &Endpoint,
    tls: Option<&TlsClient>,
    uuid: &Uuid,
    target: &Endpoint,
) -> io::Result<(BoxStream, Option<SocketAddr>)> {
    let inner = crate::direct::connect(server).await?;
    let bound = inner.local_addr().ok();
    let mut stream = match tls {
        Some(tls) => tls.connect(Box::new(inner)).await.map_err(tls_error)?,
        None => Box::new(inner),
    };
    write_request(&mut stream, uuid, target, COMMAND_TCP).await?;
    Ok((Box::new(ClientStream::new(stream)), bound))
}

/// A simple UDP-over-TCP association with one fixed target.
pub(crate) struct VlessUdpClient {
    stream: BoxStream,
    frames: UotReader,
    target: Endpoint,
}

impl VlessUdpClient {
    /// Writes one UoT frame; the target must match the association.
    pub(crate) async fn send_to(&mut self, target: &Endpoint, payload: &[u8]) -> io::Result<()> {
        if target != &self.target {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VLESS association has a different target",
            ));
        }
        if payload.is_empty() {
            return Ok(());
        }
        write_udp_frame(&mut self.stream, payload).await
    }

    /// Reads one UoT frame; replies always come from the association target.
    pub(crate) async fn recv_from(&mut self, buffer: &mut [u8]) -> io::Result<(usize, Endpoint)> {
        loop {
            let Some(payload) = self.frames.next(&mut self.stream).await? else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "VLESS association closed",
                ));
            };
            if payload.is_empty() {
                continue;
            }
            if payload.len() > buffer.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "VLESS datagram exceeds the output buffer",
                ));
            }
            buffer[..payload.len()].copy_from_slice(&payload);
            return Ok((payload.len(), self.target.clone()));
        }
    }
}

/// Opens a VLESS UDP association for `target`.
pub(crate) async fn connect_udp(
    server: &Endpoint,
    tls: Option<&TlsClient>,
    uuid: &Uuid,
    target: &Endpoint,
) -> io::Result<VlessUdpClient> {
    let inner = crate::direct::connect(server).await?;
    let mut stream = match tls {
        Some(tls) => tls.connect(Box::new(inner)).await.map_err(tls_error)?,
        None => Box::new(inner),
    };
    write_request(&mut stream, uuid, target, COMMAND_UDP).await?;
    read_response_header(&mut stream).await?;
    Ok(VlessUdpClient {
        stream,
        frames: UotReader::new(&[])?,
        target: target.clone(),
    })
}

async fn write_request(
    stream: &mut BoxStream,
    uuid: &Uuid,
    target: &Endpoint,
    command: u8,
) -> io::Result<usize> {
    let mut header = [0_u8; REQUEST_HEADER_MAX];
    let length = encode_request(uuid, target, command, &mut header)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let written = stream.write_all(&header[..length]).await;
    header.zeroize();
    written?;
    Ok(length)
}
