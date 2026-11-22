//! VLESS outbound: TCP streams and simple UDP-over-TCP associations.

use std::io;
use std::sync::{Arc, OnceLock};

use marmo_net::Endpoint;
use marmo_proto::mux::{NETWORK_UDP, STATUS_END, STATUS_KEEP, STATUS_KEEPALIVE, STATUS_NEW};
use marmo_proto::vless::{
    COMMAND_TCP, COMMAND_UDP, REQUEST_HEADER_MAX, Uuid, encode_mux_request, encode_request,
};
use marmo_transport::{BoxFuture, BoxStream, Layer};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::runtime::Handle;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroize;

use crate::mux::{MuxReader, MuxWriter};
use crate::outbound::mux::{MuxDialer, MuxPool};
use crate::vless::{ClientStream, UotReader, read_response_header, write_udp_frame};

/// Dials `server` and opens a VLESS TCP stream to `target`.
pub(crate) async fn connect(
    server: &Endpoint, uuid: &Uuid, target: &Endpoint, layers: &[Arc<dyn Layer>],
) -> io::Result<(BoxStream, Option<std::net::SocketAddr>)> {
    let (mut stream, bound) = open_stream(server, layers).await?;
    write_request(&mut stream, uuid, target, COMMAND_TCP).await?;
    Ok((Box::new(ClientStream::new(stream)), bound))
}

/// A VLESS outbound node.
pub(crate) struct VlessOutbound {
    pub(crate) server: Endpoint,
    pub(crate) uuid: Arc<Uuid>,
    pub(crate) xudp: bool,
    pub(crate) mux: bool,
    pub(crate) layers: Vec<Arc<dyn Layer>>,
    pub(crate) pool: OnceLock<Arc<MuxPool>>,
}

impl crate::outbound::Outbound for VlessOutbound {
    fn connect<'a>(
        &'a self, target: &'a Endpoint,
    ) -> marmo_transport::BoxFuture<'a, io::Result<crate::outbound::Connected>> {
        Box::pin(async move {
            if self.mux {
                let Some(pool) = self.pool.get() else {
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "VLESS mux pool is not started",
                    ));
                };
                let stream = pool.open_tcp(target).await?;
                return Ok(crate::outbound::Connected::with_bound(stream, None));
            }
            let (stream, bound) = connect(&self.server, &self.uuid, target, &self.layers).await?;
            Ok(crate::outbound::Connected::with_bound(stream, bound))
        })
    }

    fn connect_datagram<'a>(
        &'a self, target: &'a Endpoint, _ipv4: bool,
    ) -> marmo_transport::BoxFuture<'a, io::Result<Option<crate::outbound::udp::UdpOutbound>>> {
        Box::pin(async move {
            if self.mux {
                let Some(pool) = self.pool.get() else {
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "VLESS mux pool is not started",
                    ));
                };
                let datagram = pool.open_udp(target).await?;
                return Ok(Some(crate::outbound::udp::UdpOutbound::Mux(Box::new(
                    datagram,
                ))));
            }
            if self.xudp {
                let client = connect_xudp(&self.server, &self.uuid, target, &self.layers).await?;
                Ok(Some(crate::outbound::udp::UdpOutbound::VlessXudp(client)))
            } else {
                let client = connect_udp(&self.server, &self.uuid, target, &self.layers).await?;
                Ok(Some(crate::outbound::udp::UdpOutbound::Vless(client)))
            }
        })
    }

    fn start(&self, runtime: &Handle, token: &CancellationToken) -> Option<JoinHandle<()>> {
        if !self.mux || self.pool.get().is_some() {
            return None;
        }
        let dialer: Arc<dyn MuxDialer> = Arc::new(VlessDialer {
            server: self.server.clone(),
            uuid: Arc::clone(&self.uuid),
            layers: self.layers.clone(),
        });
        let pool = MuxPool::new(runtime.clone(), token.clone(), dialer);
        let supervisor = pool.supervisor();
        let _ = self.pool.set(pool);
        Some(supervisor)
    }
}

struct VlessDialer {
    server: Endpoint,
    uuid: Arc<Uuid>,
    layers: Vec<Arc<dyn Layer>>,
}

impl MuxDialer for VlessDialer {
    fn dial(&self) -> BoxFuture<'_, io::Result<BoxStream>> {
        Box::pin(async move {
            let (mut stream, _) = open_stream(&self.server, &self.layers).await?;
            let mut header = [0_u8; 1 + 16 + 1 + 1];
            let length = encode_mux_request(&self.uuid, &mut header)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            stream.write_all(&header[..length]).await?;
            Ok(stream)
        })
    }

    fn handshake_len(&self) -> usize {
        2
    }
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
    server: &Endpoint, uuid: &Uuid, target: &Endpoint, layers: &[Arc<dyn Layer>],
) -> io::Result<VlessUdpClient> {
    let (mut stream, _bound) = open_stream(server, layers).await?;
    write_request(&mut stream, uuid, target, COMMAND_UDP).await?;
    read_response_header(&mut stream).await?;
    Ok(VlessUdpClient {
        stream,
        frames: UotReader::new(&[])?,
        target: target.clone(),
    })
}

/// A VLESS XUDP association with one fixed target.
pub(crate) struct VlessXudpClient {
    read_half: Option<ReadHalf<BoxStream>>,
    reader: Option<MuxReader<ReadHalf<BoxStream>>>,
    writer: MuxWriter<WriteHalf<BoxStream>>,
    target: Endpoint,
}

impl VlessXudpClient {
    /// Writes one Keep frame; the target must match the association.
    pub(crate) async fn send_to(&mut self, target: &Endpoint, payload: &[u8]) -> io::Result<()> {
        if target != &self.target {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "XUDP association has a different target",
            ));
        }
        if payload.is_empty() {
            return Ok(());
        }
        self.writer.keep(0, None, payload).await
    }

    /// Reads one data frame; replies carry the source or the fixed target.
    pub(crate) async fn recv_from(&mut self, buffer: &mut [u8]) -> io::Result<(usize, Endpoint)> {
        if self.reader.is_none() {
            let mut read_half = self.read_half.take().ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "XUDP stream closed")
            })?;
            let mut response = [0_u8; 2];
            read_half.read_exact(&mut response).await?;
            if response != [0, 0] {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid VLESS mux response",
                ));
            }
            self.reader = Some(MuxReader::new(read_half, &[])?);
        }
        loop {
            let Some(frame) = self
                .reader
                .as_mut()
                .expect("reader is initialized above")
                .next()
                .await?
            else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "XUDP association closed",
                ));
            };
            if frame.meta.session != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected XUDP session",
                ));
            }
            match frame.meta.status {
                STATUS_NEW | STATUS_KEEP => {
                    if frame.meta.target.is_some() && frame.meta.network != NETWORK_UDP {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "unexpected XUDP network",
                        ));
                    }
                    if frame.data.is_empty() {
                        continue;
                    }
                    if frame.data.len() > buffer.len() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "XUDP datagram exceeds the output buffer",
                        ));
                    }
                    buffer[..frame.data.len()].copy_from_slice(&frame.data);
                    let source = frame.meta.target.unwrap_or_else(|| self.target.clone());
                    return Ok((frame.data.len(), source));
                }
                STATUS_KEEPALIVE => continue,
                STATUS_END => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "XUDP association ended",
                    ));
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected XUDP frame",
                    ));
                }
            }
        }
    }
}

/// Opens a VLESS XUDP association for `target`.
pub(crate) async fn connect_xudp(
    server: &Endpoint, uuid: &Uuid, target: &Endpoint, layers: &[Arc<dyn Layer>],
) -> io::Result<VlessXudpClient> {
    let (mut stream, _bound) = open_stream(server, layers).await?;
    let mut header = [0_u8; 1 + 16 + 1 + 1];
    let length = encode_mux_request(uuid, &mut header)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    stream.write_all(&header[..length]).await?;
    let (read_half, write_half) = tokio::io::split(stream);
    let mut writer = MuxWriter::new(write_half);
    writer.new_session(0, target, NETWORK_UDP, &[]).await?;
    Ok(VlessXudpClient {
        read_half: Some(read_half),
        reader: None,
        writer,
        target: target.clone(),
    })
}

async fn open_stream(
    server: &Endpoint, layers: &[Arc<dyn Layer>],
) -> io::Result<(BoxStream, Option<std::net::SocketAddr>)> {
    let inner = crate::direct::connect(server).await?;
    let bound = inner.local_addr().ok();
    let mut stream: BoxStream = Box::new(inner);
    for layer in layers {
        stream = layer.wrap(stream).await.map_err(io::Error::other)?;
    }
    Ok((stream, bound))
}

async fn write_request(
    stream: &mut BoxStream, uuid: &Uuid, target: &Endpoint, command: u8,
) -> io::Result<usize> {
    let mut header = [0_u8; REQUEST_HEADER_MAX];
    let length = encode_request(uuid, target, command, &mut header)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let written = stream.write_all(&header[..length]).await;
    header.zeroize();
    written?;
    Ok(length)
}
