//! VLESS outbound: TCP streams and simple UDP-over-TCP associations.

use std::io;
use std::sync::{Arc, OnceLock};

use marmo_net::Endpoint;
use marmo_proto::mux::{NETWORK_UDP, STATUS_END, STATUS_KEEP, STATUS_KEEPALIVE, STATUS_NEW};
use marmo_proto::vless::{
    COMMAND_TCP, COMMAND_UDP, REQUEST_HEADER_MAX, Uuid, encode_mux_request, encode_request,
};
use marmo_transport::h2::{H2ClientConnection, H2ClientOptions};
use marmo_transport::{BoxFuture, BoxStream, Layer};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::runtime::Handle;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::direct::Dialer;
use crate::mux::{MuxReader, MuxWriter};
use crate::outbound::h2::{H2Dialer, H2Pool, pool_config};
use crate::outbound::mux::{MuxDialer, MuxPool};
use crate::outbound::stream_pool::StreamDialer;
use crate::vless::{ClientStream, UotReader, read_response_header, write_udp_frame};

/// A VLESS outbound node.
pub(crate) struct VlessOutbound {
    pub(crate) server: Endpoint,
    pub(crate) uuid: Arc<Uuid>,
    pub(crate) xudp: bool,
    pub(crate) mux: bool,
    pub(crate) layers: Vec<Arc<dyn Layer>>,
    pub(crate) h2: Option<H2ClientOptions>,
    pub(crate) h2_pool: OnceLock<Arc<H2Pool>>,
    pub(crate) pool: OnceLock<Arc<MuxPool>>,
    pub(crate) dialer: Dialer,
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
            let (mut stream, bound) = self.open_base().await?;
            write_request(&mut stream, &self.uuid, target, COMMAND_TCP).await?;
            Ok(crate::outbound::Connected::with_bound(
                Box::new(ClientStream::new(stream)),
                bound,
            ))
        })
    }

    fn connect_datagram<'a>(
        &'a self, target: &'a Endpoint, _ipv4: bool,
    ) -> marmo_transport::BoxFuture<'a, io::Result<Option<crate::outbound::datagram::BoxDatagram>>>
    {
        Box::pin(async move {
            if self.mux {
                let Some(pool) = self.pool.get() else {
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "VLESS mux pool is not started",
                    ));
                };
                let datagram = pool.open_udp(target).await?;
                return Ok(Some(
                    Box::new(datagram) as crate::outbound::datagram::BoxDatagram
                ));
            }
            let h2_pool = self.h2_pool()?;
            if self.xudp {
                let client = connect_xudp(
                    &self.dialer,
                    &self.server,
                    &self.uuid,
                    target,
                    &self.layers,
                    h2_pool,
                )
                .await?;
                Ok(Some(
                    Box::new(client) as crate::outbound::datagram::BoxDatagram
                ))
            } else {
                let client = connect_udp(
                    &self.dialer,
                    &self.server,
                    &self.uuid,
                    target,
                    &self.layers,
                    h2_pool,
                )
                .await?;
                Ok(Some(
                    Box::new(client) as crate::outbound::datagram::BoxDatagram
                ))
            }
        })
    }

    fn start(&self, runtime: &Handle, token: &CancellationToken) -> Vec<JoinHandle<()>> {
        let mut tasks = Vec::new();
        if let Some(options) = self.h2.as_ref()
            && self.h2_pool.get().is_none()
        {
            let dialer: Arc<dyn StreamDialer<H2ClientConnection>> = Arc::new(H2Dialer {
                server: self.server.clone(),
                options: options.clone(),
                layers: self.layers.clone(),
                dialer: self.dialer.clone(),
            });
            let pool = H2Pool::new(runtime.clone(), token.clone(), dialer, pool_config());
            tasks.push(pool.supervisor());
            let _ = self.h2_pool.set(pool);
        }
        if self.mux && self.pool.get().is_none() {
            let dialer: Arc<dyn MuxDialer> = Arc::new(VlessDialer {
                server: self.server.clone(),
                uuid: Arc::clone(&self.uuid),
                layers: self.layers.clone(),
                h2: self.h2.is_some(),
                h2_pool: self.h2_pool.get().cloned(),
                dialer: self.dialer.clone(),
            });
            let pool = MuxPool::new(runtime.clone(), token.clone(), dialer);
            tasks.push(pool.supervisor());
            let _ = self.pool.set(pool);
        }
        tasks
    }
}

impl VlessOutbound {
    fn h2_pool(&self) -> io::Result<Option<&Arc<H2Pool>>> {
        if self.h2.is_none() {
            return Ok(None);
        }
        self.h2_pool.get().map(Some).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "VLESS HTTP/2 pool is not started",
            )
        })
    }

    async fn open_base(&self) -> io::Result<(BoxStream, Option<std::net::SocketAddr>)> {
        dial_base(&self.dialer, &self.server, &self.layers, self.h2_pool()?).await
    }
}

struct VlessDialer {
    server: Endpoint,
    uuid: Arc<Uuid>,
    layers: Vec<Arc<dyn Layer>>,
    h2: bool,
    h2_pool: Option<Arc<H2Pool>>,
    dialer: Dialer,
}

impl MuxDialer for VlessDialer {
    fn dial(&self) -> BoxFuture<'_, io::Result<BoxStream>> {
        Box::pin(async move {
            let h2_pool = if self.h2 {
                Some(self.h2_pool.as_ref().ok_or_else(not_started)?)
            } else {
                None
            };
            let (mut stream, _) =
                dial_base(&self.dialer, &self.server, &self.layers, h2_pool).await?;
            let mut header = Zeroizing::new([0_u8; 1 + 16 + 1 + 1]);
            let length = encode_mux_request(&self.uuid, &mut header[..])
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
    /// Whether the response header has been read; it is deferred until the
    /// first reply so the first frame is not held back by the server's
    /// response.
    response_read: bool,
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
        if !self.response_read {
            read_response_header(&mut self.stream).await?;
            self.response_read = true;
        }
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
    dialer: &Dialer, server: &Endpoint, uuid: &Uuid, target: &Endpoint, layers: &[Arc<dyn Layer>],
    h2_pool: Option<&Arc<H2Pool>>,
) -> io::Result<VlessUdpClient> {
    let (mut stream, _bound) = dial_base(dialer, server, layers, h2_pool).await?;
    write_request(&mut stream, uuid, target, COMMAND_UDP).await?;
    Ok(VlessUdpClient {
        stream,
        frames: UotReader::new(&[])?,
        target: target.clone(),
        response_read: false,
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
    dialer: &Dialer, server: &Endpoint, uuid: &Uuid, target: &Endpoint, layers: &[Arc<dyn Layer>],
    h2_pool: Option<&Arc<H2Pool>>,
) -> io::Result<VlessXudpClient> {
    let (mut stream, _bound) = dial_base(dialer, server, layers, h2_pool).await?;
    let mut header = Zeroizing::new([0_u8; 1 + 16 + 1 + 1]);
    let length = encode_mux_request(uuid, &mut header[..])
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

fn not_started() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        "VLESS HTTP/2 pool is not started",
    )
}

async fn dial_base(
    dialer: &Dialer, server: &Endpoint, layers: &[Arc<dyn Layer>], h2_pool: Option<&Arc<H2Pool>>,
) -> io::Result<(BoxStream, Option<std::net::SocketAddr>)> {
    if let Some(pool) = h2_pool {
        return Ok((pool.open().await?, None));
    }
    open_stream(dialer, server, layers).await
}

async fn open_stream(
    dialer: &Dialer, server: &Endpoint, layers: &[Arc<dyn Layer>],
) -> io::Result<(BoxStream, Option<std::net::SocketAddr>)> {
    let inner = dialer.connect(server).await?;
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
    let mut header = Zeroizing::new([0_u8; REQUEST_HEADER_MAX]);
    let length = encode_request(uuid, target, command, &mut header[..])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    stream.write_all(&header[..length]).await?;
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio::time::{Duration, timeout};

    const UUID: &str = "00112233-4455-6677-8899-aabbccddeeff";
    const HEADER_LEN: usize = 1 + 16 + 1 + 1 + 2 + 1 + 4;

    #[tokio::test]
    async fn sends_the_first_uot_frame_before_reading_the_response() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
        let address = listener.local_addr().expect("addr");
        let target = Endpoint::parse("127.0.0.1:9").expect("target");
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut header = [0_u8; HEADER_LEN];
            stream
                .read_exact(&mut header)
                .await
                .expect("request header");
            // Xray and V2Ray withhold the response header until the first
            // body bytes arrive, so waiting here would deadlock.
            let mut frame = [0_u8; 2 + 4];
            stream.read_exact(&mut frame).await.expect("first frame");
            assert_eq!(&frame[2..], b"ping");
            stream.write_all(&[0, 0]).await.expect("response header");
            stream
                .write_all(&[0, 4, b'p', b'o', b'n', b'g'])
                .await
                .expect("reply");
        });

        let server = Endpoint::parse(&address.to_string()).expect("server");
        let uuid = Uuid::parse(UUID).expect("uuid");
        let mut client = timeout(
            Duration::from_secs(2),
            connect_udp(&Dialer::default(), &server, &uuid, &target, &[], None),
        )
        .await
        .expect("connect must not wait for the response header")
        .expect("connect");

        client.send_to(&target, b"ping").await.expect("send");
        let mut buffer = [0_u8; 8];
        let (length, source) = timeout(Duration::from_secs(2), client.recv_from(&mut buffer))
            .await
            .expect("recv timeout")
            .expect("recv");
        assert_eq!(&buffer[..length], b"pong");
        assert_eq!(source, target);
        server_task.await.expect("server");
    }
}
