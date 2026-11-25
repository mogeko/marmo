//! VMess outbound: AEAD request, chunked TCP, and direct UDP.

use std::io;
use std::sync::{Arc, OnceLock};

use marmo_net::Endpoint;
use marmo_proto::vmess::{
    COMMAND_MUX, COMMAND_TCP, COMMAND_UDP, ChunkDecoder, ChunkEncoder, CmdKey, MUX_DOMAIN,
    MUX_PORT, REQUEST_HEADER_MAX, Request, RequestProgress, RequestSecrets, RequestSpec, Security,
    encode_request, request_progress, response_keys,
};
use marmo_transport::h2::{H2ClientConnection, H2ClientOptions};
use marmo_transport::{BoxFuture, BoxStream, Layer};
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::runtime::Handle;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::direct::Dialer;
use crate::outbound::Connected;
use crate::outbound::h2::{H2Dialer, H2Pool, pool_config};
use crate::outbound::mux::{MuxDialer, MuxPool};
use crate::outbound::stream_pool::StreamDialer;
use crate::vmess::{ChunkReader, ChunkStream, ChunkWriter, now_unix, random};

/// A VMess outbound node.
pub(crate) struct VmessOutbound {
    pub(crate) server: Endpoint,
    pub(crate) cmd_key: Arc<CmdKey>,
    pub(crate) security: Security,
    pub(crate) mux: bool,
    pub(crate) layers: Vec<Arc<dyn Layer>>,
    pub(crate) h2: Option<H2ClientOptions>,
    pub(crate) h2_pool: OnceLock<Arc<H2Pool>>,
    pub(crate) pool: OnceLock<Arc<MuxPool>>,
    pub(crate) dialer: Dialer,
}

impl crate::outbound::Outbound for VmessOutbound {
    fn connect<'a>(&'a self, target: &'a Endpoint) -> BoxFuture<'a, io::Result<Connected>> {
        Box::pin(async move {
            if self.mux {
                let Some(pool) = self.pool.get() else {
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "VMess mux pool is not started",
                    ));
                };
                let stream = pool.open_tcp(target).await?;
                return Ok(Connected::with_bound(stream, None));
            }
            let (mut stream, bound) = self.open_base().await?;
            let request = write_request(
                &mut stream,
                &self.cmd_key,
                target,
                COMMAND_TCP,
                self.security,
            )
            .await?;
            let padding =
                random::<64>().map_err(|_| io::Error::other("random source unavailable"))?;
            let client = ChunkStream::client(stream, request, padding, &[]);
            Ok(Connected::with_bound(Box::new(client), bound))
        })
    }

    fn connect_datagram<'a>(
        &'a self, target: &'a Endpoint, _ipv4: bool,
    ) -> BoxFuture<'a, io::Result<Option<crate::outbound::datagram::BoxDatagram>>> {
        Box::pin(async move {
            if self.mux {
                let Some(pool) = self.pool.get() else {
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "VMess mux pool is not started",
                    ));
                };
                let datagram = pool.open_udp(target).await?;
                return Ok(Some(
                    Box::new(datagram) as crate::outbound::datagram::BoxDatagram
                ));
            }
            let (mut stream, _bound) = self.open_base().await?;
            let request = write_request(
                &mut stream,
                &self.cmd_key,
                target,
                COMMAND_UDP,
                self.security,
            )
            .await?;
            let (response_key, response_iv) = response_keys(&request.body_key, &request.body_iv);
            let decoder = ChunkDecoder::new(
                request.security,
                &response_key,
                &response_iv,
                request.option,
            );
            let padding =
                random::<64>().map_err(|_| io::Error::other("random source unavailable"))?;
            let encoder = ChunkEncoder::new(
                request.security,
                &request.body_key,
                &request.body_iv,
                request.option,
                padding,
            );
            let (reader, writer) = tokio::io::split(stream);
            Ok(Some(Box::new(VmessUdpClient {
                reader: ChunkReader::with_response(reader, decoder, &[], request),
                writer: ChunkWriter::new(writer, encoder),
                target: target.clone(),
            })
                as crate::outbound::datagram::BoxDatagram))
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
            let dialer: Arc<dyn MuxDialer> = Arc::new(VmessDialer {
                server: self.server.clone(),
                cmd_key: Arc::clone(&self.cmd_key),
                security: self.security,
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

impl VmessOutbound {
    fn h2_pool(&self) -> io::Result<Option<&Arc<H2Pool>>> {
        if self.h2.is_none() {
            return Ok(None);
        }
        self.h2_pool.get().map(Some).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "VMess HTTP/2 pool is not started",
            )
        })
    }

    async fn open_base(&self) -> io::Result<(BoxStream, Option<std::net::SocketAddr>)> {
        dial_base(&self.dialer, &self.server, &self.layers, self.h2_pool()?).await
    }
}

struct VmessDialer {
    server: Endpoint,
    cmd_key: Arc<CmdKey>,
    security: Security,
    layers: Vec<Arc<dyn Layer>>,
    h2: bool,
    h2_pool: Option<Arc<H2Pool>>,
    dialer: Dialer,
}

impl MuxDialer for VmessDialer {
    fn dial(&self) -> BoxFuture<'_, io::Result<BoxStream>> {
        Box::pin(async move {
            let h2_pool = if self.h2 {
                Some(self.h2_pool.as_ref().ok_or_else(not_started)?)
            } else {
                None
            };
            let (mut stream, _) =
                dial_base(&self.dialer, &self.server, &self.layers, h2_pool).await?;
            let target = Endpoint::from_domain(MUX_DOMAIN, MUX_PORT)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "mux target"))?;
            let request = write_request(
                &mut stream,
                &self.cmd_key,
                &target,
                COMMAND_MUX,
                self.security,
            )
            .await?;
            let padding =
                random::<64>().map_err(|_| io::Error::other("random source unavailable"))?;
            let client: BoxStream = Box::new(ChunkStream::client(stream, request, padding, &[]));
            Ok(client)
        })
    }
}

/// A direct UDP association with one fixed target.
pub(crate) struct VmessUdpClient {
    reader: ChunkReader<ReadHalf<BoxStream>>,
    writer: ChunkWriter<WriteHalf<BoxStream>>,
    target: Endpoint,
}

impl VmessUdpClient {
    /// Writes one datagram; the target must match the association.
    pub(crate) async fn send_to(&mut self, target: &Endpoint, payload: &[u8]) -> io::Result<()> {
        if target != &self.target {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VMess association has a different target",
            ));
        }
        if payload.is_empty() {
            return Ok(());
        }
        self.writer.write(payload).await
    }

    /// Reads one datagram; replies come from the association target.
    pub(crate) async fn recv_from(&mut self, buffer: &mut [u8]) -> io::Result<(usize, Endpoint)> {
        loop {
            let Some(payload) = self.reader.next().await? else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "VMess association closed",
                ));
            };
            if payload.is_empty() {
                continue;
            }
            if payload.len() > buffer.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "VMess datagram exceeds the output buffer",
                ));
            }
            buffer[..payload.len()].copy_from_slice(&payload);
            return Ok((payload.len(), self.target.clone()));
        }
    }
}

fn not_started() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        "VMess HTTP/2 pool is not started",
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
    stream: &mut BoxStream, cmd_key: &CmdKey, target: &Endpoint, command: u8, security: Security,
) -> io::Result<Request> {
    let now = now_unix();
    let secrets = RequestSecrets {
        body_iv: random::<16>().map_err(|_| io::Error::other("random source unavailable"))?,
        body_key: random::<16>().map_err(|_| io::Error::other("random source unavailable"))?,
        response_auth: random::<1>().map_err(|_| io::Error::other("random source unavailable"))?[0],
        auth_rand: random::<4>().map_err(|_| io::Error::other("random source unavailable"))?,
        connection_nonce: random::<8>()
            .map_err(|_| io::Error::other("random source unavailable"))?,
    };
    let padding = random::<16>().map_err(|_| io::Error::other("random source unavailable"))?;
    let padding_len = usize::from(padding[0] & 0x0f);
    let mut header = Zeroizing::new([0_u8; REQUEST_HEADER_MAX]);
    let length = encode_request(
        cmd_key,
        &RequestSpec {
            target,
            command,
            security,
            timestamp: now,
            padding: &padding[1..1 + padding_len],
            secrets: &secrets,
        },
        &mut header[..],
    )
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    stream.write_all(&header[..length]).await?;
    match request_progress(&header[..length], cmd_key, now) {
        RequestProgress::Complete(request) => Ok(request),
        _ => Err(io::Error::other("VMess request did not decode")),
    }
}
