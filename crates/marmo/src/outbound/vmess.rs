//! VMess outbound: AEAD request, chunked TCP, and direct UDP.

use std::io;
use std::sync::Arc;

use marmo_net::Endpoint;
use marmo_proto::vmess::{
    COMMAND_TCP, COMMAND_UDP, ChunkDecoder, ChunkEncoder, CmdKey, REQUEST_HEADER_MAX, Request,
    RequestProgress, RequestSecrets, RequestSpec, Security, encode_request, request_progress,
    response_keys,
};
use marmo_transport::{BoxFuture, BoxStream, Layer};
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use zeroize::Zeroize;

use crate::outbound::Connected;
use crate::vmess::{ChunkReader, ChunkStream, ChunkWriter, now_unix, random};

/// A VMess outbound node.
pub(crate) struct VmessOutbound {
    pub(crate) server: Endpoint,
    pub(crate) cmd_key: Arc<CmdKey>,
    pub(crate) security: Security,
    pub(crate) layers: Vec<Arc<dyn Layer>>,
}

impl crate::outbound::Outbound for VmessOutbound {
    fn connect<'a>(&'a self, target: &'a Endpoint) -> BoxFuture<'a, io::Result<Connected>> {
        Box::pin(async move {
            let (mut stream, bound) = open_stream(&self.server, &self.layers).await?;
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
    ) -> BoxFuture<'a, io::Result<Option<crate::outbound::udp::UdpOutbound>>> {
        Box::pin(async move {
            let (mut stream, _bound) = open_stream(&self.server, &self.layers).await?;
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
            Ok(Some(crate::outbound::udp::UdpOutbound::Vmess(Box::new(
                VmessUdpClient {
                    reader: ChunkReader::with_response(reader, decoder, &[], request),
                    writer: ChunkWriter::new(writer, encoder),
                    target: target.clone(),
                },
            ))))
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
    let mut header = [0_u8; REQUEST_HEADER_MAX];
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
        &mut header,
    )
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    stream.write_all(&header[..length]).await?;
    let request = match request_progress(&header[..length], cmd_key, now) {
        RequestProgress::Complete(request) => request,
        _ => {
            header.zeroize();
            return Err(io::Error::other("VMess request did not decode"));
        }
    };
    header.zeroize();
    Ok(request)
}
