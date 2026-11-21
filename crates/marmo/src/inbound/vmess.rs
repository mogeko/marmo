//! VMess inbound: AEAD header, replay filter, TCP, UDP, and Mux.Cool.

use std::io;
use std::sync::{Arc, Mutex};

use marmo_net::{Endpoint, Network};
use marmo_proto::vless::MAX_UDP_PAYLOAD;
use marmo_proto::vmess::{
    COMMAND_MUX, COMMAND_TCP, COMMAND_UDP, ChunkDecoder, ChunkEncoder, CmdKey, REQUEST_HEADER_MAX,
    Request, RequestProgress, encode_response, is_mux_target, request_progress, response_keys,
};
use marmo_transport::{BoxStream, Layer};
use tokio::io::{AsyncReadExt, AsyncWriteExt, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{Notify, mpsc};
use tokio_util::sync::CancellationToken;

use crate::deadline::{Deadline, wait_for_activity};
use crate::instance::Context;
use crate::outbound::udp::UdpOutbound;
use crate::routing::{Action, Metadata};
use crate::vmess::{ChunkReader, ChunkStream, ChunkWriter, ReplayFilter, now_unix, random};

/// Bounded queue between the chunk reader and the outbound reply task.
const UDP_QUEUE: usize = 16;
/// Encrypted response header is 18 + 4 + 16 bytes.
const RESPONSE_MAX: usize = 64;

/// Handles one accepted VMess connection.
pub(crate) async fn handle(
    client: TcpStream, context: Arc<Context>, inbound: Arc<str>, cmd_key: Arc<CmdKey>,
    replay: Arc<Mutex<ReplayFilter>>, layers: Arc<[Arc<dyn Layer>]>, deadline: Deadline,
) {
    let token = context.supervisor.token();
    let source = client.peer_addr().ok().map(Endpoint::from);
    let prepared = tokio::select! {
        _ = token.cancelled() => return,
        result = deadline.run(prepare(client, &layers, &cmd_key, &replay)) => result,
    };
    let (
        Ok(Ok(Prepared {
            stream,
            request,
            leftover,
        })),
        Some(source),
    ) = (prepared, source)
    else {
        return;
    };

    match request.command {
        COMMAND_TCP => {
            connect_relay(
                stream, request, leftover, &context, &inbound, source, token, deadline,
            )
            .await;
        }
        COMMAND_UDP => {
            handle_udp(
                stream, request, leftover, context, inbound, source, token, deadline,
            )
            .await;
        }
        COMMAND_MUX => {
            if !is_mux_target(&request.target) {
                return;
            }
            handle_mux(stream, request, leftover, context, inbound, source, token).await;
        }
        _ => {}
    }
}

struct Prepared {
    stream: BoxStream,
    request: Request,
    leftover: Vec<u8>,
}

async fn prepare(
    client: TcpStream, layers: &[Arc<dyn Layer>], cmd_key: &CmdKey, replay: &Mutex<ReplayFilter>,
) -> io::Result<Prepared> {
    let mut stream: BoxStream = Box::new(client);
    for layer in layers {
        stream = layer.accept(stream).await.map_err(io::Error::other)?;
    }
    let mut buffer = [0_u8; REQUEST_HEADER_MAX];
    let mut filled = 0;
    let now = now_unix();
    loop {
        match request_progress(&buffer[..filled], cmd_key, now) {
            RequestProgress::Complete(request) => {
                let accepted = replay
                    .lock()
                    .map_err(|_| io::Error::other("VMess replay filter is poisoned"))?
                    .check_and_insert(request.auth_id, now);
                if !accepted {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "replayed VMess auth id",
                    ));
                }
                let leftover = buffer[request.consumed..filled].to_vec();
                return Ok(Prepared {
                    stream,
                    request,
                    leftover,
                });
            }
            RequestProgress::NeedMore => {}
            RequestProgress::Unauthorized => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "invalid VMess auth id",
                ));
            }
            RequestProgress::Invalid => {
                return Err(invalid("invalid VMess request"));
            }
        }
        if filled == buffer.len() {
            return Err(invalid("VMess request header is too long"));
        }
        let read = stream.read(&mut buffer[filled..]).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "VMess request header is truncated",
            ));
        }
        filled += read;
    }
}

#[allow(clippy::too_many_arguments)]
async fn connect_relay(
    mut stream: BoxStream, request: Request, leftover: Vec<u8>, context: &Context, inbound: &str,
    source: Endpoint, token: CancellationToken, deadline: Deadline,
) {
    let Some(action) = route(context, inbound, source, &request.target, Network::Tcp) else {
        return;
    };
    let connected = tokio::select! {
        _ = token.cancelled() => return,
        result = deadline.run(context.connect(action, &request.target)) => result,
    };
    let Ok(Ok(connected)) = connected else {
        return;
    };
    let mut response = [0_u8; RESPONSE_MAX];
    let Ok(length) = encode_response(&request, &mut response) else {
        return;
    };
    if stream.write_all(&response[..length]).await.is_err() {
        return;
    }
    let Ok(padding) = random::<64>() else {
        return;
    };
    let client: BoxStream = Box::new(ChunkStream::server(stream, &request, padding, &leftover));
    context
        .relay_streams(client, connected.stream, &token)
        .await;
}

#[allow(clippy::too_many_arguments)]
async fn handle_udp(
    mut stream: BoxStream, request: Request, leftover: Vec<u8>, context: Arc<Context>,
    inbound: Arc<str>, source: Endpoint, token: CancellationToken, deadline: Deadline,
) {
    let ipv4 = source.ip().is_none_or(|ip| ip.is_ipv4());
    let Some(action) = route(&context, &inbound, source, &request.target, Network::Udp) else {
        return;
    };
    let outbound = tokio::select! {
        _ = token.cancelled() => return,
        result = deadline.run(context.udp_outbound(action, ipv4, &request.target)) => result,
    };
    let Ok(Ok(Some(outbound))) = outbound else {
        return;
    };
    let mut response = [0_u8; RESPONSE_MAX];
    let Ok(length) = encode_response(&request, &mut response) else {
        return;
    };
    if stream.write_all(&response[..length]).await.is_err() {
        return;
    }
    let Ok(padding) = random::<64>() else {
        return;
    };
    let decoder = ChunkDecoder::new(
        request.security,
        &request.body_key,
        &request.body_iv,
        request.option,
    );
    let (response_key, response_iv) = response_keys(&request.body_key, &request.body_iv);
    let encoder = ChunkEncoder::new(
        request.security,
        &response_key,
        &response_iv,
        request.option,
        padding,
    );
    let (reader, writer) = tokio::io::split(stream);
    let mut chunks = ChunkReader::new(reader, decoder, &leftover);
    let frames = ChunkWriter::new(writer, encoder);
    let target = request.target.clone();
    let activity = Arc::new(Notify::new());
    let (sender, receiver) = mpsc::channel(UDP_QUEUE);
    let reply = tokio::spawn(reply_loop(
        frames,
        receiver,
        outbound,
        target,
        token.clone(),
        Arc::clone(&activity),
    ));

    loop {
        let next = tokio::select! {
            _ = token.cancelled() => break,
            idle = wait_for_activity(context.limits.idle_timeout, &activity) => {
                if idle {
                    break;
                }
                continue;
            }
            result = chunks.next() => result,
        };
        let Ok(Some(payload)) = next else {
            break;
        };
        if payload.is_empty() {
            continue;
        }
        if sender.send(payload).await.is_err() {
            break;
        }
    }
    drop(sender);
    let _ = reply.await;
}

#[allow(clippy::too_many_arguments)]
async fn handle_mux(
    mut stream: BoxStream, request: Request, leftover: Vec<u8>, context: Arc<Context>,
    inbound: Arc<str>, source: Endpoint, token: CancellationToken,
) {
    let mut response = [0_u8; RESPONSE_MAX];
    let Ok(length) = encode_response(&request, &mut response) else {
        return;
    };
    if stream.write_all(&response[..length]).await.is_err() {
        return;
    }
    let Ok(padding) = random::<64>() else {
        return;
    };
    let client = ChunkStream::server(stream, &request, padding, &leftover);
    super::mux::serve(client, context, inbound, source, token).await;
}

async fn reply_loop(
    mut frames: ChunkWriter<WriteHalf<BoxStream>>, mut receiver: mpsc::Receiver<Vec<u8>>,
    mut outbound: UdpOutbound, target: Endpoint, token: CancellationToken, activity: Arc<Notify>,
) {
    let mut buffer = vec![0_u8; MAX_UDP_PAYLOAD];
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            message = receiver.recv() => {
                let Some(payload) = message else {
                    break;
                };
                if outbound.send_to(&target, &payload).await.is_err() {
                    break;
                }
            }
            received = outbound.recv_from(&mut buffer) => {
                let Ok((length, _source)) = received else {
                    break;
                };
                activity.notify_one();
                if frames.write(&buffer[..length]).await.is_err() {
                    break;
                }
            }
        }
    }
}

fn route(
    context: &Context, inbound: &str, source: Endpoint, target: &Endpoint, network: Network,
) -> Option<Action> {
    let domain = target.domain().map(str::to_owned);
    let metadata = Metadata {
        network,
        source,
        destination: target.clone(),
        domain: domain.as_deref(),
        inbound: Some(inbound),
    };
    Some(context.router.route(&metadata))
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
