//! VMess inbound: AEAD header, replay filter, TCP, UDP, and Mux.Cool.

use std::io;
use std::sync::{Arc, Mutex};

use marmo_net::{Endpoint, Network};
use marmo_proto::vless::MAX_UDP_PAYLOAD;
use marmo_proto::vmess::{
    COMMAND_MUX, COMMAND_TCP, COMMAND_UDP, ChunkDecoder, ChunkEncoder, CmdKey, REQUEST_HEADER_MAX,
    Request, RequestProgress, encode_response, is_mux_target, request_progress, response_keys,
};
use marmo_transport::h2::H2ServerOptions;
use marmo_transport::{BoxFuture, BoxStream, Layer};
use tokio::io::{AsyncReadExt, AsyncWriteExt, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{Notify, mpsc};
use tokio_util::sync::CancellationToken;

use crate::deadline::{Deadline, wait_for_activity};
use crate::instance::Context;
use crate::outbound::udp::UdpOutbound;
use crate::routing::{Action, Metadata};
use crate::sniff::{self, Policy};
use crate::vmess::{ChunkReader, ChunkStream, ChunkWriter, ReplayFilter, now_unix, random};

/// Bounded queue between the chunk reader and the outbound reply task.
const UDP_QUEUE: usize = 16;
/// Encrypted response header is 18 + 4 + 16 bytes.
const RESPONSE_MAX: usize = 64;

/// Handles one accepted VMess connection.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle(
    client: TcpStream, context: Arc<Context>, inbound: Arc<str>, cmd_key: Arc<CmdKey>,
    replay: Arc<Mutex<ReplayFilter>>, layers: Arc<[Arc<dyn Layer>]>, sniffing: Option<Policy>,
    deadline: Deadline,
) {
    let token = context.supervisor.token();
    let Some(source) = client.peer_addr().ok().map(Endpoint::from) else {
        return;
    };
    let prepared = tokio::select! {
        _ = token.cancelled() => return,
        result = deadline.run(prepare(client, &layers, &cmd_key, &replay)) => result,
    };
    let Ok(Ok(prepared)) = prepared else {
        return;
    };
    serve_prepared(
        prepared, source, context, inbound, sniffing, deadline, token,
    )
    .await;
}

/// Handles one stream accepted from a VMess HTTP/2 connection.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_stream(
    stream: BoxStream, source: Endpoint, context: Arc<Context>, inbound: Arc<str>,
    cmd_key: Arc<CmdKey>, replay: Arc<Mutex<ReplayFilter>>, sniffing: Option<Policy>,
    deadline: Deadline, token: CancellationToken,
) {
    let prepared = tokio::select! {
        _ = token.cancelled() => return,
        result = deadline.run(prepare_stream(stream, &cmd_key, &replay)) => result,
    };
    let Ok(Ok(prepared)) = prepared else {
        return;
    };
    serve_prepared(
        prepared, source, context, inbound, sniffing, deadline, token,
    )
    .await;
}

/// Serves every stream on one VMess HTTP/2 connection.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve_h2(
    client: TcpStream, context: Arc<Context>, inbound: Arc<str>, cmd_key: Arc<CmdKey>,
    replay: Arc<Mutex<ReplayFilter>>, layers: Arc<[Arc<dyn Layer>]>, options: H2ServerOptions,
    sniffing: Option<Policy>, deadline: Deadline,
) {
    let handler_context = Arc::clone(&context);
    let handler: Arc<super::h2::StreamHandler> =
        Arc::new(move |stream, source, deadline, token| {
            let context = Arc::clone(&handler_context);
            let inbound = Arc::clone(&inbound);
            let cmd_key = Arc::clone(&cmd_key);
            let replay = Arc::clone(&replay);
            let future: BoxFuture<'static, ()> = Box::pin(async move {
                handle_stream(
                    stream, source, context, inbound, cmd_key, replay, sniffing, deadline, token,
                )
                .await;
            });
            future
        });
    super::h2::serve(client, layers, options, context, deadline, handler).await;
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
    prepare_stream(stream, cmd_key, replay).await
}

async fn prepare_stream(
    mut stream: BoxStream, cmd_key: &CmdKey, replay: &Mutex<ReplayFilter>,
) -> io::Result<Prepared> {
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

async fn serve_prepared(
    prepared: Prepared, source: Endpoint, context: Arc<Context>, inbound: Arc<str>,
    sniffing: Option<Policy>, deadline: Deadline, token: CancellationToken,
) {
    let Prepared {
        stream,
        request,
        leftover,
    } = prepared;
    match request.command {
        COMMAND_TCP => {
            connect_relay(
                stream, request, leftover, &context, &inbound, source, token, deadline, sniffing,
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

#[allow(clippy::too_many_arguments)]
async fn connect_relay(
    mut stream: BoxStream, request: Request, mut leftover: Vec<u8>, context: &Context,
    inbound: &str, source: Endpoint, token: CancellationToken, deadline: Deadline,
    sniffing: Option<Policy>,
) {
    let mut domain = request.target.domain().map(str::to_owned);
    if let (Some(policy), None) = (sniffing, domain.as_deref()) {
        let sniffed = tokio::select! {
            _ = token.cancelled() => return,
            result = deadline.run(sniff::sniff_stream(stream, leftover, policy)) => result,
        };
        let Ok(sniffed) = sniffed else {
            return;
        };
        stream = sniffed.stream;
        domain = sniffed.domain;
        leftover = Vec::new();
    }

    let Some(action) = route(
        context,
        inbound,
        source,
        &request.target,
        Network::Tcp,
        domain.as_deref(),
    )
    .await
    else {
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
    let Some(action) = route(
        &context,
        &inbound,
        source,
        &request.target,
        Network::Udp,
        request.target.domain(),
    )
    .await
    else {
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
    let client: BoxStream = Box::new(ChunkStream::server(stream, &request, padding, &leftover));
    super::mux::serve(client, &[], context, inbound, source, token).await;
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

async fn route(
    context: &Context, inbound: &str, source: Endpoint, target: &Endpoint, network: Network,
    domain: Option<&str>,
) -> Option<Action> {
    let metadata = Metadata {
        network,
        source,
        destination: target.clone(),
        domain,
        inbound: Some(inbound),
        process: None,
    };
    Some(context.route(metadata).await)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
