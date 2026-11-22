//! VLESS inbound: TLS termination, UUID authentication, TCP and simple UoT.

use std::io;
use std::sync::Arc;

use marmo_net::{Endpoint, Network};
use marmo_proto::vless::{
    COMMAND_MUX, COMMAND_TCP, COMMAND_UDP, MAX_UDP_PAYLOAD, REQUEST_HEADER_MAX, RequestProgress,
    Uuid, is_mux_target, request_progress,
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
use crate::sniff::{self, Policy};
use crate::vless::{UotReader, write_udp_frame};

/// Bounded queue between the frame reader and the outbound reply task.
const UDP_QUEUE: usize = 16;
/// Empty VLESS response header.
const RESPONSE: [u8; 2] = [0, 0];

/// Handles one accepted VLESS connection.
pub(crate) async fn handle(
    client: TcpStream, context: Arc<Context>, inbound: Arc<str>, uuid: Arc<Uuid>,
    layers: Arc<[Arc<dyn Layer>]>, sniffing: Option<Policy>, deadline: Deadline,
) {
    let token = context.supervisor.token();
    let source = client.peer_addr().ok().map(Endpoint::from);
    let prepared = tokio::select! {
        _ = token.cancelled() => return,
        result = deadline.run(prepare(client, &layers, &uuid)) => result,
    };
    let (
        Ok(Ok(Prepared::Request {
            stream,
            command,
            target,
            leftover,
        })),
        Some(source),
    ) = (prepared, source)
    else {
        return;
    };

    match command {
        COMMAND_TCP => {
            connect_relay(
                stream, &context, &inbound, source, target, leftover, token, deadline, sniffing,
            )
            .await;
        }
        COMMAND_UDP => {
            handle_udp(
                stream, context, inbound, source, target, leftover, token, deadline,
            )
            .await;
        }
        COMMAND_MUX => {
            if !is_mux_target(&target) {
                return;
            }
            handle_mux(stream, leftover, context, inbound, source, token).await;
        }
        _ => {}
    }
}

enum Prepared {
    Request {
        stream: BoxStream,
        command: u8,
        target: Endpoint,
        leftover: Vec<u8>,
    },
}

async fn prepare(
    client: TcpStream, layers: &[Arc<dyn Layer>], uuid: &Uuid,
) -> io::Result<Prepared> {
    let mut stream: BoxStream = Box::new(client);
    for layer in layers {
        stream = layer.accept(stream).await.map_err(io::Error::other)?;
    }
    let mut buffer = [0_u8; REQUEST_HEADER_MAX];
    let mut filled = 0;
    loop {
        match request_progress(&buffer[..filled]) {
            RequestProgress::Complete(request) => {
                if !uuid.matches(request.uuid.as_bytes()) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "invalid VLESS UUID",
                    ));
                }
                return Ok(Prepared::Request {
                    stream,
                    command: request.command,
                    target: request.target,
                    leftover: buffer[request.consumed..filled].to_vec(),
                });
            }
            RequestProgress::Invalid => {
                return Err(invalid("invalid VLESS request"));
            }
            RequestProgress::NeedMore => {}
        }
        if filled == buffer.len() {
            return Err(invalid("VLESS request header is too long"));
        }
        let read = stream.read(&mut buffer[filled..]).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "VLESS request header is truncated",
            ));
        }
        filled += read;
    }
}

#[allow(clippy::too_many_arguments)]
async fn connect_relay(
    mut stream: BoxStream, context: &Context, inbound: &str, source: Endpoint, target: Endpoint,
    mut leftover: Vec<u8>, token: CancellationToken, deadline: Deadline, sniffing: Option<Policy>,
) {
    let mut domain = target.domain().map(str::to_owned);
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
        &target,
        Network::Tcp,
        domain.as_deref(),
    ) else {
        return;
    };
    let connected = tokio::select! {
        _ = token.cancelled() => return,
        result = deadline.run(context.connect(action, &target)) => result,
    };
    let Ok(Ok(connected)) = connected else {
        return;
    };
    let mut remote = connected.stream;
    if stream.write_all(&RESPONSE).await.is_err() {
        return;
    }
    if !leftover.is_empty() && remote.write_all(&leftover).await.is_err() {
        return;
    }
    relay_streams(stream, remote, context, token).await;
}

#[allow(clippy::too_many_arguments)]
async fn handle_udp(
    mut stream: BoxStream, context: Arc<Context>, inbound: Arc<str>, source: Endpoint,
    target: Endpoint, leftover: Vec<u8>, token: CancellationToken, deadline: Deadline,
) {
    let ipv4 = source.ip().is_none_or(|ip| ip.is_ipv4());
    let Some(action) = route(
        &context,
        &inbound,
        source,
        &target,
        Network::Udp,
        target.domain(),
    ) else {
        return;
    };
    let outbound = tokio::select! {
        _ = token.cancelled() => return,
        result = deadline.run(context.udp_outbound(action, ipv4, &target)) => result,
    };
    let Ok(Ok(Some(outbound))) = outbound else {
        return;
    };
    if stream.write_all(&RESPONSE).await.is_err() {
        return;
    }

    let (mut reader, writer) = tokio::io::split(stream);
    let Ok(mut frames) = UotReader::new(&leftover) else {
        return;
    };
    let activity = Arc::new(Notify::new());
    let (sender, receiver) = mpsc::channel(UDP_QUEUE);
    let reply = tokio::spawn(reply_loop(
        writer,
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
            result = frames.next(&mut reader) => result,
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

async fn handle_mux(
    mut stream: BoxStream, leftover: Vec<u8>, context: Arc<Context>, inbound: Arc<str>,
    source: Endpoint, token: CancellationToken,
) {
    if stream.write_all(&RESPONSE).await.is_err() {
        return;
    }
    super::mux::serve(stream, &leftover, context, inbound, source, token).await;
}

async fn reply_loop(
    mut writer: WriteHalf<BoxStream>, mut receiver: mpsc::Receiver<Vec<u8>>,
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
                if write_udp_frame(&mut writer, &buffer[..length])
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }
}

fn route(
    context: &Context, inbound: &str, source: Endpoint, target: &Endpoint, network: Network,
    domain: Option<&str>,
) -> Option<Action> {
    let metadata = Metadata {
        network,
        source,
        destination: target.clone(),
        domain,
        inbound: Some(inbound),
    };
    Some(context.router.route(&metadata))
}

async fn relay_streams(
    client: BoxStream, remote: BoxStream, context: &Context, token: CancellationToken,
) {
    context.relay_streams(client, remote, &token).await;
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
