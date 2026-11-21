//! VLESS inbound: TLS termination, UUID authentication, TCP and simple UoT.

use std::io;
use std::sync::Arc;

use marmo_net::{Endpoint, Network};
use marmo_proto::vless::{
    COMMAND_MUX, COMMAND_TCP, COMMAND_UDP, MAX_UDP_PAYLOAD, REQUEST_HEADER_MAX, RequestProgress,
    Uuid, is_mux_target, request_progress,
};
use marmo_proto::xudp::{STATUS_END, STATUS_KEEP, STATUS_KEEPALIVE, STATUS_NEW};
use marmo_transport::h2::H2Server;
use marmo_transport::tls::TlsServer;
use marmo_transport::ws::WsServer;
use marmo_transport::{BoxStream, RelayOptions, relay};
use tokio::io::{AsyncReadExt, AsyncWriteExt, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::instance::Context;
use crate::outbound::trojan::tls_error;
use crate::outbound::udp::UdpOutbound;
use crate::routing::{Action, Metadata};
use crate::vless::{UotReader, write_udp_frame};
use crate::xudp::{XudpReader, write_keep};

/// Bounded queue between the frame reader and the outbound reply task.
const UDP_QUEUE: usize = 16;
/// Empty VLESS response header.
const RESPONSE: [u8; 2] = [0, 0];

/// Handles one accepted VLESS connection.
pub(crate) async fn handle(
    client: TcpStream,
    context: Arc<Context>,
    inbound: Arc<str>,
    uuid: Arc<Uuid>,
    tls: Arc<TlsServer>,
    ws: Option<Arc<WsServer>>,
    h2: Option<Arc<H2Server>>,
) {
    let token = context.supervisor.token();
    let source = client.peer_addr().ok().map(Endpoint::from);
    let prepared = tokio::select! {
        _ = token.cancelled() => return,
        result = timeout(
            context.limits.handshake_timeout,
            prepare(client, &tls, ws.as_deref(), h2.as_deref(), &uuid),
        ) => result,
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
            connect_relay(stream, &context, &inbound, source, target, leftover, token).await;
        }
        COMMAND_UDP => {
            handle_udp(stream, context, inbound, source, target, leftover, token).await;
        }
        COMMAND_MUX => {
            if !is_mux_target(&target) {
                return;
            }
            handle_xudp(stream, context, inbound, source, leftover, token).await;
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
    client: TcpStream,
    tls: &TlsServer,
    ws: Option<&WsServer>,
    h2: Option<&H2Server>,
    uuid: &Uuid,
) -> io::Result<Prepared> {
    let accepted = tls.accept(Box::new(client)).await.map_err(tls_error)?;
    let mut stream = accepted.stream;
    if let Some(ws) = ws {
        stream = ws.accept(stream).await.map_err(io::Error::other)?.stream;
    } else if let Some(h2) = h2 {
        stream = h2.accept(stream).await.map_err(io::Error::other)?;
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

async fn connect_relay(
    mut stream: BoxStream,
    context: &Context,
    inbound: &str,
    source: Endpoint,
    target: Endpoint,
    leftover: Vec<u8>,
    token: CancellationToken,
) {
    let Some(action) = route(context, inbound, source, &target, Network::Tcp) else {
        return;
    };
    let connected = tokio::select! {
        _ = token.cancelled() => return,
        result = timeout(context.limits.handshake_timeout, context.connect(action, &target)) => result,
    };
    let Ok(Ok((mut remote, _bound))) = connected else {
        return;
    };
    if stream.write_all(&RESPONSE).await.is_err() {
        return;
    }
    if !leftover.is_empty() && remote.write_all(&leftover).await.is_err() {
        return;
    }
    relay_streams(stream, remote, context, token).await;
}

async fn handle_udp(
    mut stream: BoxStream,
    context: Arc<Context>,
    inbound: Arc<str>,
    source: Endpoint,
    target: Endpoint,
    leftover: Vec<u8>,
    token: CancellationToken,
) {
    let ipv4 = source.ip().is_none_or(|ip| ip.is_ipv4());
    let Some(action) = route(&context, &inbound, source, &target, Network::Udp) else {
        return;
    };
    let outbound = tokio::select! {
        _ = token.cancelled() => return,
        result = timeout(
            context.limits.handshake_timeout,
            context.udp_outbound(action, ipv4, &target),
        ) => result,
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
    let (sender, receiver) = mpsc::channel(UDP_QUEUE);
    let reply = tokio::spawn(reply_loop(
        writer,
        receiver,
        outbound,
        target,
        token.clone(),
        false,
    ));

    loop {
        let next = tokio::select! {
            _ = token.cancelled() => break,
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

#[allow(clippy::too_many_arguments)]
async fn handle_xudp(
    mut stream: BoxStream,
    context: Arc<Context>,
    inbound: Arc<str>,
    source: Endpoint,
    leftover: Vec<u8>,
    token: CancellationToken,
) {
    let ipv4 = source.ip().is_none_or(|ip| ip.is_ipv4());
    let Ok(mut frames) = XudpReader::new(&leftover) else {
        return;
    };
    let first = tokio::select! {
        _ = token.cancelled() => return,
        result = frames.next(&mut stream) => result,
    };
    let Ok(Some(first)) = first else {
        return;
    };
    if first.meta.status != STATUS_NEW {
        return;
    }
    let Some(target) = first.meta.target.clone() else {
        return;
    };
    let Some(action) = route(&context, &inbound, source, &target, Network::Udp) else {
        return;
    };
    let outbound = tokio::select! {
        _ = token.cancelled() => return,
        result = timeout(
            context.limits.handshake_timeout,
            context.udp_outbound(action, ipv4, &target),
        ) => result,
    };
    let Ok(Ok(Some(mut outbound))) = outbound else {
        return;
    };
    if stream.write_all(&RESPONSE).await.is_err() {
        return;
    }
    if !first.data.is_empty() && outbound.send_to(&target, &first.data).await.is_err() {
        return;
    }

    let (mut reader, writer) = tokio::io::split(stream);
    let (sender, receiver) = mpsc::channel(UDP_QUEUE);
    let reply = tokio::spawn(reply_loop(
        writer,
        receiver,
        outbound,
        target.clone(),
        token.clone(),
        true,
    ));

    loop {
        let next = tokio::select! {
            _ = token.cancelled() => break,
            result = frames.next(&mut reader) => result,
        };
        let Ok(Some(frame)) = next else {
            break;
        };
        match frame.meta.status {
            STATUS_NEW | STATUS_KEEP => {
                if frame
                    .meta
                    .target
                    .as_ref()
                    .is_some_and(|destination| destination != &target)
                {
                    break;
                }
                if frame.data.is_empty() {
                    continue;
                }
                if sender.send(frame.data).await.is_err() {
                    break;
                }
            }
            STATUS_KEEPALIVE => continue,
            STATUS_END => break,
            _ => break,
        }
    }
    drop(sender);
    let _ = reply.await;
}

async fn reply_loop(
    mut writer: WriteHalf<BoxStream>,
    mut receiver: mpsc::Receiver<Vec<u8>>,
    mut outbound: UdpOutbound,
    target: Endpoint,
    token: CancellationToken,
    xudp: bool,
) {
    let mut buffer = vec![0_u8; MAX_UDP_PAYLOAD];
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            message = receiver.recv() => {
                let Some(payload) = message else {
                    break;
                };
                let _ = outbound.send_to(&target, &payload).await;
            }
            received = outbound.recv_from(&mut buffer) => {
                let Ok((length, _source)) = received else {
                    continue;
                };
                let written = if xudp {
                    write_keep(&mut writer, &buffer[..length]).await
                } else {
                    write_udp_frame(&mut writer, &buffer[..length]).await
                };
                if written.is_err() {
                    break;
                }
            }
        }
    }
}

fn route(
    context: &Context,
    inbound: &str,
    source: Endpoint,
    target: &Endpoint,
    network: Network,
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

async fn relay_streams(
    client: BoxStream,
    remote: BoxStream,
    context: &Context,
    token: CancellationToken,
) {
    let options = RelayOptions {
        idle_timeout: context.limits.idle_timeout,
        uplink_grace: context.limits.uplink_grace,
        downlink_grace: context.limits.downlink_grace,
    };
    tokio::select! {
        _ = token.cancelled() => {}
        _ = relay(client, remote, options) => {}
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
