//! VLESS inbound: TLS termination, UUID authentication, TCP and simple UoT.

use std::io;
use std::sync::Arc;

use marmo_net::{Endpoint, Network};
use marmo_proto::vless::{
    COMMAND_TCP, COMMAND_UDP, MAX_UDP_PAYLOAD, REQUEST_HEADER_MAX, RequestProgress, Uuid,
    request_progress,
};
use marmo_transport::tls::TlsServer;
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
) {
    let token = context.supervisor.token();
    let source = client.peer_addr().ok().map(Endpoint::from);
    let prepared = tokio::select! {
        _ = token.cancelled() => return,
        result = timeout(
            context.limits.handshake_timeout,
            prepare(client, &tls, &uuid),
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

async fn prepare(client: TcpStream, tls: &TlsServer, uuid: &Uuid) -> io::Result<Prepared> {
    let accepted = tls.accept(Box::new(client)).await.map_err(tls_error)?;
    let mut stream = accepted.stream;
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

async fn reply_loop(
    mut writer: WriteHalf<BoxStream>,
    mut receiver: mpsc::Receiver<Vec<u8>>,
    mut outbound: UdpOutbound,
    target: Endpoint,
    token: CancellationToken,
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
                if write_udp_frame(&mut writer, &buffer[..length]).await.is_err() {
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
