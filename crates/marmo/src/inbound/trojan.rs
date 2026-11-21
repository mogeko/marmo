//! Trojan inbound: TLS termination, authentication probe, CONNECT, fallback.
//!
//! Traffic that does not start with the configured authentication line is
//! replayed to the optional fallback service (ADR-0011). UDP ASSOCIATE frames
//! are routed per datagram with one sticky outbound per association.

use std::io;
use std::sync::Arc;

use marmo_net::{Endpoint, Network};
use marmo_proto::trojan::{
    AUTH_PREFIX_LEN, AuthState, COMMAND_CONNECT, COMMAND_UDP_ASSOCIATE, MAX_UDP_PAYLOAD,
    PasswordHash, REQUEST_HEADER_MAX, RequestProgress, auth_state, request_progress,
};
use marmo_transport::tls::TlsServer;
use marmo_transport::{BoxStream, RelayOptions, relay};
use tokio::io::{AsyncReadExt, AsyncWriteExt, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::instance::Context;
use crate::outbound::trojan::tls_error;
use crate::outbound::udp::UdpOutbound;
use crate::routing::{Action, Metadata};
use crate::trojan::{FrameReader, write_frame};

/// Bounded queue between the frame reader and the outbound reply task.
const UDP_QUEUE: usize = 16;

/// Handles one accepted Trojan connection.
pub(crate) async fn handle(
    client: TcpStream,
    context: Arc<Context>,
    inbound: Arc<str>,
    tls: Arc<TlsServer>,
    password: Arc<PasswordHash>,
    fallback: Option<Endpoint>,
) {
    let token = context.supervisor.token();
    let source = client.peer_addr().ok().map(Endpoint::from);
    let prepared = tokio::select! {
        _ = token.cancelled() => return,
        result = timeout(
            context.limits.handshake_timeout,
            prepare(client, &tls, &password),
        ) => result,
    };
    let (Ok(Ok(prepared)), Some(source)) = (prepared, source) else {
        return;
    };

    match prepared {
        Prepared::Fallback { stream, prefix } => {
            fallback_relay(stream, prefix, fallback, &context, &inbound, source, token).await;
        }
        Prepared::Request {
            stream,
            command,
            target,
            leftover,
        } => match command {
            COMMAND_CONNECT => {
                connect_relay(stream, &context, &inbound, source, target, leftover, token).await;
            }
            COMMAND_UDP_ASSOCIATE => {
                handle_udp(stream, context, inbound, source, leftover, token).await;
            }
            _ => {}
        },
    }
}

enum Prepared {
    Fallback {
        stream: BoxStream,
        prefix: Vec<u8>,
    },
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
    password: &PasswordHash,
) -> io::Result<Prepared> {
    let accepted = tls.accept(Box::new(client)).await.map_err(tls_error)?;
    let mut stream = accepted.stream;

    let mut auth = Zeroizing::new([0_u8; AUTH_PREFIX_LEN]);
    let mut filled = 0;
    loop {
        match auth_state(&auth[..filled], password) {
            AuthState::Matched => break,
            AuthState::Mismatched => {
                return Ok(Prepared::Fallback {
                    stream,
                    prefix: auth[..filled].to_vec(),
                });
            }
            AuthState::NeedMore => {}
        }
        let read = stream.read(&mut auth[filled..]).await?;
        if read == 0 {
            return Ok(Prepared::Fallback {
                stream,
                prefix: auth[..filled].to_vec(),
            });
        }
        filled += read;
    }

    let mut buffer = [0_u8; REQUEST_HEADER_MAX];
    let mut filled = 0;
    loop {
        match request_progress(&buffer[..filled]) {
            RequestProgress::Complete(request) => {
                return Ok(Prepared::Request {
                    stream,
                    command: request.command,
                    target: request.target,
                    leftover: buffer[request.consumed..filled].to_vec(),
                });
            }
            RequestProgress::Invalid => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid trojan request",
                ));
            }
            RequestProgress::NeedMore => {}
        }
        if filled == buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trojan request header is too long",
            ));
        }
        let read = stream.read(&mut buffer[filled..]).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "trojan request header is truncated",
            ));
        }
        filled += read;
    }
}

async fn connect_relay(
    stream: BoxStream,
    context: &Context,
    inbound: &str,
    source: Endpoint,
    target: Endpoint,
    leftover: Vec<u8>,
    token: CancellationToken,
) {
    let Some(action) = route(context, inbound, source, &target) else {
        return;
    };
    let connected = tokio::select! {
        _ = token.cancelled() => return,
        result = timeout(context.limits.handshake_timeout, context.connect(action, &target)) => result,
    };
    let Ok(Ok((mut remote, _bound))) = connected else {
        return;
    };
    if !leftover.is_empty() && remote.write_all(&leftover).await.is_err() {
        return;
    }
    relay_streams(stream, remote, context, token).await;
}

async fn handle_udp(
    stream: BoxStream,
    context: Arc<Context>,
    inbound: Arc<str>,
    source: Endpoint,
    leftover: Vec<u8>,
    token: CancellationToken,
) {
    let ipv4 = source.ip().is_none_or(|ip| ip.is_ipv4());
    let (mut reader, writer) = tokio::io::split(stream);
    let Ok(mut frames) = FrameReader::new(&leftover) else {
        return;
    };
    let (sender, receiver) = mpsc::channel(UDP_QUEUE);
    let reply = tokio::spawn(reply_loop(
        writer,
        receiver,
        Arc::clone(&context),
        ipv4,
        token.clone(),
    ));

    loop {
        let next = tokio::select! {
            _ = token.cancelled() => break,
            result = frames.next(&mut reader) => result,
        };
        let Ok(Some((destination, payload))) = next else {
            break;
        };
        if payload.is_empty() {
            continue;
        }
        let Some(action) = route(&context, &inbound, source.clone(), &destination) else {
            continue;
        };
        if sender.send((action, destination, payload)).await.is_err() {
            break;
        }
    }
    drop(sender);
    let _ = reply.await;
}

async fn reply_loop(
    mut writer: WriteHalf<BoxStream>,
    mut receiver: mpsc::Receiver<(Action, Endpoint, Vec<u8>)>,
    context: Arc<Context>,
    ipv4: bool,
    token: CancellationToken,
) {
    let mut outbound: Option<(Action, UdpOutbound)> = None;
    let mut buffer = vec![0_u8; MAX_UDP_PAYLOAD];
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            message = receiver.recv() => {
                let Some((action, target, payload)) = message else {
                    break;
                };
                if outbound
                    .as_ref()
                    .is_some_and(|(current, _)| *current != action)
                {
                    continue;
                }
                if outbound.is_none() {
                    match context.udp_outbound(action, ipv4, &target).await {
                        Ok(Some(connection)) => outbound = Some((action, connection)),
                        _ => continue,
                    }
                }
                if let Some((_, connection)) = outbound.as_mut() {
                    let _ = connection.send_to(&target, &payload).await;
                }
            }
            received = async {
                match outbound.as_mut() {
                    Some((_, connection)) => connection.recv_from(&mut buffer).await,
                    None => std::future::pending().await,
                }
            } => {
                let Ok((length, source)) = received else {
                    continue;
                };
                if write_frame(&mut writer, &source, &buffer[..length]).await.is_err() {
                    break;
                }
            }
        }
    }
}

async fn fallback_relay(
    stream: BoxStream,
    prefix: Vec<u8>,
    fallback: Option<Endpoint>,
    context: &Context,
    inbound: &str,
    source: Endpoint,
    token: CancellationToken,
) {
    let (Some(target), false) = (fallback, prefix.is_empty()) else {
        return;
    };
    let Some(action) = route(context, inbound, source, &target) else {
        return;
    };
    let connected = tokio::select! {
        _ = token.cancelled() => return,
        result = timeout(context.limits.handshake_timeout, context.connect(action, &target)) => result,
    };
    let Ok(Ok((mut remote, _bound))) = connected else {
        return;
    };
    if remote.write_all(&prefix).await.is_err() {
        return;
    }
    relay_streams(stream, remote, context, token).await;
}

fn route(
    context: &Context,
    inbound: &str,
    source: Endpoint,
    target: &Endpoint,
) -> Option<crate::routing::Action> {
    let domain = target.domain().map(str::to_owned);
    let metadata = Metadata {
        network: Network::Tcp,
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
