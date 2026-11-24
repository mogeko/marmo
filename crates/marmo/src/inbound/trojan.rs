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
use marmo_transport::BoxStream;
use marmo_transport::tls::TlsServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{Notify, mpsc};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::deadline::{Deadline, wait_for_activity};
use crate::instance::Context;
use crate::outbound::datagram::{BoxDatagram, DatagramError};
use crate::outbound::trojan::tls_error;
use crate::routing::{Action, Metadata};
use crate::sniff::{self, Policy};
use crate::trojan::{FrameReader, write_frame};

/// Bounded queue between the frame reader and the outbound reply task.
const UDP_QUEUE: usize = 16;

/// Handles one accepted Trojan connection.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle(
    client: TcpStream, context: Arc<Context>, inbound: Arc<str>, tls: Arc<TlsServer>,
    password: Arc<PasswordHash>, fallback: Option<Endpoint>, sniffing: Option<Policy>,
    deadline: Deadline,
) {
    let token = context.supervisor.token();
    let source = client.peer_addr().ok().map(Endpoint::from);
    let prepared = tokio::select! {
        _ = token.cancelled() => return,
        result = deadline.run(prepare(client, &tls, &password)) => result,
    };
    let (Ok(Ok(prepared)), Some(source)) = (prepared, source) else {
        return;
    };

    match prepared {
        Prepared::Fallback { stream, prefix } => {
            fallback_relay(
                stream, prefix, fallback, &context, &inbound, source, token, deadline,
            )
            .await;
        }
        Prepared::Request {
            stream,
            command,
            target,
            leftover,
        } => match command {
            COMMAND_CONNECT => {
                connect_relay(
                    stream, &context, &inbound, source, target, leftover, token, deadline, sniffing,
                )
                .await;
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
    client: TcpStream, tls: &TlsServer, password: &PasswordHash,
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

    let Some(action) = route(context, inbound, source, &target, domain.as_deref()).await else {
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
    if !leftover.is_empty() && remote.write_all(&leftover).await.is_err() {
        return;
    }
    relay_streams(stream, remote, context, token).await;
}

async fn handle_udp(
    stream: BoxStream, context: Arc<Context>, inbound: Arc<str>, source: Endpoint,
    leftover: Vec<u8>, token: CancellationToken,
) {
    let ipv4 = source.ip().is_none_or(|ip| ip.is_ipv4());
    let (mut reader, writer) = tokio::io::split(stream);
    let Ok(mut frames) = FrameReader::new(&leftover) else {
        return;
    };
    let activity = Arc::new(Notify::new());
    let (sender, receiver) = mpsc::channel(UDP_QUEUE);
    let reply = tokio::spawn(reply_loop(
        writer,
        receiver,
        Arc::clone(&context),
        ipv4,
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
        let Ok(Some((destination, payload))) = next else {
            break;
        };
        if payload.is_empty() {
            continue;
        }
        let Some(action) = route(
            &context,
            &inbound,
            source.clone(),
            &destination,
            destination.domain(),
        )
        .await
        else {
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
    mut writer: WriteHalf<BoxStream>, mut receiver: mpsc::Receiver<(Action, Endpoint, Vec<u8>)>,
    context: Arc<Context>, ipv4: bool, token: CancellationToken, activity: Arc<Notify>,
) {
    let mut outbound: Option<(Action, BoxDatagram)> = None;
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
                    match timeout(
                        context.limits.handshake_timeout,
                        context.udp_outbound(action, ipv4, &target),
                    )
                    .await
                    {
                        Ok(Ok(Some(connection))) => outbound = Some((action, connection)),
                        _ => continue,
                    }
                }
                if let Some((_, connection)) = outbound.as_mut()
                    && connection.send_to(&target, &payload).await.is_err() {
                        break;
                    }
            }
            received = async {
                match outbound.as_mut() {
                    Some((_, connection)) => connection.recv_from(&mut buffer).await,
                    None => std::future::pending().await,
                }
            } => {
                let (length, source) = match received {
                    Ok(reply) => reply,
                    Err(DatagramError::NoReply) => continue,
                    Err(DatagramError::Io(_)) => break,
                };
                activity.notify_one();
                if write_frame(&mut writer, &source, &buffer[..length]).await.is_err() {
                    break;
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn fallback_relay(
    stream: BoxStream, prefix: Vec<u8>, fallback: Option<Endpoint>, context: &Context,
    inbound: &str, source: Endpoint, token: CancellationToken, deadline: Deadline,
) {
    let (Some(target), false) = (fallback, prefix.is_empty()) else {
        return;
    };
    let Some(action) = route(context, inbound, source, &target, None).await else {
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
    if remote.write_all(&prefix).await.is_err() {
        return;
    }
    relay_streams(stream, remote, context, token).await;
}

async fn route(
    context: &Context, inbound: &str, source: Endpoint, target: &Endpoint, domain: Option<&str>,
) -> Option<Action> {
    let metadata = Metadata {
        network: Network::Tcp,
        source,
        destination: target.clone(),
        domain,
        inbound: Some(inbound),
        process: None,
    };
    Some(context.route(metadata).await)
}

async fn relay_streams(
    client: BoxStream, remote: BoxStream, context: &Context, token: CancellationToken,
) {
    context.relay_streams(client, remote, &token).await;
}
