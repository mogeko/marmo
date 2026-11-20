//! Trojan inbound: TLS termination, authentication probe, CONNECT, fallback.
//!
//! Traffic that does not start with the configured authentication line is
//! replayed to the optional fallback service (ADR-0011). UDP ASSOCIATE is not
//! wired yet.

use std::io;
use std::sync::Arc;

use marmo_net::{Endpoint, Network};
use marmo_proto::trojan::{
    AUTH_PREFIX_LEN, AuthState, COMMAND_CONNECT, PasswordHash, REQUEST_HEADER_MAX, RequestProgress,
    auth_state, request_progress,
};
use marmo_transport::tls::TlsServer;
use marmo_transport::{BoxStream, RelayOptions, relay};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::instance::Context;
use crate::outbound::trojan::tls_error;
use crate::routing::Metadata;

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
        } => {
            if command != COMMAND_CONNECT {
                return;
            }
            connect_relay(stream, &context, &inbound, source, target, leftover, token).await;
        }
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
