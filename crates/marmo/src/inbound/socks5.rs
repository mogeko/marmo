//! SOCKS5 CONNECT inbound: greeting, request, route, connect, relay.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use marmo_net::Network;
use marmo_proto::socks5::{
    Greeting, METHOD_NO_ACCEPTABLE, METHOD_NO_AUTH, ReplyStatus, Request, VERSION,
    encode_method_selection, encode_reply,
};
use marmo_transport::{BoxStream, RelayOptions, relay};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::instance::Context;
use crate::routing::Metadata;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// Handles one accepted SOCKS5 connection.
pub(crate) async fn handle(mut client: TcpStream, context: Arc<Context>, inbound: Arc<str>) {
    let token = context.supervisor.token();
    let handshake = tokio::select! {
        _ = token.cancelled() => return,
        result = timeout(
            context.limits.handshake_timeout,
            negotiate(&mut client, &context, &inbound),
        ) => result,
    };
    let Ok(Ok(Some(remote))) = handshake else {
        return;
    };

    let options = RelayOptions {
        idle_timeout: context.limits.idle_timeout,
        uplink_grace: context.limits.uplink_grace,
        downlink_grace: context.limits.downlink_grace,
    };
    tokio::select! {
        _ = token.cancelled() => {}
        _ = relay(
            Box::new(client) as BoxStream,
            Box::new(remote) as BoxStream,
            options,
        ) => {}
    }
}

async fn negotiate(
    client: &mut TcpStream,
    context: &Context,
    inbound: &str,
) -> io::Result<Option<TcpStream>> {
    let Some(request) = handshake(client).await? else {
        return Ok(None);
    };

    let destination = request.destination;
    let domain = destination.domain().map(str::to_owned);
    let source = client.peer_addr()?.into();
    let metadata = Metadata {
        network: Network::Tcp,
        source,
        destination: destination.clone(),
        domain: domain.as_deref(),
        inbound: Some(inbound),
    };
    let action = context.router.route(&metadata);

    match context.connect(action, &destination).await {
        Ok(remote) => {
            let bound = remote.local_addr().ok();
            if send_reply(client, ReplyStatus::Succeeded, bound)
                .await
                .is_err()
            {
                return Ok(None);
            }
            Ok(Some(remote))
        }
        Err(error) => {
            let _ = send_reply(client, reply_status(&error), None).await;
            Ok(None)
        }
    }
}

async fn handshake(client: &mut TcpStream) -> io::Result<Option<Request>> {
    if !greet(client).await? {
        return Ok(None);
    }

    let mut header = [0_u8; 4];
    client.read_exact(&mut header).await?;
    if header[0] != VERSION {
        return Ok(None);
    }
    if header[2] != 0 {
        let _ = send_reply(client, ReplyStatus::GeneralFailure, None).await;
        return Ok(None);
    }
    if header[1] != 0x01 {
        let _ = send_reply(client, ReplyStatus::CommandNotSupported, None).await;
        return Ok(None);
    }

    let mut message = Vec::with_capacity(262);
    message.extend_from_slice(&header);
    match header[3] {
        ATYP_IPV4 => {
            let mut rest = [0_u8; 6];
            client.read_exact(&mut rest).await?;
            message.extend_from_slice(&rest);
        }
        ATYP_IPV6 => {
            let mut rest = [0_u8; 18];
            client.read_exact(&mut rest).await?;
            message.extend_from_slice(&rest);
        }
        ATYP_DOMAIN => {
            let mut length = [0_u8; 1];
            client.read_exact(&mut length).await?;
            message.push(length[0]);
            let mut rest = vec![0_u8; usize::from(length[0]) + 2];
            client.read_exact(&mut rest).await?;
            message.extend_from_slice(&rest);
        }
        _ => {
            let _ = send_reply(client, ReplyStatus::AddressNotSupported, None).await;
            return Ok(None);
        }
    }

    match Request::parse(&message) {
        Ok(request) => Ok(Some(request)),
        Err(_) => {
            let _ = send_reply(client, ReplyStatus::GeneralFailure, None).await;
            Ok(None)
        }
    }
}

async fn greet(client: &mut TcpStream) -> io::Result<bool> {
    let mut head = [0_u8; 2];
    client.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Ok(false);
    }
    let count = usize::from(head[1]);
    if count == 0 {
        let _ = send_method(client, METHOD_NO_ACCEPTABLE).await;
        return Ok(false);
    }

    let mut message = vec![0_u8; 2 + count];
    message[..2].copy_from_slice(&head);
    client.read_exact(&mut message[2..]).await?;
    let Ok(greeting) = Greeting::parse(&message) else {
        let _ = send_method(client, METHOD_NO_ACCEPTABLE).await;
        return Ok(false);
    };
    if !greeting.accepts_no_auth() {
        let _ = send_method(client, METHOD_NO_ACCEPTABLE).await;
        return Ok(false);
    }
    send_method(client, METHOD_NO_AUTH).await?;
    Ok(true)
}

async fn send_method(client: &mut TcpStream, method: u8) -> io::Result<()> {
    let mut buffer = [0_u8; 2];
    let length = encode_method_selection(method, &mut buffer).map_err(codec_error)?;
    client.write_all(&buffer[..length]).await
}

async fn send_reply(
    client: &mut TcpStream,
    status: ReplyStatus,
    bound: Option<SocketAddr>,
) -> io::Result<()> {
    let mut buffer = [0_u8; 22];
    let length = encode_reply(status, bound, &mut buffer).map_err(codec_error)?;
    client.write_all(&buffer[..length]).await
}

fn reply_status(error: &io::Error) -> ReplyStatus {
    match error.kind() {
        io::ErrorKind::PermissionDenied => ReplyStatus::NotAllowed,
        io::ErrorKind::ConnectionRefused => ReplyStatus::ConnectionRefused,
        io::ErrorKind::TimedOut => ReplyStatus::TtlExpired,
        io::ErrorKind::NotFound => ReplyStatus::HostUnreachable,
        _ => ReplyStatus::GeneralFailure,
    }
}

fn codec_error(error: marmo_proto::socks5::Socks5Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
