//! SOCKS5 inbound: CONNECT tunnels and UDP ASSOCIATE relays.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use marmo_net::{Endpoint, Network};
use marmo_proto::socks5::{
    Command, Greeting, METHOD_NO_ACCEPTABLE, METHOD_NO_AUTH, ReplyStatus, Request, VERSION,
    encode_method_selection, encode_reply, encode_udp, parse_udp,
};
use marmo_transport::{BoxStream, RelayOptions, relay};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::deadline::Deadline;
use crate::instance::Context;
use crate::outbound::udp::UdpOutbound;
use crate::routing::{Action, Metadata};

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const UDP_BUFFER: usize = 65_535;
const UDP_REPLY_BUFFER: usize = 65_535 + 262;

/// Handles one accepted SOCKS5 connection.
pub(crate) async fn handle(
    mut client: TcpStream,
    context: Arc<Context>,
    inbound: Arc<str>,
    deadline: Deadline,
) {
    let token = context.supervisor.token();
    let handshake = tokio::select! {
        _ = token.cancelled() => return,
        result = deadline.run(handshake(&mut client)) => result,
    };
    let Ok(Ok(Some(request))) = handshake else {
        return;
    };

    match request.command {
        Command::Connect => {
            let connect = tokio::select! {
                _ = token.cancelled() => return,
                result = deadline.run(
                    connect_target(&mut client, &context, &inbound, request.destination),
                ) => result,
            };
            let Ok(Ok(Some(remote))) = connect else {
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
        Command::UdpAssociate => {
            udp_associate(client, context, inbound, token).await;
        }
        Command::Bind => {}
    }
}

async fn connect_target(
    client: &mut TcpStream,
    context: &Context,
    inbound: &str,
    destination: Endpoint,
) -> io::Result<Option<marmo_transport::BoxStream>> {
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
        Ok(connected) => {
            if send_reply(client, ReplyStatus::Succeeded, connected.bound)
                .await
                .is_err()
            {
                return Ok(None);
            }
            Ok(Some(connected.stream))
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
    if header[1] != 0x01 && header[1] != 0x03 {
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

enum UdpEvent {
    Cancel,
    Control(io::Result<usize>),
    Client(io::Result<(usize, SocketAddr)>),
    Upstream(io::Result<(usize, Endpoint)>),
}

async fn udp_event(
    token: &CancellationToken,
    client: &mut TcpStream,
    client_socket: &UdpSocket,
    upstream: &mut Option<UdpOutbound>,
    client_buffer: &mut [u8],
    upstream_buffer: &mut [u8],
    control_buffer: &mut [u8],
) -> UdpEvent {
    let awaiting = async {
        match upstream {
            Some(connection) => connection.recv_from(upstream_buffer).await,
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        _ = token.cancelled() => UdpEvent::Cancel,
        result = client.read(control_buffer) => UdpEvent::Control(result),
        result = client_socket.recv_from(client_buffer) => UdpEvent::Client(result),
        result = awaiting => UdpEvent::Upstream(result),
    }
}

async fn udp_associate(
    mut client: TcpStream,
    context: Arc<Context>,
    inbound: Arc<str>,
    token: CancellationToken,
) {
    let Ok(tcp_local) = client.local_addr() else {
        return;
    };
    let ipv4 = tcp_local.is_ipv4();
    let bind = if ipv4 {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0_u16; 8], 0))
    };
    let Ok(client_socket) = UdpSocket::bind(bind).await else {
        let _ = send_reply(&mut client, ReplyStatus::GeneralFailure, None).await;
        return;
    };
    let Ok(local) = client_socket.local_addr() else {
        let _ = send_reply(&mut client, ReplyStatus::GeneralFailure, None).await;
        return;
    };
    let relay_address = SocketAddr::new(tcp_local.ip(), local.port());
    if send_reply(&mut client, ReplyStatus::Succeeded, Some(relay_address))
        .await
        .is_err()
    {
        return;
    }

    let tcp_peer_ip = client.peer_addr().ok().map(|address| address.ip());
    let mut client_address = None;
    let mut upstream: Option<UdpOutbound> = None;
    let mut upstream_action: Option<Action> = None;
    let mut client_buffer = vec![0_u8; UDP_BUFFER];
    let mut upstream_buffer = vec![0_u8; UDP_BUFFER];
    let mut reply_buffer = vec![0_u8; UDP_REPLY_BUFFER];
    let mut control_buffer = [0_u8; 64];

    loop {
        let event = if let Some(idle) = context.limits.idle_timeout {
            match timeout(
                idle,
                udp_event(
                    &token,
                    &mut client,
                    &client_socket,
                    &mut upstream,
                    &mut client_buffer,
                    &mut upstream_buffer,
                    &mut control_buffer,
                ),
            )
            .await
            {
                Ok(event) => event,
                Err(_) => break,
            }
        } else {
            udp_event(
                &token,
                &mut client,
                &client_socket,
                &mut upstream,
                &mut client_buffer,
                &mut upstream_buffer,
                &mut control_buffer,
            )
            .await
        };

        match event {
            UdpEvent::Cancel => break,
            UdpEvent::Control(result) => match result {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            },
            UdpEvent::Client(result) => {
                let Ok((length, source)) = result else {
                    continue;
                };
                match client_address {
                    None => {
                        if let Some(expected) = tcp_peer_ip {
                            if source.ip() != expected {
                                continue;
                            }
                        }
                        client_address = Some(source);
                    }
                    Some(known) if known != source => continue,
                    Some(_) => {}
                }

                let Ok(request) = parse_udp(&client_buffer[..length]) else {
                    continue;
                };
                let destination = request.destination.clone();
                let metadata = Metadata {
                    network: Network::Udp,
                    source: Endpoint::from(source),
                    destination: destination.clone(),
                    domain: destination.domain(),
                    inbound: Some(&inbound),
                };
                let action = context.router.route(&metadata);
                if upstream_action != Some(action) {
                    if upstream.is_some() {
                        continue;
                    }
                    match context.udp_outbound(action, ipv4, &destination).await {
                        Ok(Some(connection)) => {
                            upstream = Some(connection);
                            upstream_action = Some(action);
                        }
                        _ => continue,
                    }
                }
                let Some(connection) = upstream.as_mut() else {
                    continue;
                };
                let _ = connection.send_to(&destination, request.payload).await;
            }
            UdpEvent::Upstream(result) => {
                let Ok((length, source)) = result else {
                    continue;
                };
                let Some(client_address) = client_address else {
                    continue;
                };
                let Ok(encoded) =
                    encode_udp(&source, &upstream_buffer[..length], &mut reply_buffer)
                else {
                    continue;
                };
                let _ = client_socket
                    .send_to(&reply_buffer[..encoded], client_address)
                    .await;
            }
        }
    }
}
