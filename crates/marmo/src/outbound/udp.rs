//! Datagram outbounds: direct sockets and Shadowsocks 2022 framing.

use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;

use marmo_net::Endpoint;
use tokio::net::UdpSocket;

use crate::direct::Dialer;
use crate::outbound::mux::MuxDatagram;
use crate::outbound::trojan::TrojanUdpClient;
use crate::outbound::vless::{VlessUdpClient, VlessXudpClient};
use crate::outbound::vmess::VmessUdpClient;
use crate::shadowsocks::SsUdpClient;

/// Maximum distinct destinations whose replies one direct socket accepts.
const MAX_DIRECT_TARGETS: usize = 128;
/// Datagrams examined before a direct receive attempt gives up on unrelated
/// packets.
const RECEIVE_ATTEMPTS: usize = 32;

/// An established datagram path to one outbound.
pub(crate) enum UdpOutbound {
    /// A socket that sends to resolved targets directly.
    Direct {
        socket: UdpSocket,
        ipv4: bool,
        dialer: Dialer,
        targets: HashSet<SocketAddr>,
    },
    /// A Shadowsocks 2022 association with one server.
    Shadowsocks(SsUdpClient),
    /// A Trojan UDP association over one TLS stream.
    Trojan(TrojanUdpClient),
    /// A simple VLESS UDP-over-TCP association.
    Vless(VlessUdpClient),
    /// A VLESS XUDP association.
    VlessXudp(VlessXudpClient),
    /// A direct VMess UDP association.
    Vmess(Box<VmessUdpClient>),
    /// A client-side mux UDP session.
    Mux(Box<MuxDatagram>),
}

impl UdpOutbound {
    /// Binds a direct socket of the requested family.
    pub(crate) async fn direct(dialer: Dialer, ipv4: bool) -> io::Result<Self> {
        let bind = if ipv4 {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0_u16; 8], 0))
        };
        Ok(Self::Direct {
            socket: UdpSocket::bind(bind).await?,
            ipv4,
            dialer,
            targets: HashSet::new(),
        })
    }

    /// Sends one datagram to `target`.
    pub(crate) async fn send_to(&mut self, target: &Endpoint, payload: &[u8]) -> io::Result<()> {
        match self {
            Self::Direct {
                socket,
                ipv4,
                dialer,
                targets,
            } => {
                let address = dialer.resolve_udp(target, *ipv4).await?;
                if !targets.contains(&address) {
                    if targets.len() >= MAX_DIRECT_TARGETS {
                        return Err(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "direct UDP target limit reached",
                        ));
                    }
                    targets.insert(address);
                }
                socket.send_to(payload, address).await?;
                Ok(())
            }
            Self::Shadowsocks(client) => client.send_to(target, payload).await,
            Self::Trojan(client) => client.send_to(target, payload).await,
            Self::Vless(client) => client.send_to(target, payload).await,
            Self::VlessXudp(client) => client.send_to(target, payload).await,
            Self::Vmess(client) => client.send_to(target, payload).await,
            Self::Mux(client) => client.send_to(target, payload).await,
        }
    }

    /// Receives one datagram, returning its length and source.
    pub(crate) async fn recv_from(&mut self, buffer: &mut [u8]) -> io::Result<(usize, Endpoint)> {
        match self {
            Self::Direct {
                socket, targets, ..
            } => {
                for _ in 0..RECEIVE_ATTEMPTS {
                    let (length, source) = socket.recv_from(buffer).await?;
                    if targets.contains(&source) {
                        return Ok((length, Endpoint::from(source)));
                    }
                    // Ignore replies from a source this association never
                    // sent to. Without this check a wildcard socket lets an
                    // off-path packet masquerade as an upstream reply.
                }
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "no valid direct UDP reply",
                ))
            }
            Self::Shadowsocks(client) => client.recv_from(buffer).await,
            Self::Trojan(client) => client.recv_from(buffer).await,
            Self::Vless(client) => client.recv_from(buffer).await,
            Self::VlessXudp(client) => client.recv_from(buffer).await,
            Self::Vmess(client) => client.recv_from(buffer).await,
            Self::Mux(client) => client.recv_from(buffer).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use tokio::time::timeout;

    #[tokio::test]
    async fn direct_udp_ignores_unknown_sources() {
        let mut direct = UdpOutbound::direct(Dialer::default(), true)
            .await
            .expect("direct");
        let local = match &direct {
            UdpOutbound::Direct { socket, .. } => socket.local_addr().expect("local"),
            _ => panic!("expected direct"),
        };

        let injector = UdpSocket::bind(("127.0.0.1", 0)).await.expect("injector");
        let loopback = SocketAddr::from(([127, 0, 0, 1], local.port()));
        injector
            .send_to(b"injected", loopback)
            .await
            .expect("inject");
        let mut buffer = [0_u8; 16];
        assert!(
            timeout(Duration::from_millis(200), direct.recv_from(&mut buffer))
                .await
                .is_err(),
            "direct UDP accepted a packet from an unknown source"
        );

        let target = UdpSocket::bind(("127.0.0.1", 0)).await.expect("target");
        let target_addr = target.local_addr().expect("target addr");
        let target_endpoint = Endpoint::from(target_addr);
        direct
            .send_to(&target_endpoint, b"ping")
            .await
            .expect("send");
        let mut probe = [0_u8; 16];
        let (length, source) = target.recv_from(&mut probe).await.expect("target recv");
        assert_eq!(&probe[..length], b"ping");
        target.send_to(b"pong", source).await.expect("target reply");

        let (length, source) = timeout(Duration::from_secs(1), direct.recv_from(&mut buffer))
            .await
            .expect("reply timeout")
            .expect("reply");
        assert_eq!(&buffer[..length], b"pong");
        assert_eq!(source, target_endpoint);
    }
}
