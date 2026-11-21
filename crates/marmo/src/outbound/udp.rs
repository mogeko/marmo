//! Datagram outbounds: direct sockets and Shadowsocks 2022 framing.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;

use marmo_net::Endpoint;
use tokio::net::UdpSocket;

use crate::direct;
use crate::outbound::trojan::TrojanUdpClient;
use crate::outbound::vless::{VlessUdpClient, VlessXudpClient};
use crate::outbound::vmess::VmessUdpClient;
use crate::shadowsocks::SsUdpClient;

/// Bound on cached direct-UDP resolutions per association.
const DIRECT_CACHE: usize = 64;

/// An established datagram path to one outbound.
pub(crate) enum UdpOutbound {
    /// A socket that sends to resolved targets directly.
    Direct {
        socket: UdpSocket,
        ipv4: bool,
        cache: HashMap<Endpoint, SocketAddr>,
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
}

impl UdpOutbound {
    /// Binds a direct socket of the requested family.
    pub(crate) async fn direct(ipv4: bool) -> io::Result<Self> {
        let bind = if ipv4 {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0_u16; 8], 0))
        };
        Ok(Self::Direct {
            socket: UdpSocket::bind(bind).await?,
            ipv4,
            cache: HashMap::new(),
        })
    }

    /// Sends one datagram to `target`.
    pub(crate) async fn send_to(&mut self, target: &Endpoint, payload: &[u8]) -> io::Result<()> {
        match self {
            Self::Direct {
                socket,
                ipv4,
                cache,
            } => {
                let address = match cache.get(target) {
                    Some(address) => *address,
                    None => {
                        let address = direct::resolve_udp(target, *ipv4).await?;
                        if cache.len() >= DIRECT_CACHE {
                            cache.clear();
                        }
                        cache.insert(target.clone(), address);
                        address
                    }
                };
                socket.send_to(payload, address).await?;
                Ok(())
            }
            Self::Shadowsocks(client) => client.send_to(target, payload).await,
            Self::Trojan(client) => client.send_to(target, payload).await,
            Self::Vless(client) => client.send_to(target, payload).await,
            Self::VlessXudp(client) => client.send_to(target, payload).await,
            Self::Vmess(client) => client.send_to(target, payload).await,
        }
    }

    /// Receives one datagram, returning its length and source.
    pub(crate) async fn recv_from(&mut self, buffer: &mut [u8]) -> io::Result<(usize, Endpoint)> {
        match self {
            Self::Direct { socket, .. } => {
                let (length, source) = socket.recv_from(buffer).await?;
                Ok((length, Endpoint::from(source)))
            }
            Self::Shadowsocks(client) => client.recv_from(buffer).await,
            Self::Trojan(client) => client.recv_from(buffer).await,
            Self::Vless(client) => client.recv_from(buffer).await,
            Self::VlessXudp(client) => client.recv_from(buffer).await,
            Self::Vmess(client) => client.recv_from(buffer).await,
        }
    }
}
