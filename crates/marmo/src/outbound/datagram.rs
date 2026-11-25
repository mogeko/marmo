//! The datagram boundary shared by every UDP outbound (ADR-0033).
//!
//! An established association owns its socket, target set, counters, and
//! queues. Callers only send and receive; a new datagram transport implements
//! this trait instead of extending a central enum.

use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;

use marmo_net::Endpoint;
use marmo_transport::BoxFuture;
use thiserror::Error;
use tokio::net::UdpSocket;

use crate::direct::Dialer;
use crate::outbound::mux::MuxDatagram;
use crate::outbound::trojan::TrojanUdpClient;
use crate::outbound::vless::{VlessUdpClient, VlessXudpClient};
use crate::outbound::vmess::VmessUdpClient;
use crate::shadowsocks::SsUdpClient;

/// Maximum distinct destinations whose replies one direct socket accepts.
const MAX_DIRECT_TARGETS: usize = 128;
/// Datagrams examined before a direct receive attempt reports `NoReply`.
const RECEIVE_ATTEMPTS: usize = 32;
/// Largest payload carried by a protocol datagram implementation.
const MAX_DATAGRAM_SIZE: usize = 65_535;
/// Largest payload an IPv4/IPv6 UDP socket can carry.
const MAX_UDP_PAYLOAD: usize = 65_507;

const _: () = assert!(MAX_DATAGRAM_SIZE <= 65_535);
const _: () = assert!(MAX_UDP_PAYLOAD <= MAX_DATAGRAM_SIZE);

/// One datagram association.
pub(crate) trait Datagram: Send {
    /// Sends one payload to `target`.
    fn send_to<'a>(
        &'a mut self, target: &'a Endpoint, payload: &'a [u8],
    ) -> BoxFuture<'a, Result<(), DatagramError>>;

    /// Receives one payload and its source.
    fn recv_from<'a>(
        &'a mut self, buffer: &'a mut [u8],
    ) -> BoxFuture<'a, Result<(usize, Endpoint), DatagramError>>;

    /// Largest payload this implementation accepts; never exceeds `65_535`.
    fn max_datagram_size(&self) -> usize;
}

/// A boxed datagram association, mirroring the stream `BoxStream` boundary.
pub(crate) type BoxDatagram = Box<dyn Datagram>;

/// A per-datagram failure.
#[derive(Debug, Error)]
pub(crate) enum DatagramError {
    /// The association failed or the underlying socket reported an error.
    #[error(transparent)]
    Io(#[from] io::Error),

    /// Every received packet came from a source this association has not
    /// contacted. This is not an association-fatal condition.
    #[error("no valid datagram reply")]
    NoReply,
}

/// A direct datagram socket with a bounded set of allowed reply sources.
pub(crate) struct DirectDatagram {
    socket: UdpSocket,
    ipv4: bool,
    dialer: Dialer,
    targets: HashSet<SocketAddr>,
}

impl DirectDatagram {
    /// Binds a direct socket of the requested family.
    pub(crate) async fn new(dialer: Dialer, ipv4: bool) -> io::Result<Self> {
        let bind = if ipv4 {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0_u16; 8], 0))
        };
        Ok(Self {
            socket: UdpSocket::bind(bind).await?,
            ipv4,
            dialer,
            targets: HashSet::new(),
        })
    }
}

impl Datagram for DirectDatagram {
    fn send_to<'a>(
        &'a mut self, target: &'a Endpoint, payload: &'a [u8],
    ) -> BoxFuture<'a, Result<(), DatagramError>> {
        Box::pin(async move {
            let address = self
                .dialer
                .resolve_udp(target, self.ipv4)
                .await
                .map_err(DatagramError::Io)?;
            if !self.targets.contains(&address) {
                if self.targets.len() >= MAX_DIRECT_TARGETS {
                    return Err(DatagramError::Io(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "direct UDP target limit reached",
                    )));
                }
                self.targets.insert(address);
            }
            self.socket
                .send_to(payload, address)
                .await
                .map_err(DatagramError::Io)?;
            Ok(())
        })
    }

    fn recv_from<'a>(
        &'a mut self, buffer: &'a mut [u8],
    ) -> BoxFuture<'a, Result<(usize, Endpoint), DatagramError>> {
        Box::pin(async move {
            for _ in 0..RECEIVE_ATTEMPTS {
                let (length, source) = self
                    .socket
                    .recv_from(buffer)
                    .await
                    .map_err(DatagramError::Io)?;
                if self.targets.contains(&source) {
                    return Ok((length, Endpoint::from(source)));
                }
                // Ignore replies from a source this association never sent to.
                // Without this check a wildcard socket lets an off-path packet
                // masquerade as an upstream reply.
            }
            Err(DatagramError::NoReply)
        })
    }

    fn max_datagram_size(&self) -> usize {
        MAX_UDP_PAYLOAD
    }
}

/// Implements the datagram boundary for a protocol client that already owns
/// `send_to`/`recv_from`.
macro_rules! datagram_adapter {
    ($ty:ty) => {
        impl Datagram for $ty {
            fn send_to<'a>(
                &'a mut self, target: &'a Endpoint, payload: &'a [u8],
            ) -> BoxFuture<'a, Result<(), DatagramError>> {
                Box::pin(async move {
                    <$ty>::send_to(self, target, payload)
                        .await
                        .map_err(DatagramError::Io)
                })
            }

            fn recv_from<'a>(
                &'a mut self, buffer: &'a mut [u8],
            ) -> BoxFuture<'a, Result<(usize, Endpoint), DatagramError>> {
                Box::pin(async move {
                    <$ty>::recv_from(self, buffer)
                        .await
                        .map_err(DatagramError::Io)
                })
            }

            fn max_datagram_size(&self) -> usize {
                MAX_DATAGRAM_SIZE
            }
        }
    };
}

datagram_adapter!(SsUdpClient);
datagram_adapter!(TrojanUdpClient);
datagram_adapter!(VlessUdpClient);
datagram_adapter!(VlessXudpClient);
datagram_adapter!(VmessUdpClient);
datagram_adapter!(MuxDatagram);

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use tokio::time::timeout;

    #[tokio::test]
    async fn direct_datagram_ignores_unknown_sources() {
        let mut direct = DirectDatagram::new(Dialer::default(), true)
            .await
            .expect("direct");
        let local = direct.socket.local_addr().expect("local");

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
            "direct datagram accepted a packet from an unknown source"
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

    #[tokio::test]
    async fn unknown_sources_report_no_reply() {
        let mut direct = DirectDatagram::new(Dialer::default(), true)
            .await
            .expect("direct");
        let local = direct.socket.local_addr().expect("local");
        let injector = UdpSocket::bind(("127.0.0.1", 0)).await.expect("injector");
        let loopback = SocketAddr::from(([127, 0, 0, 1], local.port()));
        for _ in 0..RECEIVE_ATTEMPTS {
            injector
                .send_to(b"injected", loopback)
                .await
                .expect("inject");
        }
        let mut buffer = [0_u8; 16];
        let result = timeout(Duration::from_secs(1), direct.recv_from(&mut buffer))
            .await
            .expect("bounded receive");
        assert!(matches!(result, Err(DatagramError::NoReply)));
    }
}
