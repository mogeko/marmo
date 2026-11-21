//! Outbound adapters and the config-chosen outbound boundary.

use std::io;
use std::net::SocketAddr;

use marmo_net::Endpoint;
use marmo_transport::{BoxFuture, BoxStream};
use tokio::runtime::Handle;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::outbound::udp::UdpOutbound;

pub(crate) mod http_connect;
pub(crate) mod selector;
pub(crate) mod shadowsocks;
pub(crate) mod trojan;
pub(crate) mod udp;
pub(crate) mod vless;

/// A TCP connection plus the local address chosen for it, when known.
pub(crate) struct Connected {
    pub(crate) stream: BoxStream,
    pub(crate) bound: Option<SocketAddr>,
}

impl Connected {
    pub(crate) fn with_bound(stream: BoxStream, bound: Option<SocketAddr>) -> Self {
        Self { stream, bound }
    }
}

/// One outbound chosen from config at runtime.
///
/// Concrete protocol structs implement this boundary; `Context` dispatches
/// through `Arc<dyn Outbound>` instead of matching a central enum
/// (ADR-0017, ADR-0004).
pub(crate) trait Outbound: Send + Sync {
    /// Opens a TCP stream to `target` through this outbound.
    fn connect<'a>(&'a self, target: &'a Endpoint) -> BoxFuture<'a, io::Result<Connected>>;

    /// Opens a datagram path, or `None` when the outbound has no UDP.
    fn connect_datagram<'a>(
        &'a self,
        target: &'a Endpoint,
        ipv4: bool,
    ) -> BoxFuture<'a, io::Result<Option<UdpOutbound>>>;

    /// Whether this outbound is the direct dialer.
    fn is_direct(&self) -> bool {
        false
    }

    /// Starts an optional health-probe task owned by the instance.
    fn start_health(
        &self,
        _runtime: &Handle,
        _token: &CancellationToken,
    ) -> Option<JoinHandle<()>> {
        None
    }
}
