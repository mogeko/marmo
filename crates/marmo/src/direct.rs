//! Direct outbound: dial an IP literal or resolve a domain through the
//! configured DNS resolver or the system resolver.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use marmo_net::Endpoint;
use tokio::net::TcpStream;

use crate::dns::DnsRuntime;

/// A direct dialer carrying the optional instance DNS resolver.
#[derive(Clone, Default)]
pub(crate) struct Dialer {
    #[cfg(feature = "dns")]
    dns: Option<Arc<DnsRuntime>>,
}

impl Dialer {
    /// Builds a dialer over the instance resolver, if any.
    pub(crate) fn new(dns: Option<Arc<DnsRuntime>>) -> Self {
        #[cfg(feature = "dns")]
        {
            Self { dns }
        }
        #[cfg(not(feature = "dns"))]
        {
            let _ = dns;
            Self {}
        }
    }

    /// Connects to `endpoint` without a proxy protocol.
    pub(crate) async fn connect(&self, endpoint: &Endpoint) -> io::Result<TcpStream> {
        if let Some(address) = endpoint.to_socket_addr() {
            return TcpStream::connect(address).await;
        }

        let domain = endpoint
            .domain()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "endpoint has no host"))?;
        let addresses = self.lookup(domain).await?;

        let mut last_error = None;
        for address in addresses {
            match TcpStream::connect(SocketAddr::new(address, endpoint.port())).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::AddrNotAvailable, "no addresses resolved")
        }))
    }

    /// Resolves an endpoint to one address, preferring the resolver's order.
    pub(crate) async fn resolve(&self, endpoint: &Endpoint) -> io::Result<SocketAddr> {
        if let Some(address) = endpoint.to_socket_addr() {
            return Ok(address);
        }
        let domain = endpoint
            .domain()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "endpoint has no host"))?;
        self.lookup(domain)
            .await?
            .into_iter()
            .next()
            .map(|address| SocketAddr::new(address, endpoint.port()))
            .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no addresses resolved"))
    }

    /// Resolves a UDP target to an address of the requested family.
    pub(crate) async fn resolve_udp(
        &self, endpoint: &Endpoint, ipv4: bool,
    ) -> io::Result<SocketAddr> {
        if let Some(address) = endpoint.to_socket_addr() {
            if address.is_ipv4() == ipv4 {
                return Ok(address);
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP target family does not match the relay socket",
            ));
        }

        let domain = endpoint
            .domain()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "endpoint has no host"))?;
        for address in self.lookup(domain).await? {
            if address.is_ipv4() == ipv4 {
                return Ok(SocketAddr::new(address, endpoint.port()));
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no UDP address of the requested family",
        ))
    }

    async fn lookup(&self, domain: &str) -> io::Result<Vec<IpAddr>> {
        #[cfg(feature = "dns")]
        if let Some(dns) = self.dns.as_ref() {
            return dns
                .resolve(domain)
                .await
                .map(|addresses| addresses.to_vec())
                .map_err(DnsRuntime::io_resolve);
        }

        let addresses = tokio::net::lookup_host((domain, 0)).await?;
        Ok(addresses.map(|address| address.ip()).collect())
    }
}

/// The built-in direct dialer.
pub(crate) struct DirectOutbound {
    pub(crate) dialer: Dialer,
}

impl DirectOutbound {
    pub(crate) fn new(dialer: Dialer) -> Self {
        Self { dialer }
    }
}

impl crate::outbound::Outbound for DirectOutbound {
    fn connect<'a>(
        &'a self, endpoint: &'a Endpoint,
    ) -> marmo_transport::BoxFuture<'a, std::io::Result<crate::outbound::Connected>> {
        Box::pin(async move {
            let stream = self.dialer.connect(endpoint).await?;
            let bound = stream.local_addr().ok();
            Ok(crate::outbound::Connected::with_bound(
                Box::new(stream) as marmo_transport::BoxStream,
                bound,
            ))
        })
    }

    fn connect_datagram<'a>(
        &'a self, _target: &'a Endpoint, ipv4: bool,
    ) -> marmo_transport::BoxFuture<'a, std::io::Result<Option<crate::outbound::udp::UdpOutbound>>>
    {
        Box::pin(async move {
            let socket =
                crate::outbound::udp::UdpOutbound::direct(self.dialer.clone(), ipv4).await?;
            Ok(Some(socket))
        })
    }

    fn is_direct(&self) -> bool {
        true
    }
}
