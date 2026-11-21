//! Shadowsocks 2022 outbound: dials the server and wraps the TCP stream.

use std::io;
use std::sync::Arc;

use marmo_net::Endpoint;
use marmo_proto::shadowsocks::{Key, Method};
use tokio::net::TcpStream;

use crate::shadowsocks::SsStream;

/// Dials `server` and opens a Shadowsocks 2022 stream to `target`.
pub(crate) async fn connect(
    server: &Endpoint,
    method: Method,
    key: Arc<Key>,
    target: &Endpoint,
) -> io::Result<(SsStream<TcpStream>, Option<std::net::SocketAddr>)> {
    let inner = crate::direct::connect(server).await?;
    let bound = inner.local_addr().ok();
    let stream = SsStream::connect(inner, method, key, target).await?;
    Ok((stream, bound))
}

/// A Shadowsocks 2022 outbound node.
pub(crate) struct ShadowsocksOutbound {
    pub(crate) server: Endpoint,
    pub(crate) method: Method,
    pub(crate) key: Arc<Key>,
}

impl crate::outbound::Outbound for ShadowsocksOutbound {
    fn connect<'a>(
        &'a self,
        target: &'a Endpoint,
    ) -> marmo_transport::BoxFuture<'a, io::Result<crate::outbound::Connected>> {
        Box::pin(async move {
            let (stream, bound) =
                connect(&self.server, self.method, Arc::clone(&self.key), target).await?;
            Ok(crate::outbound::Connected::with_bound(
                Box::new(stream) as marmo_transport::BoxStream,
                bound,
            ))
        })
    }

    fn connect_datagram<'a>(
        &'a self,
        _target: &'a Endpoint,
        _ipv4: bool,
    ) -> marmo_transport::BoxFuture<'a, io::Result<Option<crate::outbound::udp::UdpOutbound>>> {
        Box::pin(async move {
            let client = crate::shadowsocks::SsUdpClient::connect(
                &self.server,
                self.method,
                Arc::clone(&self.key),
            )
            .await?;
            Ok(Some(crate::outbound::udp::UdpOutbound::Shadowsocks(client)))
        })
    }
}
