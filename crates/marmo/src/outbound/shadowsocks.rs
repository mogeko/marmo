//! Shadowsocks 2022 outbound: dials the server and wraps the TCP stream.

use std::io;
use std::net::SocketAddr;
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
) -> io::Result<(SsStream<TcpStream>, Option<SocketAddr>)> {
    let inner = crate::direct::connect(server).await?;
    let bound = inner.local_addr().ok();
    let stream = SsStream::connect(inner, method, key, target).await?;
    Ok((stream, bound))
}
