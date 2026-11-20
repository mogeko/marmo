//! Shadowsocks 2022 inbound: decrypts the request and relays to the target.

use std::sync::Arc;

use marmo_net::{Endpoint, Network};
use marmo_proto::shadowsocks::{Key, Method};
use marmo_transport::{BoxStream, RelayOptions, relay};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::instance::Context;
use crate::routing::Metadata;
use crate::shadowsocks::SsStream;

/// Handles one accepted Shadowsocks 2022 connection.
pub(crate) async fn handle(
    client: TcpStream,
    context: Arc<Context>,
    inbound: Arc<str>,
    method: Method,
    key: Arc<Key>,
) {
    let token = context.supervisor.token();
    let source = match client.peer_addr() {
        Ok(address) => Endpoint::from(address),
        Err(_) => return,
    };
    let accepted = tokio::select! {
        _ = token.cancelled() => return,
        result = timeout(context.limits.handshake_timeout, SsStream::accept(client, method, key)) => result,
    };
    let Ok(Ok((stream, target))) = accepted else {
        return;
    };

    let domain = target.domain().map(str::to_owned);
    let metadata = Metadata {
        network: Network::Tcp,
        source,
        destination: target.clone(),
        domain: domain.as_deref(),
        inbound: Some(&inbound),
    };
    let action = context.router.route(&metadata);
    let connected = tokio::select! {
        _ = token.cancelled() => return,
        result = timeout(context.limits.handshake_timeout, context.connect(action, &target)) => result,
    };
    let Ok(Ok((remote, _bound))) = connected else {
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
            Box::new(stream) as BoxStream,
            remote,
            options,
        ) => {}
    }
}
