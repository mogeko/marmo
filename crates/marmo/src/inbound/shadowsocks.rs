//! Shadowsocks 2022 inbound: decrypts the request and relays to the target.

use std::sync::Arc;

use crate::deadline::Deadline;
use crate::instance::Context;
use crate::routing::Metadata;
use crate::shadowsocks::SsStream;
use marmo_net::{Endpoint, Network};
use marmo_proto::shadowsocks::{Key, Method};
use marmo_transport::BoxStream;
use tokio::net::TcpStream;

/// Handles one accepted Shadowsocks 2022 connection.
pub(crate) async fn handle(
    client: TcpStream,
    context: Arc<Context>,
    inbound: Arc<str>,
    method: Method,
    key: Arc<Key>,
    deadline: Deadline,
) {
    let token = context.supervisor.token();
    let source = match client.peer_addr() {
        Ok(address) => Endpoint::from(address),
        Err(_) => return,
    };
    let accepted = tokio::select! {
        _ = token.cancelled() => return,
        result = deadline.run(SsStream::accept(client, method, key)) => result,
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
        result = deadline.run(context.connect(action, &target)) => result,
    };
    let Ok(Ok(connected)) = connected else {
        return;
    };

    context
        .relay_streams(Box::new(stream) as BoxStream, connected.stream, &token)
        .await;
}
