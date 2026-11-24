//! Shadowsocks 2022 inbound: decrypts the request and relays to the target.

use std::sync::{Arc, Mutex};

use crate::deadline::Deadline;
use crate::instance::Context;
use crate::routing::Metadata;
use crate::shadowsocks::{SaltReplay, SsStream, unix_now};
use crate::sniff::{self, Policy};
use marmo_net::{Endpoint, Network};
use marmo_proto::shadowsocks::{Key, Method};
use marmo_transport::BoxStream;
use tokio::net::TcpStream;

/// Handles one accepted Shadowsocks 2022 connection.
pub(crate) async fn handle(
    client: TcpStream, context: Arc<Context>, inbound: Arc<str>, method: Method, key: Arc<Key>,
    replay: Arc<Mutex<SaltReplay>>, sniffing: Option<Policy>, deadline: Deadline,
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

    let salt = *stream.request_salt();
    let fresh = replay
        .lock()
        .map(|mut replay| replay.check_and_insert(salt, unix_now()))
        .unwrap_or(false);
    if !fresh {
        return;
    }

    let mut domain = target.domain().map(str::to_owned);
    let mut stream: BoxStream = Box::new(stream);
    if let (Some(policy), None) = (sniffing, domain.as_deref()) {
        let sniffed = tokio::select! {
            _ = token.cancelled() => return,
            result = deadline.run(sniff::sniff_stream(stream, Vec::new(), policy)) => result,
        };
        let Ok(sniffed) = sniffed else {
            return;
        };
        domain = sniffed.domain;
        stream = sniffed.stream;
    }

    let metadata = Metadata {
        network: Network::Tcp,
        source,
        destination: target.clone(),
        domain: domain.as_deref(),
        inbound: Some(&inbound),
        process: None,
    };
    let action = context.route(metadata).await;
    let connected = tokio::select! {
        _ = token.cancelled() => return,
        result = deadline.run(context.connect(action, &target)) => result,
    };
    let Ok(Ok(connected)) = connected else {
        return;
    };

    context
        .relay_streams(stream, connected.stream, &token)
        .await;
}
