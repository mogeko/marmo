//! HTTP/1.1 inbound: CONNECT tunnels and forward proxying.
//!
//! One request per connection. Forward requests are rewritten from
//! absolute-form to origin-form, hop-by-hop headers are stripped, and the
//! upstream is forced to `Connection: close`. The request body (if any) is
//! relayed after the rewritten head.

use std::io;
use std::sync::Arc;

use marmo_net::{Endpoint, Network};
use marmo_proto::http::{
    self, HEAD_MAX, HttpError, RequestHead, build_forward_head, find_head_end, parse_absolute,
};
use marmo_transport::BoxStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::deadline::Deadline;
use crate::instance::Context;
use crate::routing::{Action, Metadata};

/// Handles one accepted HTTP proxy connection.
pub(crate) async fn handle(
    mut client: TcpStream,
    context: Arc<Context>,
    inbound: Arc<str>,
    deadline: Deadline,
) {
    let token = context.supervisor.token();
    let handshake = tokio::select! {
        _ = token.cancelled() => return,
        result = deadline.run(prepare(&mut client, &context, &inbound)) => result,
    };
    let Ok(Ok(Some(remote))) = handshake else {
        return;
    };

    context
        .relay_streams(
            Box::new(client) as BoxStream,
            Box::new(remote) as BoxStream,
            &token,
        )
        .await;
}

async fn prepare(
    client: &mut TcpStream,
    context: &Context,
    inbound: &str,
) -> io::Result<Option<BoxStream>> {
    let (buffer, head_len) = match read_head(client).await {
        Ok(Some(head)) => head,
        Ok(None) => return Ok(None),
        Err(HeadError::Eof) => return Ok(None),
        Err(HeadError::TooLarge) => {
            let _ = respond(client, "431 Request Header Fields Too Large").await;
            return Ok(None);
        }
        Err(HeadError::Io(error)) => return Err(error),
    };

    let request = match http::parse_request(&buffer[..head_len]) {
        Ok(request) => request,
        Err(HttpError::TooManyHeaders | HttpError::TooLarge) => {
            let _ = respond(client, "431 Request Header Fields Too Large").await;
            return Ok(None);
        }
        Err(HttpError::UnsupportedVersion) => {
            let _ = respond(client, "505 HTTP Version Not Supported").await;
            return Ok(None);
        }
        Err(_) => {
            let _ = respond(client, "400 Bad Request").await;
            return Ok(None);
        }
    };

    let leftover = &buffer[head_len..];
    if request.method.eq_ignore_ascii_case("CONNECT") {
        return connect_tunnel(client, context, inbound, request.target, leftover).await;
    }
    forward(client, context, inbound, &request, leftover).await
}

async fn connect_tunnel(
    client: &mut TcpStream,
    context: &Context,
    inbound: &str,
    target_text: &str,
    leftover: &[u8],
) -> io::Result<Option<BoxStream>> {
    let Ok(destination) = Endpoint::parse(target_text) else {
        let _ = respond(client, "400 Bad Request").await;
        return Ok(None);
    };
    let Some(action) = route(client, context, inbound, &destination).await? else {
        return Ok(None);
    };
    let mut remote = match context.connect(action, &destination).await {
        Ok(connected) => connected.stream,
        Err(_) => {
            let _ = respond(client, "502 Bad Gateway").await;
            return Ok(None);
        }
    };

    if client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .is_err()
    {
        return Ok(None);
    }
    if !leftover.is_empty() {
        remote.write_all(leftover).await?;
    }
    Ok(Some(remote))
}

async fn forward(
    client: &mut TcpStream,
    context: &Context,
    inbound: &str,
    request: &RequestHead<'_>,
    leftover: &[u8],
) -> io::Result<Option<BoxStream>> {
    let target = match parse_absolute(request.target) {
        Ok(target) => target,
        Err(HttpError::UnsupportedScheme) => {
            let _ = respond(client, "501 Not Implemented").await;
            return Ok(None);
        }
        Err(_) => {
            let _ = respond(client, "400 Bad Request").await;
            return Ok(None);
        }
    };
    let head = match build_forward_head(request.method, request.version, &target, request.headers())
    {
        Ok(head) => head,
        Err(HttpError::TooLarge) => {
            let _ = respond(client, "431 Request Header Fields Too Large").await;
            return Ok(None);
        }
        Err(_) => {
            let _ = respond(client, "400 Bad Request").await;
            return Ok(None);
        }
    };

    let Some(action) = route(client, context, inbound, &target.endpoint).await? else {
        return Ok(None);
    };
    let mut remote = match context.connect(action, &target.endpoint).await {
        Ok(connected) => connected.stream,
        Err(_) => {
            let _ = respond(client, "502 Bad Gateway").await;
            return Ok(None);
        }
    };

    remote.write_all(&head).await?;
    if !leftover.is_empty() {
        remote.write_all(leftover).await?;
    }
    Ok(Some(remote))
}

async fn route(
    client: &mut TcpStream,
    context: &Context,
    inbound: &str,
    destination: &Endpoint,
) -> io::Result<Option<Action>> {
    let domain = destination.domain().map(str::to_owned);
    let source = client.peer_addr()?.into();
    let metadata = Metadata {
        network: Network::Tcp,
        source,
        destination: destination.clone(),
        domain: domain.as_deref(),
        inbound: Some(inbound),
    };
    let action = context.router.route(&metadata);
    match action {
        Action::Reject(_) => {
            let _ = respond(client, "403 Forbidden").await;
            Ok(None)
        }
        action => Ok(Some(action)),
    }
}

enum HeadError {
    Eof,
    TooLarge,
    Io(io::Error),
}

async fn read_head(client: &mut TcpStream) -> Result<Option<(Vec<u8>, usize)>, HeadError> {
    let mut buffer = Vec::with_capacity(1024);
    loop {
        let mut chunk = [0_u8; 1024];
        let read = client.read(&mut chunk).await.map_err(HeadError::Io)?;
        if read == 0 {
            return Err(HeadError::Eof);
        }
        buffer.extend_from_slice(&chunk[..read]);

        if let Some(end) = find_head_end(&buffer) {
            let head_len = end + 4;
            if head_len > HEAD_MAX {
                return Err(HeadError::TooLarge);
            }
            return Ok(Some((buffer, head_len)));
        }
        if buffer.len() >= HEAD_MAX {
            return Err(HeadError::TooLarge);
        }
    }
}

async fn respond(client: &mut TcpStream, status: &str) -> io::Result<()> {
    let response = format!("HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    client.write_all(response.as_bytes()).await
}
