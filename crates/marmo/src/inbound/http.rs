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
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::deadline::Deadline;
use crate::instance::Context;
use crate::routing::{Action, Metadata};
use crate::sniff::{self, Policy};

/// Handles one accepted HTTP proxy connection.
pub(crate) async fn handle(
    client: TcpStream, context: Arc<Context>, inbound: Arc<str>, sniffing: Option<Policy>,
    deadline: Deadline,
) {
    let token = context.supervisor.token();
    let handshake = tokio::select! {
        _ = token.cancelled() => return,
        result = deadline.run(prepare(client, &context, &inbound, sniffing, &deadline)) => result,
    };
    let Ok(Ok(Some((client, remote)))) = handshake else {
        return;
    };

    context.relay_streams(client, remote, &token).await;
}

async fn prepare(
    mut client: TcpStream, context: &Context, inbound: &str, sniffing: Option<Policy>,
    deadline: &Deadline,
) -> io::Result<Option<(BoxStream, BoxStream)>> {
    let (buffer, head_len) = match read_head(&mut client).await {
        Ok(Some(head)) => head,
        Ok(None) => return Ok(None),
        Err(HeadError::Eof) => return Ok(None),
        Err(HeadError::TooLarge) => {
            let _ = respond(&mut client, "431 Request Header Fields Too Large").await;
            return Ok(None);
        }
        Err(HeadError::Io(error)) => return Err(error),
    };

    let request = match http::parse_request(&buffer[..head_len]) {
        Ok(request) => request,
        Err(HttpError::TooManyHeaders | HttpError::TooLarge) => {
            let _ = respond(&mut client, "431 Request Header Fields Too Large").await;
            return Ok(None);
        }
        Err(HttpError::UnsupportedVersion) => {
            let _ = respond(&mut client, "505 HTTP Version Not Supported").await;
            return Ok(None);
        }
        Err(_) => {
            let _ = respond(&mut client, "400 Bad Request").await;
            return Ok(None);
        }
    };

    let leftover = buffer[head_len..].to_vec();
    if request.method.eq_ignore_ascii_case("CONNECT") {
        return connect_tunnel(
            client,
            context,
            inbound,
            request.target,
            leftover,
            sniffing,
            deadline,
        )
        .await;
    }
    forward(client, context, inbound, &request, leftover).await
}

async fn connect_tunnel(
    mut client: TcpStream, context: &Context, inbound: &str, target_text: &str, leftover: Vec<u8>,
    sniffing: Option<Policy>, deadline: &Deadline,
) -> io::Result<Option<(BoxStream, BoxStream)>> {
    let Ok(destination) = Endpoint::parse(target_text) else {
        let _ = respond(&mut client, "400 Bad Request").await;
        return Ok(None);
    };
    let source: Endpoint = client.peer_addr()?.into();
    let mut domain = destination.domain().map(str::to_owned);
    let mut stream: BoxStream = Box::new(client);
    let mut leftover = leftover;
    let mut replied = false;

    if let (Some(policy), None) = (sniffing, domain.as_deref()) {
        if stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .is_err()
        {
            return Ok(None);
        }
        replied = true;
        let Ok(sniffed) = deadline
            .run(sniff::sniff_stream(stream, leftover, policy))
            .await
        else {
            return Ok(None);
        };
        domain = sniffed.domain;
        stream = sniffed.stream;
        leftover = Vec::new();
    }

    let action = route(context, inbound, source, &destination, domain.as_deref()).await;
    if matches!(action, Action::Reject(_)) {
        if !replied {
            let _ = respond(&mut stream, "403 Forbidden").await;
        }
        return Ok(None);
    }
    let mut remote = match context.connect(action, &destination).await {
        Ok(connected) => connected.stream,
        Err(_) => {
            if !replied {
                let _ = respond(&mut stream, "502 Bad Gateway").await;
            }
            return Ok(None);
        }
    };

    if !replied {
        if stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .is_err()
        {
            return Ok(None);
        }
        if !leftover.is_empty() && remote.write_all(&leftover).await.is_err() {
            return Ok(None);
        }
    }
    Ok(Some((stream, remote)))
}

async fn forward(
    mut client: TcpStream, context: &Context, inbound: &str, request: &RequestHead<'_>,
    leftover: Vec<u8>,
) -> io::Result<Option<(BoxStream, BoxStream)>> {
    let target = match parse_absolute(request.target) {
        Ok(target) => target,
        Err(HttpError::UnsupportedScheme) => {
            let _ = respond(&mut client, "501 Not Implemented").await;
            return Ok(None);
        }
        Err(_) => {
            let _ = respond(&mut client, "400 Bad Request").await;
            return Ok(None);
        }
    };
    let head = match build_forward_head(request.method, request.version, &target, request.headers())
    {
        Ok(head) => head,
        Err(HttpError::TooLarge) => {
            let _ = respond(&mut client, "431 Request Header Fields Too Large").await;
            return Ok(None);
        }
        Err(_) => {
            let _ = respond(&mut client, "400 Bad Request").await;
            return Ok(None);
        }
    };

    let source = client.peer_addr()?.into();
    let action = route(
        context,
        inbound,
        source,
        &target.endpoint,
        target.endpoint.domain(),
    )
    .await;
    if matches!(action, Action::Reject(_)) {
        let _ = respond(&mut client, "403 Forbidden").await;
        return Ok(None);
    }
    let mut remote = match context.connect(action, &target.endpoint).await {
        Ok(connected) => connected.stream,
        Err(_) => {
            let _ = respond(&mut client, "502 Bad Gateway").await;
            return Ok(None);
        }
    };

    remote.write_all(&head).await?;
    if !leftover.is_empty() {
        remote.write_all(&leftover).await?;
    }
    Ok(Some((Box::new(client) as BoxStream, remote)))
}

async fn route(
    context: &Context, inbound: &str, source: Endpoint, destination: &Endpoint,
    domain: Option<&str>,
) -> Action {
    let metadata = Metadata {
        network: Network::Tcp,
        source,
        destination: destination.clone(),
        domain,
        inbound: Some(inbound),
        process: None,
    };
    context.route(metadata).await
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

async fn respond<W: AsyncWrite + Unpin>(client: &mut W, status: &str) -> io::Result<()> {
    let response = format!("HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    client.write_all(response.as_bytes()).await
}
