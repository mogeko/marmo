//! HTTP/1.1 inbound: CONNECT tunnels and forward proxying.
//!
//! One request per connection. Forward requests are rewritten from
//! absolute-form to origin-form, hop-by-hop headers are stripped, and the
//! upstream is forced to `Connection: close`. The request body (if any) is
//! relayed after the rewritten head.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;

use httparse::Status;
use marmo_net::{Endpoint, Network};
use marmo_transport::{BoxStream, RelayOptions, relay};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::instance::Context;
use crate::routing::{Action, Metadata};

const HEAD_MAX: usize = 8192;
const FORWARD_HEAD_MAX: usize = HEAD_MAX + 1024;
const MAX_HEADERS: usize = 64;

/// Handles one accepted HTTP proxy connection.
pub(crate) async fn handle(mut client: TcpStream, context: Arc<Context>, inbound: Arc<str>) {
    let token = context.supervisor.token();
    let handshake = tokio::select! {
        _ = token.cancelled() => return,
        result = timeout(
            context.limits.handshake_timeout,
            prepare(&mut client, &context, &inbound),
        ) => result,
    };
    let Ok(Ok(Some(remote))) = handshake else {
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
            Box::new(client) as BoxStream,
            Box::new(remote) as BoxStream,
            options,
        ) => {}
    }
}

async fn prepare(
    client: &mut TcpStream,
    context: &Context,
    inbound: &str,
) -> io::Result<Option<TcpStream>> {
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

    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(&buffer[..head_len]) {
        Ok(Status::Complete(_)) => {}
        Ok(Status::Partial) => {
            let _ = respond(client, "400 Bad Request").await;
            return Ok(None);
        }
        Err(httparse::Error::TooManyHeaders) => {
            let _ = respond(client, "431 Request Header Fields Too Large").await;
            return Ok(None);
        }
        Err(_) => {
            let _ = respond(client, "400 Bad Request").await;
            return Ok(None);
        }
    }

    let Some(method) = request.method else {
        let _ = respond(client, "400 Bad Request").await;
        return Ok(None);
    };
    let Some(target_text) = request.path else {
        let _ = respond(client, "400 Bad Request").await;
        return Ok(None);
    };
    let Some(version) = request.version else {
        let _ = respond(client, "400 Bad Request").await;
        return Ok(None);
    };
    if version > 1 {
        let _ = respond(client, "505 HTTP Version Not Supported").await;
        return Ok(None);
    }
    if !is_token(method) {
        let _ = respond(client, "400 Bad Request").await;
        return Ok(None);
    }

    let leftover = &buffer[head_len..];
    if method.eq_ignore_ascii_case("CONNECT") {
        return connect_tunnel(client, context, inbound, target_text, leftover).await;
    }
    forward(
        client,
        context,
        inbound,
        method,
        version,
        target_text,
        request.headers,
        leftover,
    )
    .await
}

async fn connect_tunnel(
    client: &mut TcpStream,
    context: &Context,
    inbound: &str,
    target_text: &str,
    leftover: &[u8],
) -> io::Result<Option<TcpStream>> {
    let Ok(destination) = Endpoint::parse(target_text) else {
        let _ = respond(client, "400 Bad Request").await;
        return Ok(None);
    };
    let Some(action) = route(client, context, inbound, &destination).await? else {
        return Ok(None);
    };
    let mut remote = match context.connect(action, &destination).await {
        Ok(remote) => remote,
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

#[allow(clippy::too_many_arguments)]
async fn forward(
    client: &mut TcpStream,
    context: &Context,
    inbound: &str,
    method: &str,
    version: u8,
    target_text: &str,
    headers: &[httparse::Header<'_>],
    leftover: &[u8],
) -> io::Result<Option<TcpStream>> {
    let target = match parse_absolute(target_text) {
        Ok(target) => target,
        Err(AbsoluteError::UnsupportedScheme) => {
            let _ = respond(client, "501 Not Implemented").await;
            return Ok(None);
        }
        Err(AbsoluteError::BadRequest) => {
            let _ = respond(client, "400 Bad Request").await;
            return Ok(None);
        }
    };
    let head = match build_forward_head(method, version, &target, headers) {
        Ok(head) => head,
        Err(ForwardError::TooLarge) => {
            let _ = respond(client, "431 Request Header Fields Too Large").await;
            return Ok(None);
        }
        Err(ForwardError::BadRequest) => {
            let _ = respond(client, "400 Bad Request").await;
            return Ok(None);
        }
    };

    let Some(action) = route(client, context, inbound, &target.endpoint).await? else {
        return Ok(None);
    };
    let mut remote = match context.connect(action, &target.endpoint).await {
        Ok(remote) => remote,
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

fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn build_forward_head(
    method: &str,
    version: u8,
    target: &AbsoluteTarget<'_>,
    headers: &[httparse::Header<'_>],
) -> Result<Vec<u8>, ForwardError> {
    let mut head = Vec::with_capacity(FORWARD_HEAD_MAX);
    head.extend_from_slice(method.as_bytes());
    head.push(b' ');
    if target.needs_slash {
        head.push(b'/');
    }
    head.extend_from_slice(target.path.as_bytes());
    head.extend_from_slice(b" HTTP/1.");
    head.push(b'0' + version);
    head.extend_from_slice(b"\r\n");

    let mut has_content_length = false;
    let mut has_transfer_encoding = false;
    for header in headers {
        if !is_token(header.name) || !is_valid_header_value(header.value) {
            return Err(ForwardError::BadRequest);
        }
        let name = header.name;
        if skip_hop_by_hop(name) {
            continue;
        }
        if name.eq_ignore_ascii_case("content-length") {
            if has_content_length {
                return Err(ForwardError::BadRequest);
            }
            has_content_length = true;
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            has_transfer_encoding = true;
        }
        if has_content_length && has_transfer_encoding {
            return Err(ForwardError::BadRequest);
        }

        head.extend_from_slice(name.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(header.value);
        head.extend_from_slice(b"\r\n");
        if head.len() > FORWARD_HEAD_MAX {
            return Err(ForwardError::TooLarge);
        }
    }

    head.extend_from_slice(b"Host: ");
    head.extend_from_slice(target.authority.as_bytes());
    head.extend_from_slice(b"\r\nConnection: close\r\n\r\n");
    if head.len() > FORWARD_HEAD_MAX {
        return Err(ForwardError::TooLarge);
    }
    Ok(head)
}

fn skip_hop_by_hop(name: &str) -> bool {
    name.eq_ignore_ascii_case("host")
        || name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailer")
        || name.eq_ignore_ascii_case("upgrade")
        || name.eq_ignore_ascii_case("proxy-authorization")
}

struct AbsoluteTarget<'a> {
    endpoint: Endpoint,
    authority: &'a str,
    path: &'a str,
    needs_slash: bool,
}

enum AbsoluteError {
    UnsupportedScheme,
    BadRequest,
}

fn parse_absolute(uri: &str) -> Result<AbsoluteTarget<'_>, AbsoluteError> {
    match uri.get(..7) {
        Some(scheme) if scheme.eq_ignore_ascii_case("http://") => {}
        _ => return Err(AbsoluteError::UnsupportedScheme),
    }
    for byte in uri.bytes() {
        if byte <= 0x20 || byte == 0x7f || byte == b'#' {
            return Err(AbsoluteError::BadRequest);
        }
    }
    let rest = &uri[7..];
    let authority_end = rest
        .bytes()
        .position(|byte| byte == b'/' || byte == b'?')
        .unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return Err(AbsoluteError::BadRequest);
    }
    let endpoint = parse_authority(authority)?;

    let (path, needs_slash) = if authority_end == rest.len() {
        ("/", false)
    } else if rest.as_bytes()[authority_end] == b'/' {
        (&rest[authority_end..], false)
    } else {
        (&rest[authority_end..], true)
    };

    Ok(AbsoluteTarget {
        endpoint,
        authority,
        path,
        needs_slash,
    })
}

fn parse_authority(authority: &str) -> Result<Endpoint, AbsoluteError> {
    if authority.is_empty() || authority.contains('@') {
        return Err(AbsoluteError::BadRequest);
    }
    for byte in authority.bytes() {
        if byte <= 0x20 || byte == 0x7f {
            return Err(AbsoluteError::BadRequest);
        }
    }

    if let Some(rest) = authority.strip_prefix('[') {
        let close = rest.find(']').ok_or(AbsoluteError::BadRequest)?;
        let host = &rest[..close];
        let tail = &rest[close + 1..];
        let port = if tail.is_empty() {
            80
        } else {
            let port = tail.strip_prefix(':').ok_or(AbsoluteError::BadRequest)?;
            parse_port(port)?
        };
        let address = Ipv6Addr::from_str(host).map_err(|_| AbsoluteError::BadRequest)?;
        return Ok(Endpoint::from_ip(address.into(), port));
    }

    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => {
            if host.is_empty() || port.contains(':') {
                return Err(AbsoluteError::BadRequest);
            }
            (host, parse_port(port)?)
        }
        None => (authority, 80),
    };
    if let Ok(address) = Ipv4Addr::from_str(host) {
        return Ok(Endpoint::from_ip(address.into(), port));
    }
    Endpoint::from_domain(host, port).map_err(|_| AbsoluteError::BadRequest)
}

fn parse_port(text: &str) -> Result<u16, AbsoluteError> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AbsoluteError::BadRequest);
    }
    let port: u16 = text.parse().map_err(|_| AbsoluteError::BadRequest)?;
    if port == 0 {
        return Err(AbsoluteError::BadRequest);
    }
    Ok(port)
}

fn is_token(text: &str) -> bool {
    !text.is_empty()
        && text.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn is_valid_header_value(value: &[u8]) -> bool {
    value
        .iter()
        .all(|byte| (*byte >= 0x20 || *byte == b'\t') && *byte != 0x7f)
}

enum ForwardError {
    TooLarge,
    BadRequest,
}

async fn respond(client: &mut TcpStream, status: &str) -> io::Result<()> {
    let response = format!("HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    client.write_all(response.as_bytes()).await
}
