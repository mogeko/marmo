//! HTTP CONNECT outbound.

use std::io;

use marmo_net::Endpoint;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Dials `server` and tunnels to `target` through HTTP CONNECT.
pub(crate) async fn connect(server: &Endpoint, target: &Endpoint) -> io::Result<TcpStream> {
    let mut stream = crate::direct::connect(server).await?;
    let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;
    read_response(&mut stream).await?;
    Ok(stream)
}

async fn read_response(stream: &mut TcpStream) -> io::Result<()> {
    let mut buffer = Vec::with_capacity(1024);
    loop {
        let mut chunk = [0_u8; 1024];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "HTTP CONNECT proxy closed before responding",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);

        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = &buffer[..position + 4];
            let mut headers = [httparse::EMPTY_HEADER; 32];
            let mut response = httparse::Response::new(&mut headers);
            match response.parse(head) {
                Ok(httparse::Status::Complete(_)) => {}
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid HTTP CONNECT response",
                    ));
                }
            }
            let code = response.code.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP CONNECT response has no status",
                )
            })?;
            if !(200..300).contains(&code) {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("HTTP CONNECT failed with status {code}"),
                ));
            }
            return Ok(());
        }
        if buffer.len() >= 8192 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP CONNECT response is too large",
            ));
        }
    }
}
