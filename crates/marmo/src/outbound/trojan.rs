//! Trojan outbound: TLS, authentication line, and CONNECT request.

use std::io;
use std::net::SocketAddr;

use marmo_net::Endpoint;
use marmo_proto::trojan::{
    COMMAND_CONNECT, PasswordHash, REQUEST_HEADER_MAX, encode_request_header,
};
use marmo_transport::BoxStream;
use marmo_transport::tls::TlsClient;
use tokio::io::AsyncWriteExt;
use zeroize::Zeroize;

/// Dials `server` over TLS and sends a CONNECT request for `target`.
pub(crate) async fn connect(
    server: &Endpoint,
    tls: &TlsClient,
    password: &PasswordHash,
    target: &Endpoint,
) -> io::Result<(BoxStream, Option<SocketAddr>)> {
    let inner = crate::direct::connect(server).await?;
    let bound = inner.local_addr().ok();
    let mut stream = tls.connect(Box::new(inner)).await.map_err(tls_error)?;

    let mut header = [0_u8; REQUEST_HEADER_MAX];
    let length = encode_request_header(password, target, COMMAND_CONNECT, &mut header)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let written = stream.write_all(&header[..length]).await;
    header.zeroize();
    written?;
    Ok((stream, bound))
}

pub(crate) fn tls_error(error: marmo_transport::tls::TlsError) -> io::Error {
    io::Error::other(error)
}
