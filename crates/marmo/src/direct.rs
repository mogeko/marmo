//! Direct outbound: dial an IP literal or resolve a domain through the system.

use std::io;

use marmo_net::Endpoint;
use tokio::net::TcpStream;

/// Connects to `endpoint` without a proxy protocol.
pub(crate) async fn connect(endpoint: &Endpoint) -> io::Result<TcpStream> {
    if let Some(address) = endpoint.to_socket_addr() {
        return TcpStream::connect(address).await;
    }

    let domain = endpoint
        .domain()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "endpoint has no host"))?;
    let addresses = tokio::net::lookup_host((domain, endpoint.port())).await?;

    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect(address).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::AddrNotAvailable, "no addresses resolved")
    }))
}
