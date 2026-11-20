//! Test-only helpers: in-memory stream pairs, fixture loaders, loopback tools.
//!
//! This crate is never published. It exists so unit tests do not need sockets
//! and so fixtures are loaded the same way across crates.
#![forbid(unsafe_code)]

use tokio::io::{DuplexStream, duplex};

/// Creates two connected in-memory streams for codec and relay tests.
///
/// `buffer` is the per-direction capacity in bytes; it must be non-zero.
///
/// # Panics
///
/// Panics if `buffer` is zero.
#[must_use]
pub fn stream_pair(buffer: usize) -> (DuplexStream, DuplexStream) {
    assert!(buffer > 0, "buffer must be non-zero");
    duplex(buffer)
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn stream_pair_forwards_bytes() {
        let (mut client, mut remote) = super::stream_pair(64);
        client.write_all(b"marmo").await.expect("write");
        let mut bytes = [0_u8; 5];
        remote.read_exact(&mut bytes).await.expect("read");
        assert_eq!(&bytes, b"marmo");
    }
}
