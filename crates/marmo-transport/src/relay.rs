//! Bidirectional relay with half-close propagation and idle deadlines.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::time::Duration;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, split};
use tokio::time::timeout;

use crate::BoxStream;

/// Default buffer size for each relay direction.
pub const RELAY_BUFFER_SIZE: usize = 32 * 1024;

/// Relay limits and half-close grace.
#[derive(Clone, Copy, Debug)]
pub struct RelayOptions {
    /// Per-direction idle deadline; `None` disables it.
    pub idle_timeout: Option<Duration>,
    /// Grace after the client uplink closes (client -> remote finished).
    pub uplink_grace: Duration,
    /// Grace after the remote downlink closes (remote -> client finished).
    pub downlink_grace: Duration,
}

impl Default for RelayOptions {
    fn default() -> Self {
        Self {
            idle_timeout: None,
            uplink_grace: Duration::from_secs(1),
            downlink_grace: Duration::from_secs(1),
        }
    }
}

/// Bytes copied in each direction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RelayStats {
    /// Bytes read from the client and written to the remote.
    pub client_to_remote: u64,
    /// Bytes read from the remote and written to the client.
    pub remote_to_client: u64,
}

/// Why a relay stopped.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RelayError {
    /// Reading from one side failed.
    #[error("relay read failed: {0}")]
    Read(#[source] io::Error),
    /// Writing to the other side failed.
    #[error("relay write failed: {0}")]
    Write(#[source] io::Error),
    /// A direction was idle past its deadline.
    #[error("relay idle timeout")]
    Idle,
    /// The peer did not finish within the half-close grace.
    #[error("relay half-close grace expired")]
    HalfClose,
}

/// Copies bytes in both directions until both sides close.
///
/// The first direction to finish propagates a half-close to its peer, then the
/// other direction gets `uplink_grace` (if the client finished) or
/// `downlink_grace` (if the remote finished). Dropping this future cancels
/// both directions and closes the streams.
pub async fn relay(
    client: BoxStream,
    remote: BoxStream,
    options: RelayOptions,
) -> Result<RelayStats, RelayError> {
    let (client_read, client_write) = split(client);
    let (remote_read, remote_write) = split(remote);

    let mut upstream = Box::pin(copy_direction(
        client_read,
        remote_write,
        options.idle_timeout,
    ));
    let mut downstream = Box::pin(copy_direction(
        remote_read,
        client_write,
        options.idle_timeout,
    ));

    let mut stats = RelayStats::default();
    tokio::select! {
        result = &mut upstream => {
            stats.client_to_remote = result?;
            stats.remote_to_client =
                wait_grace(downstream.as_mut(), options.uplink_grace).await?;
        }
        result = &mut downstream => {
            stats.remote_to_client = result?;
            stats.client_to_remote =
                wait_grace(upstream.as_mut(), options.downlink_grace).await?;
        }
    }
    Ok(stats)
}

async fn copy_direction<R, W>(
    mut reader: R,
    mut writer: W,
    idle: Option<Duration>,
) -> Result<u64, RelayError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0_u8; RELAY_BUFFER_SIZE];
    let mut total = 0_u64;
    loop {
        let read = read_with_idle(&mut reader, &mut buffer, idle).await?;
        if read == 0 {
            break;
        }
        write_with_idle(&mut writer, &buffer[..read], idle).await?;
        total += read as u64;
    }
    shutdown_with_idle(&mut writer, idle).await?;
    Ok(total)
}

async fn read_with_idle<R>(
    reader: &mut R,
    buffer: &mut [u8],
    idle: Option<Duration>,
) -> Result<usize, RelayError>
where
    R: AsyncRead + Unpin,
{
    match idle {
        Some(limit) => match timeout(limit, reader.read(buffer)).await {
            Ok(result) => result.map_err(RelayError::Read),
            Err(_) => Err(RelayError::Idle),
        },
        None => reader.read(buffer).await.map_err(RelayError::Read),
    }
}

async fn write_with_idle<W>(
    writer: &mut W,
    buffer: &[u8],
    idle: Option<Duration>,
) -> Result<(), RelayError>
where
    W: AsyncWrite + Unpin,
{
    match idle {
        Some(limit) => match timeout(limit, writer.write_all(buffer)).await {
            Ok(result) => result.map_err(RelayError::Write),
            Err(_) => Err(RelayError::Idle),
        },
        None => writer.write_all(buffer).await.map_err(RelayError::Write),
    }
}

async fn shutdown_with_idle<W>(writer: &mut W, idle: Option<Duration>) -> Result<(), RelayError>
where
    W: AsyncWrite + Unpin,
{
    match idle {
        Some(limit) => match timeout(limit, writer.shutdown()).await {
            Ok(result) => result.map_err(RelayError::Write),
            Err(_) => Err(RelayError::Idle),
        },
        None => writer.shutdown().await.map_err(RelayError::Write),
    }
}

async fn wait_grace<F>(future: Pin<&mut F>, grace: Duration) -> Result<u64, RelayError>
where
    F: Future<Output = Result<u64, RelayError>>,
{
    match timeout(grace, future).await {
        Ok(result) => result,
        Err(_) => Err(RelayError::HalfClose),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::DuplexStream;

    fn pair(capacity: usize) -> (BoxStream, BoxStream) {
        let (a, b) = tokio::io::duplex(capacity);
        (Box::new(a), Box::new(b))
    }

    fn duplex_pair(capacity: usize) -> (DuplexStream, DuplexStream) {
        tokio::io::duplex(capacity)
    }

    #[tokio::test]
    async fn copies_both_directions() {
        let (mut client, client_relay) = duplex_pair(64);
        let (remote_relay, mut remote) = duplex_pair(64);
        let task = tokio::spawn(relay(
            Box::new(client_relay),
            Box::new(remote_relay),
            RelayOptions::default(),
        ));

        client.write_all(b"ping").await.expect("write");
        let mut buffer = [0_u8; 4];
        remote.read_exact(&mut buffer).await.expect("read");
        assert_eq!(&buffer, b"ping");

        remote.write_all(b"pong").await.expect("write");
        client.read_exact(&mut buffer).await.expect("read");
        assert_eq!(&buffer, b"pong");

        client.shutdown().await.expect("shutdown");
        remote.shutdown().await.expect("shutdown");

        let stats = task.await.expect("join").expect("relay");
        assert_eq!(stats.client_to_remote, 4);
        assert_eq!(stats.remote_to_client, 4);
    }

    #[tokio::test]
    async fn propagates_half_close() {
        let (mut client, client_relay) = duplex_pair(64);
        let (remote_relay, mut remote) = duplex_pair(64);
        let task = tokio::spawn(relay(
            Box::new(client_relay),
            Box::new(remote_relay),
            RelayOptions::default(),
        ));

        client.write_all(b"req").await.expect("write");
        client.shutdown().await.expect("shutdown");
        let mut request = [0_u8; 3];
        remote.read_exact(&mut request).await.expect("read");
        assert_eq!(&request, b"req");
        let mut eof = [0_u8; 1];
        assert_eq!(remote.read(&mut eof).await.expect("eof"), 0);

        remote.write_all(b"res").await.expect("write");
        remote.shutdown().await.expect("shutdown");
        let mut response = [0_u8; 3];
        client.read_exact(&mut response).await.expect("read");
        assert_eq!(&response, b"res");

        let stats = task.await.expect("join").expect("relay");
        assert_eq!(stats.client_to_remote, 3);
        assert_eq!(stats.remote_to_client, 3);
    }

    #[tokio::test]
    async fn idle_timeout_closes() {
        let (_client, client_relay) = duplex_pair(64);
        let (remote_relay, _remote) = duplex_pair(64);
        let options = RelayOptions {
            idle_timeout: Some(Duration::from_millis(30)),
            ..RelayOptions::default()
        };
        let result = relay(Box::new(client_relay), Box::new(remote_relay), options).await;
        assert!(matches!(result, Err(RelayError::Idle)));
    }

    #[tokio::test]
    async fn half_close_grace_expires() {
        let (mut client, client_relay) = duplex_pair(64);
        let (remote_relay, _remote) = duplex_pair(64);
        let options = RelayOptions {
            uplink_grace: Duration::from_millis(30),
            downlink_grace: Duration::from_millis(30),
            ..RelayOptions::default()
        };
        let task = tokio::spawn(relay(
            Box::new(client_relay),
            Box::new(remote_relay),
            options,
        ));
        client.shutdown().await.expect("shutdown");
        let result = task.await.expect("join");
        assert!(matches!(result, Err(RelayError::HalfClose)));
    }

    #[test]
    fn stream_pair_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<BoxStream>();
        let _ = pair(16);
    }
}
