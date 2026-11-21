//! Bidirectional relay with half-close propagation and idle deadlines.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, split};
use tokio::sync::Notify;
use tokio::time::{Instant, sleep};

use crate::BoxStream;

/// Default buffer size for each relay direction.
pub const RELAY_BUFFER_SIZE: usize = 32 * 1024;

/// Relay limits and half-close grace.
#[derive(Clone, Copy, Debug)]
pub struct RelayOptions {
    /// Shared idle deadline; `None` disables it.
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
    /// Both directions were idle past the shared deadline.
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
/// `downlink_grace` (if the remote finished). The idle deadline is shared by
/// both directions: any payload activity in either direction resets it
/// (ADR-0015). Dropping this future cancels both directions and closes the
/// streams.
pub async fn relay(
    client: BoxStream,
    remote: BoxStream,
    options: RelayOptions,
) -> Result<RelayStats, RelayError> {
    let (client_read, client_write) = split(client);
    let (remote_read, remote_write) = split(remote);

    let activity = Arc::new(Activity::new());
    let mut upstream = Box::pin(copy_direction(
        client_read,
        remote_write,
        Arc::clone(&activity),
    ));
    let mut downstream = Box::pin(copy_direction(
        remote_read,
        client_write,
        Arc::clone(&activity),
    ));

    let mut idle = spawn_idle(activity, options.idle_timeout);
    let mut stats = RelayStats::default();
    tokio::select! {
        result = &mut upstream => {
            stats.client_to_remote = result?;
            stats.remote_to_client =
                wait_grace(downstream.as_mut(), options.uplink_grace, &mut idle).await?;
        }
        result = &mut downstream => {
            stats.remote_to_client = result?;
            stats.client_to_remote =
                wait_grace(upstream.as_mut(), options.downlink_grace, &mut idle).await?;
        }
        _ = &mut idle => return Err(RelayError::Idle),
    }
    Ok(stats)
}

type IdleFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Shared activity clock for both relay directions.
struct Activity {
    start: Instant,
    millis: AtomicU64,
    notify: Notify,
}

impl Activity {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            millis: AtomicU64::new(0),
            notify: Notify::new(),
        }
    }

    fn touch(&self) {
        self.millis
            .store(self.start.elapsed().as_millis() as u64, Ordering::Relaxed);
        self.notify.notify_one();
    }

    fn idle_for(&self) -> u64 {
        let last = self.millis.load(Ordering::Relaxed);
        (self.start.elapsed().as_millis() as u64).saturating_sub(last)
    }
}

fn spawn_idle(activity: Arc<Activity>, idle: Option<Duration>) -> IdleFuture {
    match idle {
        Some(limit) => Box::pin(async move {
            let limit = limit.as_millis().max(1) as u64;
            loop {
                let idle_for = activity.idle_for();
                if idle_for >= limit {
                    return;
                }
                let wait = Duration::from_millis(limit - idle_for);
                tokio::select! {
                    _ = sleep(wait) => {}
                    _ = activity.notify.notified() => {}
                }
            }
        }),
        None => Box::pin(std::future::pending()),
    }
}

async fn copy_direction<R, W>(
    mut reader: R,
    mut writer: W,
    activity: Arc<Activity>,
) -> Result<u64, RelayError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0_u8; RELAY_BUFFER_SIZE];
    let mut total = 0_u64;
    loop {
        let read = reader.read(&mut buffer).await.map_err(RelayError::Read)?;
        if read == 0 {
            break;
        }
        activity.touch();
        writer
            .write_all(&buffer[..read])
            .await
            .map_err(RelayError::Write)?;
        activity.touch();
        total += read as u64;
    }
    writer.shutdown().await.map_err(RelayError::Write)?;
    activity.touch();
    Ok(total)
}

async fn wait_grace<F>(
    future: Pin<&mut F>,
    grace: Duration,
    idle: &mut IdleFuture,
) -> Result<u64, RelayError>
where
    F: Future<Output = Result<u64, RelayError>>,
{
    let grace = sleep(grace);
    tokio::pin!(grace);
    tokio::select! {
        result = future => result,
        _ = &mut grace => Err(RelayError::HalfClose),
        _ = idle => Err(RelayError::Idle),
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
        drop(client);
        drop(remote);

        let stats = task.await.expect("task").expect("relay");
        assert_eq!(stats.client_to_remote, 4);
        assert_eq!(stats.remote_to_client, 4);
    }

    #[tokio::test]
    async fn unidirectional_traffic_keeps_the_idle_deadline_open() {
        let (mut client, client_relay) = duplex_pair(64);
        let (remote_relay, mut remote) = duplex_pair(64);
        let options = RelayOptions {
            idle_timeout: Some(Duration::from_millis(80)),
            uplink_grace: Duration::from_millis(50),
            downlink_grace: Duration::from_millis(50),
        };
        let task = tokio::spawn(relay(
            Box::new(client_relay),
            Box::new(remote_relay),
            options,
        ));

        for _ in 0..5 {
            remote.write_all(b"x").await.expect("write");
            let mut byte = [0_u8; 1];
            client.read_exact(&mut byte).await.expect("read");
            assert_eq!(&byte, b"x");
            tokio::time::sleep(Duration::from_millis(40)).await;
        }

        drop(client);
        drop(remote);
        let _ = task.await.expect("task");
    }

    #[tokio::test]
    async fn idle_both_directions_returns_idle() {
        let (client, client_relay) = duplex_pair(64);
        let (remote_relay, remote) = duplex_pair(64);
        let options = RelayOptions {
            idle_timeout: Some(Duration::from_millis(20)),
            ..RelayOptions::default()
        };
        let task = tokio::spawn(relay(
            Box::new(client_relay),
            Box::new(remote_relay),
            options,
        ));
        let result = task.await.expect("task");
        assert!(matches!(result, Err(RelayError::Idle)));
        drop(client);
        drop(remote);
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

        client.write_all(b"bye").await.expect("write");
        client.shutdown().await.expect("shutdown");
        let mut buffer = [0_u8; 3];
        remote.read_exact(&mut buffer).await.expect("read");
        assert_eq!(&buffer, b"bye");
        let mut tail = [0_u8; 1];
        assert_eq!(remote.read(&mut tail).await.expect("eof"), 0);
        drop(remote);
        let _ = task.await.expect("task");
    }

    #[tokio::test]
    async fn stream_pair_is_send() {
        fn send<T: Send>(_: T) {}
        let (client, remote) = pair(64);
        send(relay(client, remote, RelayOptions::default()));
    }
}
