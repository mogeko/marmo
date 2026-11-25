//! Transport-neutral outbound stream pool for multiplexed connections.
//!
//! The pool owns a small set of physical connections and hands each caller one
//! logical [`BoxStream`]. HTTP/2 uses it now; a later QUIC adapter can reuse the
//! same slot, permit, retry, and supervisor machinery with its own connection
//! factory.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};

use marmo_transport::{BoxFuture, BoxStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::runtime::Handle;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// One connection that can open independent byte streams.
pub(crate) trait StreamConnection: Send + Sync + 'static {
    /// Opens one logical stream, or fails when the connection is gone.
    fn open_stream(&self) -> BoxFuture<'_, io::Result<BoxStream>>;
}

/// Creates a physical connection when the pool has room.
pub(crate) trait StreamDialer<C>: Send + Sync + 'static {
    /// Dials and handshakes one connection.
    fn dial(&self) -> BoxFuture<'_, io::Result<C>>;
}

/// Fixed pool bounds.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StreamPoolConfig {
    /// Physical connections per outbound.
    pub(crate) max_connections: usize,
    /// Logical streams per physical connection.
    pub(crate) max_streams_per_connection: usize,
    /// Logical streams in flight per pool.
    pub(crate) max_in_flight: usize,
}

struct Slot<C> {
    connection: C,
    streams: Arc<Semaphore>,
    closed: AtomicBool,
    _connection_permit: OwnedSemaphorePermit,
}

/// A bounded pool of multiplexed connections.
pub(crate) struct StreamPool<C> {
    runtime: Handle,
    token: CancellationToken,
    dialer: Arc<dyn StreamDialer<C>>,
    config: StreamPoolConfig,
    slots: Mutex<Vec<Arc<Slot<C>>>>,
    permits: Arc<Semaphore>,
    connections: Arc<Semaphore>,
    capacity: watch::Sender<u64>,
    cursor: AtomicUsize,
}

impl<C> Drop for StreamPool<C> {
    fn drop(&mut self) {
        self.token.cancel();
    }
}

impl<C: StreamConnection> StreamPool<C> {
    /// Builds an empty pool; no connection is dialed until `open`.
    pub(crate) fn new(
        runtime: Handle, token: CancellationToken, dialer: Arc<dyn StreamDialer<C>>,
        config: StreamPoolConfig,
    ) -> Arc<Self> {
        Arc::new(Self {
            runtime,
            token: token.child_token(),
            dialer,
            config,
            slots: Mutex::new(Vec::new()),
            permits: Arc::new(Semaphore::new(config.max_in_flight)),
            connections: Arc::new(Semaphore::new(config.max_connections)),
            capacity: watch::channel(0).0,
            cursor: AtomicUsize::new(0),
        })
    }

    /// Spawns the task that closes connections and wakes waiters on shutdown.
    pub(crate) fn supervisor(self: &Arc<Self>) -> JoinHandle<()> {
        let pool = Arc::clone(self);
        self.runtime.spawn(async move {
            pool.token.cancelled().await;
            pool.slots
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clear();
            notify_capacity(&pool.capacity);
        })
    }

    /// Opens one logical stream, waiting while the pool is at its limit.
    pub(crate) async fn open(&self) -> io::Result<BoxStream> {
        let pool_permit = self.acquire_permit().await?;
        let mut capacity = self.capacity.subscribe();
        let mut failed_streams = 0_u8;
        loop {
            if self.token.is_cancelled() {
                return Err(shutdown());
            }
            if let Some((slot, stream_permit)) = self.select() {
                let guard = CapacityGuard::new(stream_permit, self.capacity.clone());
                match slot.connection.open_stream().await {
                    Ok(stream) => {
                        return Ok(Box::new(PooledStream {
                            inner: stream,
                            _pool_permit: Some(pool_permit),
                            _stream_permit: Some(guard.take()),
                            capacity: self.capacity.clone(),
                        }));
                    }
                    Err(error) => {
                        drop(guard);
                        self.remove(&slot);
                        failed_streams += 1;
                        if failed_streams > 1 {
                            return Err(error);
                        }
                        continue;
                    }
                }
            }
            if let Ok(connection_permit) = self.connections.clone().try_acquire_owned() {
                let guard = CapacityGuard::new(connection_permit, self.capacity.clone());
                let connection = self.dialer.dial().await?;
                let connection_permit = guard.take();
                let slot = Arc::new(Slot {
                    connection,
                    streams: Arc::new(Semaphore::new(self.config.max_streams_per_connection)),
                    closed: AtomicBool::new(false),
                    _connection_permit: connection_permit,
                });
                self.slots
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(slot);
                notify_capacity(&self.capacity);
                continue;
            }
            tokio::select! {
                _ = self.token.cancelled() => return Err(shutdown()),
                result = capacity.changed() => {
                    if result.is_err() {
                        return Err(shutdown());
                    }
                }
            }
        }
    }

    async fn acquire_permit(&self) -> io::Result<OwnedSemaphorePermit> {
        tokio::select! {
            _ = self.token.cancelled() => Err(shutdown()),
            permit = self.permits.clone().acquire_owned() => permit.map_err(|_| shutdown()),
        }
    }

    fn select(&self) -> Option<(Arc<Slot<C>>, OwnedSemaphorePermit)> {
        let slots = self
            .slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slots.is_empty() {
            return None;
        }
        let start = self.cursor.fetch_add(1, Ordering::Relaxed) % slots.len();
        for offset in 0..slots.len() {
            let slot = &slots[(start + offset) % slots.len()];
            if slot.closed.load(Ordering::Acquire) {
                continue;
            }
            if let Ok(permit) = slot.streams.clone().try_acquire_owned() {
                return Some((Arc::clone(slot), permit));
            }
        }
        None
    }

    fn remove(&self, slot: &Arc<Slot<C>>) {
        slot.closed.store(true, Ordering::Release);
        let mut slots = self
            .slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        slots.retain(|candidate| !Arc::ptr_eq(candidate, slot));
        drop(slots);
        notify_capacity(&self.capacity);
    }
}

/// Releases a permit before waking capacity waiters, including on cancellation.
struct CapacityGuard {
    permit: Option<OwnedSemaphorePermit>,
    capacity: watch::Sender<u64>,
}

impl CapacityGuard {
    fn new(permit: OwnedSemaphorePermit, capacity: watch::Sender<u64>) -> Self {
        Self {
            permit: Some(permit),
            capacity,
        }
    }

    fn take(mut self) -> OwnedSemaphorePermit {
        self.permit.take().expect("capacity guard owns a permit")
    }
}

impl Drop for CapacityGuard {
    fn drop(&mut self) {
        drop(self.permit.take());
        notify_capacity(&self.capacity);
    }
}

struct PooledStream {
    inner: BoxStream,
    _pool_permit: Option<OwnedSemaphorePermit>,
    _stream_permit: Option<OwnedSemaphorePermit>,
    capacity: watch::Sender<u64>,
}

impl Drop for PooledStream {
    fn drop(&mut self) {
        self._pool_permit.take();
        self._stream_permit.take();
        notify_capacity(&self.capacity);
    }
}

impl AsyncRead for PooledStream {
    fn poll_read(
        self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PooledStream {
    fn poll_write(
        self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

fn notify_capacity(capacity: &watch::Sender<u64>) {
    capacity.send_modify(|value| *value = value.wrapping_add(1));
}

fn shutdown() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "stream pool is shut down")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use tokio::runtime::Handle;
    use tokio::time::{Duration, timeout};

    struct MockConnection;

    impl StreamConnection for MockConnection {
        fn open_stream(&self) -> BoxFuture<'_, io::Result<BoxStream>> {
            Box::pin(async {
                let (stream, _peer) = tokio::io::duplex(64);
                Ok(Box::new(stream) as BoxStream)
            })
        }
    }

    struct MockDialer {
        dials: AtomicUsize,
    }

    impl StreamDialer<MockConnection> for MockDialer {
        fn dial(&self) -> BoxFuture<'_, io::Result<MockConnection>> {
            self.dials.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Ok(MockConnection) })
        }
    }

    fn config(connections: usize, streams: usize) -> StreamPoolConfig {
        StreamPoolConfig {
            max_connections: connections,
            max_streams_per_connection: streams,
            max_in_flight: connections * streams,
        }
    }

    fn pool(
        token: CancellationToken, dialer: Arc<MockDialer>, config: StreamPoolConfig,
    ) -> Arc<StreamPool<MockConnection>> {
        StreamPool::new(
            Handle::current(),
            token,
            dialer as Arc<dyn StreamDialer<MockConnection>>,
            config,
        )
    }

    #[tokio::test]
    async fn reuses_one_connection_for_several_streams() {
        let dialer = Arc::new(MockDialer {
            dials: AtomicUsize::new(0),
        });
        let pool = pool(CancellationToken::new(), Arc::clone(&dialer), config(4, 4));

        let _first = pool.open().await.expect("first stream");
        let _second = pool.open().await.expect("second stream");
        let _third = pool.open().await.expect("third stream");

        assert_eq!(dialer.dials.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn opens_another_connection_when_the_stream_cap_is_full() {
        let dialer = Arc::new(MockDialer {
            dials: AtomicUsize::new(0),
        });
        let pool = pool(CancellationToken::new(), Arc::clone(&dialer), config(2, 1));

        let _first = pool.open().await.expect("first stream");
        let _second = pool.open().await.expect("second stream");

        assert_eq!(dialer.dials.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn waits_for_a_stream_permit() {
        let dialer = Arc::new(MockDialer {
            dials: AtomicUsize::new(0),
        });
        let pool = pool(CancellationToken::new(), Arc::clone(&dialer), config(1, 1));

        let first = pool.open().await.expect("first stream");
        let waiting = Arc::clone(&pool);
        let task = tokio::spawn(async move { waiting.open().await });
        tokio::task::yield_now().await;
        assert!(!task.is_finished());

        drop(first);
        let second = timeout(Duration::from_secs(1), task)
            .await
            .expect("permit wait timed out")
            .expect("join")
            .expect("second stream");
        drop(second);
        assert_eq!(dialer.dials.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn cancellation_wakes_a_waiting_open() {
        let dialer = Arc::new(MockDialer {
            dials: AtomicUsize::new(0),
        });
        let token = CancellationToken::new();
        let pool = pool(token.clone(), dialer, config(1, 1));

        let first = pool.open().await.expect("first stream");
        let waiting = Arc::clone(&pool);
        let task = tokio::spawn(async move { waiting.open().await });
        tokio::task::yield_now().await;
        assert!(!task.is_finished());

        token.cancel();
        let result = timeout(Duration::from_secs(1), task)
            .await
            .expect("cancel wait timed out")
            .expect("join");
        assert!(result.is_err());
        drop(first);
    }
}
