//! Cancellation and admission control shared by listeners.

use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

/// Owns the cancellation token and the connection permits for one listener.
pub(crate) struct Supervisor {
    token: CancellationToken,
    permits: Arc<Semaphore>,
    streams: Arc<Semaphore>,
}

impl Supervisor {
    pub(crate) fn new(max_connections: u32) -> Self {
        let permits = (max_connections as usize).min(Semaphore::MAX_PERMITS);
        Self {
            token: CancellationToken::new(),
            permits: Arc::new(Semaphore::new(permits)),
            // HTTP/2 streams have their own budget so one accepted TCP
            // connection cannot consume the connection limit from its streams.
            streams: Arc::new(Semaphore::new(permits)),
        }
    }

    pub(crate) fn token(&self) -> CancellationToken {
        self.token.clone()
    }

    pub(crate) fn cancel(&self) {
        self.token.cancel();
    }

    /// Returns `None` when the instance is at its connection limit.
    pub(crate) fn try_acquire(&self) -> Option<OwnedSemaphorePermit> {
        self.permits.clone().try_acquire_owned().ok()
    }

    /// Returns `None` when the instance is at its HTTP/2 stream limit.
    pub(crate) fn try_acquire_stream(&self) -> Option<OwnedSemaphorePermit> {
        self.streams.clone().try_acquire_owned().ok()
    }
}
