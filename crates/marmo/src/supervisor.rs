//! Cancellation and admission control shared by listeners.

use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

/// Owns the cancellation token and the connection permits for one listener.
pub(crate) struct Supervisor {
    token: CancellationToken,
    permits: Arc<Semaphore>,
}

impl Supervisor {
    pub(crate) fn new(max_connections: u32) -> Self {
        let permits = (max_connections as usize).min(Semaphore::MAX_PERMITS);
        Self {
            token: CancellationToken::new(),
            permits: Arc::new(Semaphore::new(permits)),
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
}
