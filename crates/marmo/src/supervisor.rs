//! Cancellation and admission control shared by listeners.

use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

/// One Mux.Cool frame is at most 64 KiB; 1,024 permits cap queued mux frames
/// at roughly 64 MiB per instance.
const MUX_MEMORY_PERMITS: usize = 1_024;

/// Owns the cancellation token and the connection permits for one listener.
pub(crate) struct Supervisor {
    token: CancellationToken,
    permits: Arc<Semaphore>,
    streams: Arc<Semaphore>,
    mux_sessions: Arc<Semaphore>,
    mux_memory: Arc<Semaphore>,
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
            // Mux.Cool logical sessions are also bounded separately from the
            // physical connection budget.
            mux_sessions: Arc::new(Semaphore::new(permits)),
            // Aggregate in-flight Mux frame memory, independent of the
            // per-session queue bound.
            mux_memory: Arc::new(Semaphore::new(MUX_MEMORY_PERMITS)),
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

    /// Returns `None` when the instance is at its Mux.Cool session limit.
    pub(crate) fn try_acquire_mux(&self) -> Option<OwnedSemaphorePermit> {
        self.mux_sessions.clone().try_acquire_owned().ok()
    }

    /// Returns `None` when the instance Mux frame memory budget is full.
    pub(crate) fn try_acquire_mux_memory(&self) -> Option<OwnedSemaphorePermit> {
        self.mux_memory.clone().try_acquire_owned().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budgets_are_separate_and_bounded() {
        let supervisor = Supervisor::new(2);
        let first = supervisor.try_acquire_mux().expect("first mux session");
        let second = supervisor.try_acquire_mux().expect("second mux session");
        assert!(supervisor.try_acquire_mux().is_none());
        assert!(supervisor.try_acquire_stream().is_some());
        assert!(supervisor.try_acquire().is_some());
        drop(first);
        drop(second);
        assert!(supervisor.try_acquire_mux().is_some());
    }
}
