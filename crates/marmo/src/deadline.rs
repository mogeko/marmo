//! Absolute deadlines for connection handshakes.

use std::future::Future;
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::{Instant, timeout_at};

/// A fixed point in time, shared by every phase of one handshake.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Deadline {
    at: Instant,
}

/// The deadline passed before the wrapped future finished.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Elapsed;

impl Deadline {
    /// Starts a deadline `timeout` from now.
    pub(crate) fn after(timeout: Duration) -> Self {
        Self {
            at: Instant::now() + timeout,
        }
    }

    /// Runs `future` until it completes or this deadline expires.
    pub(crate) async fn run<F>(&self, future: F) -> Result<F::Output, Elapsed>
    where
        F: Future,
    {
        timeout_at(self.at, future).await.map_err(|_| Elapsed)
    }

    /// Returns true once the deadline has passed.
    #[cfg(test)]
    pub(crate) fn expired(&self) -> bool {
        Instant::now() >= self.at
    }
}

/// Waits for `limit` without activity, or forever when the limit is disabled.
///
/// Each successful payload in either direction calls `notify_one`, which
/// restarts the wait. This is the shared UDP association idle rule of
/// ADR-0015.
/// Returns `true` when the limit expired, or `false` when activity arrived.
pub(crate) async fn wait_for_activity(limit: Option<Duration>, activity: &Notify) -> bool {
    match limit {
        Some(limit) => {
            tokio::select! {
                _ = tokio::time::sleep(limit) => true,
                _ = activity.notified() => false,
            }
        }
        None => std::future::pending().await,
    }
}
