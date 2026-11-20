//! Global limits for an instance.

use std::time::Duration;

/// Limits applied to every connection owned by an instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum accepted TCP streams; `0` rejects every connection.
    pub max_connections: u32,
    /// Absolute deadline from accept through the outbound connect.
    pub handshake_timeout: Duration,
    /// Activity-based relay idle deadline; `None` disables it.
    pub idle_timeout: Option<Duration>,
    /// Grace after the client uplink closes.
    pub uplink_grace: Duration,
    /// Grace after the remote downlink closes.
    pub downlink_grace: Duration,
    /// Drain deadline after shutdown is requested.
    pub shutdown_grace: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: Some(Duration::from_secs(300)),
            uplink_grace: Duration::from_secs(1),
            downlink_grace: Duration::from_secs(1),
            shutdown_grace: Duration::from_secs(10),
        }
    }
}
