//! Global limits for an instance.

use std::time::Duration;

/// Limits applied to every connection owned by an instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeLimits {
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

impl RuntimeLimits {
    pub(crate) fn from_config(config: &crate::config::Limits) -> Self {
        Self {
            max_connections: config.max_connections,
            handshake_timeout: Duration::from_secs(u64::from(config.handshake_timeout_s)),
            idle_timeout: (config.idle_timeout_s != 0)
                .then(|| Duration::from_secs(u64::from(config.idle_timeout_s))),
            uplink_grace: Duration::from_secs(u64::from(config.uplink_only_s)),
            downlink_grace: Duration::from_secs(u64::from(config.downlink_only_s)),
            shutdown_grace: Duration::from_secs(10),
        }
    }
}

impl Default for RuntimeLimits {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_seconds_and_zero_idle() {
        let config: crate::Config = r#"{
            "limits": {
                "max_connections": 7,
                "handshake_timeout_s": 2,
                "idle_timeout_s": 0,
                "uplink_only_s": 3,
                "downlink_only_s": 4
            }
        }"#
        .parse()
        .expect("parse");

        let limits = RuntimeLimits::from_config(&config.inner.limits);
        assert_eq!(limits.max_connections, 7);
        assert_eq!(limits.handshake_timeout, Duration::from_secs(2));
        assert_eq!(limits.idle_timeout, None);
        assert_eq!(limits.uplink_grace, Duration::from_secs(3));
        assert_eq!(limits.downlink_grace, Duration::from_secs(4));
        assert_eq!(limits.shutdown_grace, Duration::from_secs(10));
    }

    #[test]
    fn maps_nonzero_idle() {
        let config: crate::Config = r#"{"limits":{"idle_timeout_s":5}}"#.parse().expect("parse");
        let limits = RuntimeLimits::from_config(&config.inner.limits);
        assert_eq!(limits.idle_timeout, Some(Duration::from_secs(5)));
    }
}
