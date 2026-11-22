//! Connection, byte, timeout, and health counters.
//!
//! `Instance` always keeps atomics so embedders can read a cheap snapshot.
//! An optional [`MetricsSink`] receives the same events without coupling the
//! library to a metrics backend.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// A point-in-time view of the instance counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct MetricsSnapshot {
    /// TCP streams accepted after admission control.
    pub connections_accepted: u64,
    /// TCP streams currently owned by the instance.
    pub connections_active: u64,
    /// TCP streams rejected by `max_connections`.
    pub connections_rejected: u64,
    /// TCP streams whose handler finished.
    pub connections_closed: u64,
    /// Bytes relayed from clients to outbounds.
    pub bytes_client_to_remote: u64,
    /// Bytes relayed from outbounds to clients.
    pub bytes_remote_to_client: u64,
    /// Handshakes that hit the absolute deadline.
    pub timeouts_handshake: u64,
    /// Relays that hit the idle or half-close deadline.
    pub timeouts_idle: u64,
    /// UDP sessions opened.
    pub udp_sessions_opened: u64,
    /// Health probes attempted.
    pub health_probes: u64,
    /// Health probes that failed or timed out.
    pub health_failures: u64,
    /// DNS upstream queries started.
    pub dns_queries: u64,
    /// DNS lookups served from the library cache.
    pub dns_cache_hits: u64,
    /// DNS lookups that used the fallback tier.
    pub dns_fallbacks: u64,
    /// DNS lookups that failed.
    pub dns_failures: u64,
}

/// One observable event.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum MetricEvent<'a> {
    /// A TCP stream passed admission control.
    ConnectionAccepted,
    /// A TCP stream handler finished.
    ConnectionClosed,
    /// Admission control rejected a TCP stream.
    ConnectionRejected,
    /// Bytes copied in both relay directions.
    BytesRelayed {
        /// Client to outbound.
        client_to_remote: u64,
        /// Outbound to client.
        remote_to_client: u64,
    },
    /// A handshake exceeded its absolute deadline.
    HandshakeTimeout,
    /// A relay exceeded its idle or half-close deadline.
    RelayTimeout,
    /// A UDP session was created.
    UdpSessionOpened,
    /// A selector health probe finished.
    HealthProbe {
        /// Selector tag.
        outbound: &'a str,
        /// Probe latency.
        latency: Duration,
        /// Whether the probe connected.
        ok: bool,
    },
    /// A DNS lookup moved to the fallback tier.
    DnsFallback,
    /// A DNS lookup failed.
    DnsFailure,
}

/// Receives metrics events from every connection.
pub trait MetricsSink: Send + Sync {
    /// Records one event. Implementations must not block the connection path.
    fn record(&self, event: &MetricEvent<'_>);
}

#[derive(Clone)]
pub(crate) struct Metrics {
    inner: Arc<Inner>,
}

struct Inner {
    sink: Option<Arc<dyn MetricsSink>>,
    accepted: AtomicU64,
    rejected: AtomicU64,
    closed: AtomicU64,
    client_to_remote: AtomicU64,
    remote_to_client: AtomicU64,
    timeouts_handshake: AtomicU64,
    timeouts_idle: AtomicU64,
    udp_sessions: AtomicU64,
    health_probes: AtomicU64,
    health_failures: AtomicU64,
    dns_queries: AtomicU64,
    dns_cache_hits: AtomicU64,
    dns_fallbacks: AtomicU64,
    dns_failures: AtomicU64,
}

impl Metrics {
    pub(crate) fn new(sink: Option<Arc<dyn MetricsSink>>) -> Self {
        Self {
            inner: Arc::new(Inner {
                sink,
                accepted: AtomicU64::new(0),
                rejected: AtomicU64::new(0),
                closed: AtomicU64::new(0),
                client_to_remote: AtomicU64::new(0),
                remote_to_client: AtomicU64::new(0),
                timeouts_handshake: AtomicU64::new(0),
                timeouts_idle: AtomicU64::new(0),
                udp_sessions: AtomicU64::new(0),
                health_probes: AtomicU64::new(0),
                health_failures: AtomicU64::new(0),
                dns_queries: AtomicU64::new(0),
                dns_cache_hits: AtomicU64::new(0),
                dns_fallbacks: AtomicU64::new(0),
                dns_failures: AtomicU64::new(0),
            }),
        }
    }

    pub(crate) fn record(&self, event: MetricEvent<'_>) {
        match event {
            MetricEvent::ConnectionAccepted => {
                self.inner.accepted.fetch_add(1, Ordering::Relaxed);
            }
            MetricEvent::ConnectionClosed => {
                self.inner.closed.fetch_add(1, Ordering::Relaxed);
            }
            MetricEvent::ConnectionRejected => {
                self.inner.rejected.fetch_add(1, Ordering::Relaxed);
            }
            MetricEvent::BytesRelayed {
                client_to_remote,
                remote_to_client,
            } => {
                self.inner
                    .client_to_remote
                    .fetch_add(client_to_remote, Ordering::Relaxed);
                self.inner
                    .remote_to_client
                    .fetch_add(remote_to_client, Ordering::Relaxed);
            }
            MetricEvent::HandshakeTimeout => {
                self.inner
                    .timeouts_handshake
                    .fetch_add(1, Ordering::Relaxed);
            }
            MetricEvent::RelayTimeout => {
                self.inner.timeouts_idle.fetch_add(1, Ordering::Relaxed);
            }
            MetricEvent::UdpSessionOpened => {
                self.inner.udp_sessions.fetch_add(1, Ordering::Relaxed);
            }
            MetricEvent::HealthProbe { ok, .. } => {
                self.inner.health_probes.fetch_add(1, Ordering::Relaxed);
                if !ok {
                    self.inner.health_failures.fetch_add(1, Ordering::Relaxed);
                }
            }
            MetricEvent::DnsFallback => {
                self.inner.dns_fallbacks.fetch_add(1, Ordering::Relaxed);
            }
            MetricEvent::DnsFailure => {
                self.inner.dns_failures.fetch_add(1, Ordering::Relaxed);
            }
        }
        if let Some(sink) = self.inner.sink.as_ref() {
            sink.record(&event);
        }
    }

    /// Counts an upstream DNS query without emitting a sink event.
    #[cfg(feature = "dns")]
    pub(crate) fn dns_query(&self) {
        self.inner.dns_queries.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts a DNS cache hit without emitting a sink event.
    #[cfg(feature = "dns")]
    pub(crate) fn dns_cache_hit(&self) {
        self.inner.dns_cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn snapshot(&self) -> MetricsSnapshot {
        let accepted = self.inner.accepted.load(Ordering::Relaxed);
        let closed = self.inner.closed.load(Ordering::Relaxed);
        MetricsSnapshot {
            connections_accepted: accepted,
            connections_active: accepted.saturating_sub(closed),
            connections_rejected: self.inner.rejected.load(Ordering::Relaxed),
            connections_closed: closed,
            bytes_client_to_remote: self.inner.client_to_remote.load(Ordering::Relaxed),
            bytes_remote_to_client: self.inner.remote_to_client.load(Ordering::Relaxed),
            timeouts_handshake: self.inner.timeouts_handshake.load(Ordering::Relaxed),
            timeouts_idle: self.inner.timeouts_idle.load(Ordering::Relaxed),
            udp_sessions_opened: self.inner.udp_sessions.load(Ordering::Relaxed),
            health_probes: self.inner.health_probes.load(Ordering::Relaxed),
            health_failures: self.inner.health_failures.load(Ordering::Relaxed),
            dns_queries: self.inner.dns_queries.load(Ordering::Relaxed),
            dns_cache_hits: self.inner.dns_cache_hits.load(Ordering::Relaxed),
            dns_fallbacks: self.inner.dns_fallbacks.load(Ordering::Relaxed),
            dns_failures: self.inner.dns_failures.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    struct Counter(AtomicU64);

    impl MetricsSink for Counter {
        fn record(&self, _event: &MetricEvent<'_>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[cfg(feature = "dns")]
    #[test]
    fn dns_queries_and_hits_do_not_reach_the_sink() {
        let sink = Arc::new(Counter(AtomicU64::new(0)));
        let metrics = Metrics::new(Some(sink.clone()));
        metrics.dns_query();
        metrics.dns_query();
        metrics.dns_cache_hit();
        metrics.record(MetricEvent::DnsFallback);
        metrics.record(MetricEvent::DnsFailure);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.dns_queries, 2);
        assert_eq!(snapshot.dns_cache_hits, 1);
        assert_eq!(snapshot.dns_fallbacks, 1);
        assert_eq!(snapshot.dns_failures, 1);
        assert_eq!(sink.0.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn snapshot_tracks_events_and_calls_the_sink() {
        let sink = Arc::new(Counter(AtomicU64::new(0)));
        let metrics = Metrics::new(Some(sink.clone()));
        metrics.record(MetricEvent::ConnectionAccepted);
        metrics.record(MetricEvent::ConnectionAccepted);
        metrics.record(MetricEvent::ConnectionClosed);
        metrics.record(MetricEvent::ConnectionRejected);
        metrics.record(MetricEvent::BytesRelayed {
            client_to_remote: 10,
            remote_to_client: 20,
        });
        metrics.record(MetricEvent::HandshakeTimeout);
        metrics.record(MetricEvent::RelayTimeout);
        metrics.record(MetricEvent::UdpSessionOpened);
        metrics.record(MetricEvent::HealthProbe {
            outbound: "selector",
            latency: Duration::from_millis(3),
            ok: false,
        });
        metrics.record(MetricEvent::DnsFallback);
        metrics.record(MetricEvent::DnsFailure);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.connections_accepted, 2);
        assert_eq!(snapshot.connections_active, 1);
        assert_eq!(snapshot.connections_rejected, 1);
        assert_eq!(snapshot.bytes_client_to_remote, 10);
        assert_eq!(snapshot.bytes_remote_to_client, 20);
        assert_eq!(snapshot.timeouts_handshake, 1);
        assert_eq!(snapshot.timeouts_idle, 1);
        assert_eq!(snapshot.udp_sessions_opened, 1);
        assert_eq!(snapshot.health_probes, 1);
        assert_eq!(snapshot.health_failures, 1);
        assert_eq!(snapshot.dns_fallbacks, 1);
        assert_eq!(snapshot.dns_failures, 1);
        assert_eq!(sink.0.load(Ordering::Relaxed), 11);
    }
}
