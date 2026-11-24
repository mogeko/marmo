//! Selector outbounds: ordered node lists with health-aware strategies.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use marmo_net::Endpoint;
use marmo_transport::BoxFuture;
use tokio::runtime::Handle;
use tokio::task::JoinHandle;
use tokio::time::{Instant, interval, timeout};
use tokio_util::sync::CancellationToken;

use crate::config::{HealthCheck, Strategy};
use crate::metrics::{MetricEvent, Metrics};
use crate::outbound::datagram::BoxDatagram;
use crate::outbound::{Connected, Outbound};

/// A selector outbound over a flat list of nodes (ADR-0006).
pub(crate) struct SelectorOutbound {
    tag: String,
    metrics: Arc<Metrics>,
    nodes: Vec<Arc<dyn Outbound>>,
    strategy: Strategy,
    health: Arc<Vec<NodeHealth>>,
    cursor: AtomicU64,
    sticky: AtomicU32,
    health_check: Option<HealthCheck>,
}

struct NodeHealth {
    ewma_ms: AtomicU32,
}

impl NodeHealth {
    fn new() -> Self {
        Self {
            ewma_ms: AtomicU32::new(0),
        }
    }

    fn record_success(&self, elapsed: Duration) {
        let sample = (elapsed.as_millis() as u32).max(1);
        let previous = self.ewma_ms.load(Ordering::Relaxed);
        let next = if previous == 0 || previous == u32::MAX {
            sample
        } else {
            (previous * 4 + sample) / 5
        };
        self.ewma_ms.store(next, Ordering::Relaxed);
    }

    fn record_failure(&self) {
        self.ewma_ms.store(u32::MAX, Ordering::Relaxed);
    }
}

impl SelectorOutbound {
    pub(crate) fn new(
        tag: String, metrics: Arc<Metrics>, nodes: Vec<Arc<dyn Outbound>>, strategy: Strategy,
        health_check: Option<HealthCheck>,
    ) -> Self {
        let health = Arc::new((0..nodes.len()).map(|_| NodeHealth::new()).collect());
        Self {
            tag,
            metrics,
            nodes,
            strategy,
            health,
            cursor: AtomicU64::new(0),
            sticky: AtomicU32::new(0),
            health_check,
        }
    }

    fn pick(&self) -> usize {
        let len = self.nodes.len();
        match self.strategy {
            Strategy::Manual | Strategy::Fallback => 0,
            Strategy::RoundRobin => (self.cursor.fetch_add(1, Ordering::Relaxed) as usize) % len,
            Strategy::Random => {
                let mut value = self
                    .cursor
                    .fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed);
                value ^= value << 13;
                value ^= value >> 7;
                value ^= value << 17;
                (value as usize) % len
            }
            Strategy::LeastLatency => (0..len)
                .min_by_key(|index| {
                    let health = &self.health[*index];
                    let ewma = health.ewma_ms.load(Ordering::Relaxed);
                    (if ewma == 0 { u32::MAX } else { ewma }, *index)
                })
                .unwrap_or(0),
        }
    }

    fn mark(&self, index: usize) {
        if matches!(self.strategy, Strategy::Fallback) {
            self.sticky.store(index as u32, Ordering::Relaxed);
        }
    }

    fn start(&self) -> usize {
        match self.strategy {
            Strategy::Fallback => (self.sticky.load(Ordering::Relaxed) as usize) % self.nodes.len(),
            _ => self.pick(),
        }
    }
}

impl Outbound for SelectorOutbound {
    fn connect<'a>(&'a self, target: &'a Endpoint) -> BoxFuture<'a, std::io::Result<Connected>> {
        Box::pin(async move {
            let start = self.start();
            if !matches!(self.strategy, Strategy::Fallback) {
                return self.nodes[start].connect(target).await;
            }
            let mut last = None;
            for offset in 0..self.nodes.len() {
                let index = (start + offset) % self.nodes.len();
                match self.nodes[index].connect(target).await {
                    Ok(connected) => {
                        self.mark(index);
                        return Ok(connected);
                    }
                    Err(error) => last = Some(error),
                }
            }
            Err(last.unwrap_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "selector has no nodes")
            }))
        })
    }

    fn connect_datagram<'a>(
        &'a self, target: &'a Endpoint, ipv4: bool,
    ) -> BoxFuture<'a, std::io::Result<Option<BoxDatagram>>> {
        Box::pin(async move {
            let start = self.start();
            if !matches!(self.strategy, Strategy::Fallback) {
                return self.nodes[start].connect_datagram(target, ipv4).await;
            }
            let mut last = None;
            for offset in 0..self.nodes.len() {
                let index = (start + offset) % self.nodes.len();
                match self.nodes[index].connect_datagram(target, ipv4).await {
                    Ok(Some(connection)) => {
                        self.mark(index);
                        return Ok(Some(connection));
                    }
                    Ok(None) => {}
                    Err(error) => last = Some(error),
                }
            }
            match last {
                Some(error) => Err(error),
                None => Ok(None),
            }
        })
    }

    fn udp_direct(&self) -> bool {
        self.nodes.iter().all(|node| node.udp_direct())
    }

    fn start(&self, runtime: &Handle, token: &CancellationToken) -> Vec<JoinHandle<()>> {
        let handles: Vec<JoinHandle<()>> = self
            .nodes
            .iter()
            .flat_map(|node| node.start(runtime, token))
            .collect();
        if handles.is_empty() {
            return Vec::new();
        }
        let token = token.clone();
        vec![runtime.spawn(async move {
            token.cancelled().await;
            for handle in &handles {
                handle.abort();
            }
            for handle in handles {
                let _ = handle.await;
            }
        })]
    }

    fn start_health(&self, runtime: &Handle, token: &CancellationToken) -> Option<JoinHandle<()>> {
        let check = self.health_check.clone()?;
        let target = Endpoint::parse(&check.target).ok()?;
        let nodes = self.nodes.clone();
        let health = Arc::clone(&self.health);
        let tag = self.tag.clone();
        let metrics = Arc::clone(&self.metrics);
        let token = token.clone();
        Some(runtime.spawn(async move {
            let mut ticker = interval(Duration::from_secs(u64::from(check.interval_s)));
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    _ = ticker.tick() => {}
                }
                for (node, health) in nodes.iter().zip(health.iter()) {
                    let start = Instant::now();
                    let probe = timeout(
                        Duration::from_secs(u64::from(check.timeout_s)),
                        node.connect(&target),
                    )
                    .await;
                    let latency = start.elapsed();
                    let ok = matches!(probe, Ok(Ok(_)));
                    match probe {
                        Ok(Ok(stream)) => {
                            drop(stream);
                            health.record_success(latency);
                        }
                        _ => health.record_failure(),
                    }
                    metrics.record(MetricEvent::HealthProbe {
                        outbound: &tag,
                        latency,
                        ok,
                    });
                }
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Fake {
        index: usize,
        fail: bool,
        seen: Arc<Mutex<Vec<usize>>>,
    }

    impl Outbound for Fake {
        fn connect<'a>(
            &'a self, _target: &'a Endpoint,
        ) -> BoxFuture<'a, std::io::Result<Connected>> {
            Box::pin(async move {
                self.seen.lock().expect("seen").push(self.index);
                if self.fail {
                    return Err(std::io::Error::other("unreachable"));
                }
                let (stream, _) = tokio::io::duplex(8);
                Ok(Connected::with_bound(Box::new(stream), None))
            })
        }

        fn connect_datagram<'a>(
            &'a self, _target: &'a Endpoint, _ipv4: bool,
        ) -> BoxFuture<'a, std::io::Result<Option<crate::outbound::datagram::BoxDatagram>>>
        {
            Box::pin(async { Ok(None) })
        }
    }

    fn target() -> Endpoint {
        Endpoint::from_domain("example.com", 443).expect("target")
    }

    fn fake(index: usize, fail: bool, seen: &Arc<Mutex<Vec<usize>>>) -> Arc<dyn Outbound> {
        Arc::new(Fake {
            index,
            fail,
            seen: Arc::clone(seen),
        })
    }

    #[tokio::test]
    async fn round_robin_rotates_per_connection() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let selector = SelectorOutbound::new(
            "test".into(),
            Arc::new(Metrics::new(None)),
            vec![
                fake(0, false, &seen),
                fake(1, false, &seen),
                fake(2, false, &seen),
            ],
            Strategy::RoundRobin,
            None,
        );
        for _ in 0..4 {
            selector.connect(&target()).await.expect("connect");
        }
        assert_eq!(*seen.lock().expect("seen"), vec![0, 1, 2, 0]);
    }

    #[tokio::test]
    async fn fallback_advances_and_sticks() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let selector = SelectorOutbound::new(
            "test".into(),
            Arc::new(Metrics::new(None)),
            vec![fake(0, true, &seen), fake(1, false, &seen)],
            Strategy::Fallback,
            None,
        );
        selector.connect(&target()).await.expect("first");
        selector.connect(&target()).await.expect("second");
        assert_eq!(*seen.lock().expect("seen"), vec![0, 1, 1]);
    }

    #[tokio::test]
    async fn least_latency_picks_the_lowest_ewma() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let selector = SelectorOutbound::new(
            "test".into(),
            Arc::new(Metrics::new(None)),
            vec![fake(0, false, &seen), fake(1, false, &seen)],
            Strategy::LeastLatency,
            None,
        );
        selector.health[0].ewma_ms.store(40, Ordering::Relaxed);
        selector.health[1].ewma_ms.store(5, Ordering::Relaxed);
        selector.connect(&target()).await.expect("connect");
        assert_eq!(*seen.lock().expect("seen"), vec![1]);
    }

    #[test]
    fn health_ewma_and_failure_update() {
        let health = NodeHealth::new();
        health.record_success(Duration::from_millis(10));
        assert_eq!(health.ewma_ms.load(Ordering::Relaxed), 10);
        health.record_success(Duration::from_millis(20));
        assert_eq!(health.ewma_ms.load(Ordering::Relaxed), 12);
        health.record_failure();
        assert_eq!(health.ewma_ms.load(Ordering::Relaxed), u32::MAX);
        health.record_success(Duration::from_millis(7));
        assert_eq!(health.ewma_ms.load(Ordering::Relaxed), 7);
    }
}
