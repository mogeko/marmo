//! Injected process identity for `process_name` and `process_path` rules.
//!
//! The library owns the matcher, the bounded cache, and the fail-open policy.
//! The embedder owns the operating-system lookup through [`ProcessResolver`];
//! this module never reads `/proc`, calls libproc, or depends on a platform
//! crate.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use marmo_net::{Endpoint, Network};
use tokio::runtime::Handle;
use tokio::sync::Semaphore;

use crate::config::Process as ProcessConfig;

/// Identity of the local process that opened a connection.
///
/// Fields are private so the identity cannot leak through a derived `Debug`
/// on [`Metadata`](crate::Metadata). Use [`ProcessInfo::name`] and
/// [`ProcessInfo::path`] to inspect it.
#[derive(Clone)]
pub struct ProcessInfo {
    name: Option<Arc<str>>,
    path: Option<Arc<str>>,
}

impl ProcessInfo {
    /// Builds a process identity from an optional executable name and path.
    #[must_use]
    pub fn new(name: Option<Arc<str>>, path: Option<Arc<str>>) -> Self {
        Self { name, path }
    }

    /// Returns the executable name, if the resolver provided one.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Returns the executable path, if the resolver provided one.
    #[must_use]
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }
}

impl fmt::Debug for ProcessInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessInfo")
            .finish_non_exhaustive()
    }
}

/// The connection facts passed to a [`ProcessResolver`].
#[derive(Clone, Debug)]
pub struct ProcessRequest {
    /// Transport network.
    pub network: Network,
    /// Client endpoint.
    pub source: Endpoint,
    /// Requested destination.
    pub destination: Endpoint,
}

/// Looks up the local process behind a connection.
///
/// The resolver is trusted embedder code and runs on a blocking thread. It
/// must be bounded and must not panic. Returning `None` means "unknown": the
/// process matcher does not match and routing continues.
pub trait ProcessResolver: Send + Sync {
    /// Returns the process identity for `request`, or `None` when unknown.
    fn resolve(&self, request: &ProcessRequest) -> Option<ProcessInfo>;
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Key {
    network: Network,
    address: IpAddr,
    port: u16,
}

struct Entry {
    info: Option<ProcessInfo>,
    expires: Instant,
}

#[derive(Default)]
struct Cache {
    entries: HashMap<Key, Entry>,
    order: VecDeque<Key>,
    capacity: usize,
    ttl: Duration,
}

/// The bounded cache and in-flight limiter around an injected resolver.
pub(crate) struct ProcessRuntime {
    resolver: Arc<dyn ProcessResolver>,
    cache: Mutex<Cache>,
    lookup_timeout: Duration,
    inflight: Arc<Semaphore>,
}

impl ProcessRuntime {
    pub(crate) fn new(config: &ProcessConfig, resolver: Arc<dyn ProcessResolver>) -> Self {
        Self {
            resolver,
            cache: Mutex::new(Cache {
                entries: HashMap::new(),
                order: VecDeque::new(),
                capacity: usize::from(config.cache_capacity),
                ttl: Duration::from_secs(u64::from(config.cache_ttl_s)),
            }),
            lookup_timeout: Duration::from_millis(u64::from(config.lookup_timeout_ms)),
            inflight: Arc::new(Semaphore::new(usize::from(config.max_inflight))),
        }
    }

    pub(crate) async fn lookup(
        &self, runtime: &Handle, request: ProcessRequest,
    ) -> Option<ProcessInfo> {
        let key = Key {
            network: request.network,
            address: request.source.ip()?,
            port: request.source.port(),
        };
        if let Some(cached) = self.cache_get(key) {
            return cached;
        }

        let permit = self.inflight.clone().try_acquire_owned().ok()?;
        let resolver = Arc::clone(&self.resolver);
        let task = runtime.spawn_blocking(move || {
            let _permit = permit;
            resolver.resolve(&request)
        });
        let info = match tokio::time::timeout(self.lookup_timeout, task).await {
            Ok(Ok(info)) => info,
            _ => None,
        };
        self.cache_put(key, info.clone());
        info
    }

    fn cache_get(&self, key: Key) -> Option<Option<ProcessInfo>> {
        let mut cache = self.cache.lock().unwrap_or_else(|error| error.into_inner());
        let entry = cache.entries.get(&key)?;
        if entry.expires <= Instant::now() {
            cache.entries.remove(&key);
            return None;
        }
        Some(entry.info.clone())
    }

    fn cache_put(&self, key: Key, info: Option<ProcessInfo>) {
        let mut cache = self.cache.lock().unwrap_or_else(|error| error.into_inner());
        if cache.capacity == 0 || cache.ttl.is_zero() {
            return;
        }
        let now = Instant::now();
        let expires = now.checked_add(cache.ttl).unwrap_or(now);
        if cache.entries.insert(key, Entry { info, expires }).is_none() {
            cache.order.push_back(key);
        }
        while cache.entries.len() > cache.capacity {
            let Some(oldest) = cache.order.pop_front() else {
                break;
            };
            cache.entries.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    use super::*;

    struct FakeResolver {
        calls: AtomicUsize,
        name: Option<&'static str>,
        delay: Duration,
        panic: bool,
    }

    impl FakeResolver {
        fn new(name: Option<&'static str>) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                name,
                delay: Duration::ZERO,
                panic: false,
            })
        }

        fn with_delay(name: Option<&'static str>, delay: Duration) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                name,
                delay,
                panic: false,
            })
        }

        fn panicking() -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                name: None,
                delay: Duration::ZERO,
                panic: true,
            })
        }
    }

    impl ProcessResolver for FakeResolver {
        fn resolve(&self, _request: &ProcessRequest) -> Option<ProcessInfo> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if !self.delay.is_zero() {
                thread::sleep(self.delay);
            }
            if self.panic {
                panic!("resolver panic");
            }
            self.name
                .map(|name| ProcessInfo::new(Some(Arc::from(name)), None))
        }
    }

    fn config(ttl_s: u16, capacity: u16, timeout_ms: u16) -> ProcessConfig {
        ProcessConfig {
            cache_ttl_s: ttl_s,
            cache_capacity: capacity,
            lookup_timeout_ms: timeout_ms,
            max_inflight: 4,
        }
    }

    fn request(port: u16) -> ProcessRequest {
        ProcessRequest {
            network: Network::Tcp,
            source: Endpoint::from_ip("127.0.0.1".parse().expect("ip"), port),
            destination: Endpoint::from_ip("192.0.2.1".parse().expect("ip"), 80),
        }
    }

    #[test]
    fn debug_redacts_process_identity() {
        let info = ProcessInfo::new(Some(Arc::from("curl")), Some(Arc::from("/usr/bin/curl")));
        let text = format!("{info:?}");
        assert!(!text.contains("curl"));
        assert!(text.contains("ProcessInfo"));
    }

    struct BlockingResolver {
        entered: tokio::sync::mpsc::UnboundedSender<()>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl ProcessResolver for BlockingResolver {
        fn resolve(&self, _request: &ProcessRequest) -> Option<ProcessInfo> {
            let _ = self.entered.send(());
            let _ = self.release.lock().expect("release lock").recv();
            Some(ProcessInfo::new(Some(Arc::from("curl")), None))
        }
    }

    #[tokio::test]
    async fn limits_in_flight_lookups() {
        let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let resolver = Arc::new(BlockingResolver {
            entered: entered_tx,
            release: Mutex::new(release_rx),
        });
        let runtime = Arc::new(ProcessRuntime::new(
            &ProcessConfig {
                cache_ttl_s: 5,
                cache_capacity: 8,
                lookup_timeout_ms: 500,
                max_inflight: 1,
            },
            resolver,
        ));
        let handle = Handle::current();
        let first = tokio::spawn({
            let runtime = Arc::clone(&runtime);
            let handle = handle.clone();
            async move { runtime.lookup(&handle, request(1000)).await }
        });
        entered_rx.recv().await.expect("first lookup started");

        assert!(runtime.lookup(&handle, request(1001)).await.is_none());
        release_tx.send(()).expect("release first lookup");
        assert!(first.await.expect("first task").is_some());
    }

    #[tokio::test]
    async fn caches_successful_results() {
        let resolver = FakeResolver::new(Some("curl"));
        let runtime = ProcessRuntime::new(&config(5, 8, 50), resolver.clone());
        let handle = Handle::current();

        let first = runtime.lookup(&handle, request(1000)).await;
        let second = runtime.lookup(&handle, request(1000)).await;
        assert_eq!(first.as_ref().and_then(ProcessInfo::name), Some("curl"));
        assert_eq!(second.as_ref().and_then(ProcessInfo::name), Some("curl"));
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn caches_unknown_results() {
        let resolver = FakeResolver::new(None);
        let runtime = ProcessRuntime::new(&config(5, 8, 50), resolver.clone());
        let handle = Handle::current();

        assert!(runtime.lookup(&handle, request(1000)).await.is_none());
        assert!(runtime.lookup(&handle, request(1000)).await.is_none());
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn disables_the_cache_when_configured() {
        let resolver = FakeResolver::new(Some("curl"));
        let runtime = ProcessRuntime::new(&config(0, 8, 50), resolver.clone());
        let handle = Handle::current();

        assert!(runtime.lookup(&handle, request(1000)).await.is_some());
        assert!(runtime.lookup(&handle, request(1000)).await.is_some());
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn different_sources_are_separate_entries() {
        let resolver = FakeResolver::new(Some("curl"));
        let runtime = ProcessRuntime::new(&config(5, 8, 50), resolver.clone());
        let handle = Handle::current();

        assert!(runtime.lookup(&handle, request(1000)).await.is_some());
        assert!(runtime.lookup(&handle, request(1001)).await.is_some());
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn times_out_and_fails_open() {
        let resolver = FakeResolver::with_delay(Some("curl"), Duration::from_millis(40));
        let runtime = ProcessRuntime::new(&config(5, 8, 1), resolver.clone());
        let handle = Handle::current();

        assert!(runtime.lookup(&handle, request(1000)).await.is_none());
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn catches_resolver_panics() {
        let resolver = FakeResolver::panicking();
        let runtime = ProcessRuntime::new(&config(5, 8, 50), resolver.clone());
        let handle = Handle::current();

        assert!(runtime.lookup(&handle, request(1000)).await.is_none());
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    }
}
