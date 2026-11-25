//! Implementation of the feature-gated DNS subsystem.

use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts};
use hickory_resolver::net::NetError;
use marmo_net::DomainName;
use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use thiserror::Error;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::config::{Dns as DnsConfig, DnsProtocol, DnsServer};
use crate::metrics::{MetricEvent, Metrics};

/// Maximum address records returned for one name.
const MAX_ADDRESSES: usize = 16;
/// Maximum trust anchors accepted from one inline PEM bundle.
const MAX_CA_CERTIFICATES: usize = 16;

/// A boxed future returned by an embedder resolver.
pub type DnsFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A successful DNS answer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsAnswer {
    addresses: Vec<IpAddr>,
    ttl: Duration,
}

impl DnsAnswer {
    /// Builds an answer from addresses and a positive TTL.
    ///
    /// The library deduplicates and caps the address list and clamps the TTL;
    /// an empty list is treated as [`DnsError::NotFound`].
    #[must_use]
    pub fn new(addresses: Vec<IpAddr>, ttl: Duration) -> Self {
        Self { addresses, ttl }
    }

    /// Returns the resolved addresses.
    #[must_use]
    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }

    /// Returns the answer's positive TTL.
    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.ttl
    }
}

/// Why a DNS lookup failed.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum DnsError {
    /// The name does not exist or has no records. Cache negatively and do not
    /// use the fallback tier.
    #[error("dns name has no records")]
    NotFound,
    /// The lookup exceeded its deadline.
    #[error("dns lookup timed out")]
    Timeout,
    /// A transport or upstream failure. The fallback tier may be tried.
    #[error("dns upstream unavailable")]
    Unavailable,
    /// The library's in-flight limit was reached.
    #[error("dns lookup limit reached")]
    Busy,
    /// The name cannot be represented as a DNS name.
    #[error("invalid dns name")]
    InvalidName,
}

impl DnsError {
    fn is_retryable(&self) -> bool {
        matches!(self, Self::Timeout | Self::Unavailable | Self::Busy)
    }
}

/// Resolves names for the library.
///
/// The resolver is trusted embedder code. It must be bounded, must not panic,
/// and its future must be cancel-safe. The library still applies its cache,
/// timeout, in-flight limit, deduplication, and address cap.
pub trait DnsResolver: Send + Sync {
    /// Resolves `name` to addresses.
    fn resolve<'a>(&'a self, name: &'a str) -> DnsFuture<'a, Result<DnsAnswer, DnsError>>;
}

/// Why a DNS runtime could not be built.
#[derive(Debug, Error)]
pub(crate) enum DnsBuildError {
    /// The configuration cannot be used without an injected resolver.
    #[error("{0}")]
    Config(String),
    /// An inline trust-anchor bundle was invalid.
    #[error("invalid dns.tls.ca: {0}")]
    TrustAnchors(String),
    /// The TLS client configuration could not be built.
    #[error("failed to build the dns TLS client: {0}")]
    Tls(String),
    /// Hickory rejected the resolver configuration.
    #[error("failed to build the dns resolver: {0}")]
    Resolver(String),
    /// An injected resolver and built-in server fields were both configured.
    #[error("dns_resolver conflicts with dns.servers, dns.fallback, or dns.tls")]
    Conflict,
}

#[derive(Clone, Copy)]
struct Policy {
    timeout: Duration,
    capacity: usize,
    min_ttl: Duration,
    max_ttl: Duration,
    negative_ttl: Duration,
    max_inflight: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(5000),
            capacity: 1024,
            min_ttl: Duration::ZERO,
            max_ttl: Duration::from_secs(3600),
            negative_ttl: Duration::from_secs(30),
            max_inflight: 64,
        }
    }
}

impl Policy {
    fn from_config(config: &DnsConfig) -> Self {
        Self {
            timeout: Duration::from_millis(u64::from(config.timeout_ms)),
            capacity: usize::from(config.cache_capacity),
            min_ttl: Duration::from_secs(u64::from(config.min_ttl_s)),
            max_ttl: Duration::from_secs(u64::from(config.max_ttl_s)),
            negative_ttl: Duration::from_secs(u64::from(config.negative_ttl_s)),
            max_inflight: usize::from(config.max_inflight),
        }
    }

    fn clamp_ttl(self, ttl: Duration) -> Duration {
        ttl.clamp(self.min_ttl, self.max_ttl)
    }
}

#[derive(Clone)]
enum Cached {
    Addresses(Arc<[IpAddr]>),
    NotFound,
}

struct Entry {
    value: Cached,
    expires: Instant,
}

#[derive(Default)]
struct Cache {
    entries: HashMap<Box<str>, Entry>,
    order: VecDeque<Box<str>>,
    capacity: usize,
}

/// The instance-wide resolver: policy, cache, and one or two upstream tiers.
pub(crate) struct DnsRuntime {
    plan: Plan,
    cache: Mutex<Cache>,
    policy: Policy,
    inflight: Arc<Semaphore>,
    metrics: Metrics,
}

enum Plan {
    Builtin {
        primary: Arc<dyn DnsResolver>,
        fallback: Option<Arc<dyn DnsResolver>>,
    },
    Injected(Arc<dyn DnsResolver>),
}

impl DnsRuntime {
    pub(crate) fn build(
        config: Option<&DnsConfig>, injected: Option<Arc<dyn DnsResolver>>, metrics: Metrics,
    ) -> Result<Option<Arc<Self>>, DnsBuildError> {
        let policy = config.map_or_else(Policy::default, Policy::from_config);
        match (config, injected) {
            (None, None) => Ok(None),
            (None, Some(resolver)) => Ok(Some(Arc::new(Self::new(
                Plan::Injected(resolver),
                policy,
                metrics,
            )))),
            (Some(config), Some(resolver)) => {
                if !config.servers.is_empty() || !config.fallback.is_empty() || config.tls.is_some()
                {
                    return Err(DnsBuildError::Conflict);
                }
                Ok(Some(Arc::new(Self::new(
                    Plan::Injected(resolver),
                    policy,
                    metrics,
                ))))
            }
            (Some(config), None) => {
                if config.servers.is_empty() {
                    return Err(DnsBuildError::Config(
                        "dns.servers must not be empty without dns_resolver".into(),
                    ));
                }
                let primary = Arc::new(build_hickory(&config.servers, config)?);
                let fallback = if config.fallback.is_empty() {
                    None
                } else {
                    Some(Arc::new(build_hickory(&config.fallback, config)?) as Arc<dyn DnsResolver>)
                };
                Ok(Some(Arc::new(Self::new(
                    Plan::Builtin { primary, fallback },
                    policy,
                    metrics,
                ))))
            }
        }
    }

    fn new(plan: Plan, policy: Policy, metrics: Metrics) -> Self {
        Self {
            plan,
            cache: Mutex::new(Cache {
                entries: HashMap::new(),
                order: VecDeque::new(),
                capacity: policy.capacity,
            }),
            inflight: Arc::new(Semaphore::new(policy.max_inflight)),
            policy,
            metrics,
        }
    }

    pub(crate) async fn resolve(&self, name: &str) -> Result<Arc<[IpAddr]>, DnsError> {
        let key = cache_key(name)?;
        if let Some(value) = self.cache_get(key.as_ref()) {
            self.metrics.dns_cache_hit();
            return cached_result(value);
        }

        let permit = self
            .inflight
            .clone()
            .try_acquire_owned()
            .map_err(|_| DnsError::Busy)?;
        self.metrics.dns_query();
        let deadline = Instant::now() + self.policy.timeout;
        let result = self
            .plan
            .resolve(key.as_ref(), deadline, &self.metrics)
            .await;
        drop(permit);
        self.store(key.as_ref(), result)
    }

    fn store(
        &self, key: &str, result: Result<DnsAnswer, DnsError>,
    ) -> Result<Arc<[IpAddr]>, DnsError> {
        match result {
            Ok(answer) => {
                if answer.addresses.is_empty() {
                    self.cache_put(key, Cached::NotFound, self.policy.negative_ttl);
                    return Err(DnsError::NotFound);
                }
                let addresses = deduplicate(answer.addresses);
                let ttl = self.policy.clamp_ttl(answer.ttl);
                self.cache_put(key, Cached::Addresses(Arc::clone(&addresses)), ttl);
                Ok(addresses)
            }
            Err(DnsError::NotFound) => {
                self.cache_put(key, Cached::NotFound, self.policy.negative_ttl);
                Err(DnsError::NotFound)
            }
            Err(error) => {
                self.metrics.record(MetricEvent::DnsFailure);
                Err(error)
            }
        }
    }

    pub(crate) fn io_resolve(error: DnsError) -> io::Error {
        match error {
            DnsError::NotFound => {
                io::Error::new(io::ErrorKind::AddrNotAvailable, "no addresses resolved")
            }
            DnsError::Timeout => io::Error::new(io::ErrorKind::TimedOut, "dns lookup timed out"),
            DnsError::Busy => {
                io::Error::new(io::ErrorKind::WouldBlock, "dns in-flight limit reached")
            }
            DnsError::InvalidName => {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid dns name")
            }
            DnsError::Unavailable => io::Error::other("dns upstream unavailable"),
        }
    }

    fn cache_get(&self, key: &str) -> Option<Cached> {
        let cache = self.cache.lock().unwrap_or_else(|error| error.into_inner());
        if cache.capacity == 0 {
            return None;
        }
        let now = Instant::now();
        let entry = cache.entries.get(key)?;
        if entry.expires <= now {
            // Keep the stale entry in `entries` until eviction or overwrite.
            // Removing it here would leave its key in the FIFO `order` forever,
            // and the order queue would grow without bound under TTL churn.
            return None;
        }
        Some(entry.value.clone())
    }

    fn cache_put(&self, key: &str, value: Cached, ttl: Duration) {
        let mut cache = self.cache.lock().unwrap_or_else(|error| error.into_inner());
        if cache.capacity == 0 || ttl.is_zero() {
            return;
        }
        let now = Instant::now();
        let expires = now.checked_add(ttl).unwrap_or(now);
        let key = Box::<str>::from(key);
        if cache
            .entries
            .insert(key.clone(), Entry { value, expires })
            .is_none()
        {
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

impl Plan {
    async fn resolve(
        &self, name: &str, deadline: Instant, metrics: &Metrics,
    ) -> Result<DnsAnswer, DnsError> {
        match self {
            Self::Injected(resolver) => resolve_with_deadline(resolver, name, deadline).await,
            Self::Builtin { primary, fallback } => {
                match resolve_with_deadline(primary, name, deadline).await {
                    Err(error) if error.is_retryable() => {
                        let Some(fallback) = fallback.as_ref() else {
                            return Err(error);
                        };
                        metrics.record(MetricEvent::DnsFallback);
                        resolve_with_deadline(fallback, name, deadline).await
                    }
                    result => result,
                }
            }
        }
    }
}

async fn resolve_with_deadline(
    resolver: &Arc<dyn DnsResolver>, name: &str, deadline: Instant,
) -> Result<DnsAnswer, DnsError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(DnsError::Timeout);
    }
    timeout(remaining, resolver.resolve(name))
        .await
        .map_err(|_| DnsError::Timeout)?
}

fn cached_result(value: Cached) -> Result<Arc<[IpAddr]>, DnsError> {
    match value {
        Cached::Addresses(addresses) => Ok(addresses),
        Cached::NotFound => Err(DnsError::NotFound),
    }
}

fn cache_key(name: &str) -> Result<Cow<'_, str>, DnsError> {
    let name = name.trim_end_matches('.');
    if name.is_empty() || name.len() > DomainName::MAX_LEN {
        return Err(DnsError::InvalidName);
    }
    if name.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Ok(Cow::Owned(name.to_ascii_lowercase()))
    } else {
        Ok(Cow::Borrowed(name))
    }
}

fn deduplicate(addresses: Vec<IpAddr>) -> Arc<[IpAddr]> {
    let mut unique = Vec::with_capacity(addresses.len().min(MAX_ADDRESSES));
    for address in addresses {
        if unique.len() == MAX_ADDRESSES {
            break;
        }
        if !unique.contains(&address) {
            unique.push(address);
        }
    }
    Arc::from(unique)
}

struct HickoryResolver {
    resolver: TokioResolver,
}

impl DnsResolver for HickoryResolver {
    fn resolve<'a>(&'a self, name: &'a str) -> DnsFuture<'a, Result<DnsAnswer, DnsError>> {
        Box::pin(async move {
            let lookup = self.resolver.lookup_ip(name).await.map_err(map_net_error)?;
            let ttl = lookup
                .valid_until()
                .saturating_duration_since(Instant::now());
            let addresses: Vec<IpAddr> = lookup.iter().collect();
            if addresses.is_empty() {
                return Err(DnsError::NotFound);
            }
            Ok(DnsAnswer::new(addresses, ttl))
        })
    }
}

fn map_net_error(error: NetError) -> DnsError {
    if error.is_no_records_found() {
        DnsError::NotFound
    } else {
        DnsError::Unavailable
    }
}

fn build_hickory(
    servers: &[DnsServer], config: &DnsConfig,
) -> Result<HickoryResolver, DnsBuildError> {
    let name_servers = servers
        .iter()
        .map(name_server)
        .collect::<Result<Vec<_>, _>>()?;
    let resolver_config = ResolverConfig::from_name_servers(name_servers);
    let provider = hickory_resolver::net::runtime::TokioRuntimeProvider::new();
    let mut builder = TokioResolver::builder_with_config(resolver_config, provider);
    let mut options = ResolverOpts::default();
    options.cache_size = 0;
    options.use_hosts_file = ResolveHosts::Never;
    options.attempts = 1;
    options.timeout = Duration::from_millis(u64::from(config.timeout_ms));
    builder = builder.with_options(options);
    if servers
        .iter()
        .any(|server| matches!(server.protocol, DnsProtocol::Tls | DnsProtocol::Https))
    {
        builder = builder.with_tls_config(build_tls(config.tls.as_ref())?);
    }
    let resolver = builder
        .build()
        .map_err(|error| DnsBuildError::Resolver(error.to_string()))?;
    Ok(HickoryResolver { resolver })
}

fn name_server(server: &DnsServer) -> Result<NameServerConfig, DnsBuildError> {
    let address = server
        .address
        .parse::<SocketAddr>()
        .map_err(|_| DnsBuildError::Config(format!("invalid dns address '{}'", server.address)))?;
    let mut config = match server.protocol {
        DnsProtocol::Udp => NameServerConfig::udp(address.ip()),
        DnsProtocol::Tcp => NameServerConfig::tcp(address.ip()),
        DnsProtocol::Tls => NameServerConfig::tls(address.ip(), tls_server_name(server, address)?),
        DnsProtocol::Https => NameServerConfig::https(
            address.ip(),
            tls_server_name(server, address)?,
            server.path.as_deref().map(Arc::<str>::from),
        ),
    };
    config.trust_negative_responses = false;
    for connection in &mut config.connections {
        connection.port = address.port();
    }
    Ok(config)
}

fn tls_server_name(server: &DnsServer, address: SocketAddr) -> Result<Arc<str>, DnsBuildError> {
    let name = server
        .server_name
        .clone()
        .unwrap_or_else(|| address.ip().to_string());
    rustls::pki_types::ServerName::try_from(name.clone())
        .map_err(|_| DnsBuildError::Config(format!("invalid dns server name '{name}'")))?;
    Ok(Arc::from(name))
}

fn build_tls(tls: Option<&crate::config::DnsTls>) -> Result<rustls::ClientConfig, DnsBuildError> {
    let builder = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13]);
    let builder = match tls.and_then(|tls| tls.ca.as_deref()) {
        Some(pem) => builder.with_root_certificates(trust_anchors(pem)?),
        None => {
            use rustls_platform_verifier::BuilderVerifierExt;
            builder
                .with_platform_verifier()
                .map_err(|error| DnsBuildError::Tls(error.to_string()))?
        }
    };
    Ok(builder.with_no_client_auth())
}

fn trust_anchors(pem: &str) -> Result<RootCertStore, DnsBuildError> {
    let certificates: Result<Vec<_>, _> = CertificateDer::pem_slice_iter(pem.as_bytes()).collect();
    let certificates =
        certificates.map_err(|_| DnsBuildError::TrustAnchors("invalid PEM".into()))?;
    if certificates.is_empty() || certificates.len() > MAX_CA_CERTIFICATES {
        return Err(DnsBuildError::TrustAnchors(
            "expected 1 to 16 certificates".into(),
        ));
    }
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(certificate)
            .map_err(|_| DnsBuildError::TrustAnchors("certificate rejected".into()))?;
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::sync::Notify;

    use super::*;

    type Reply = Result<DnsAnswer, DnsError>;

    struct Fake {
        calls: AtomicUsize,
        replies: Mutex<VecDeque<Reply>>,
        delay: Duration,
    }

    impl Fake {
        fn new(replies: Vec<Reply>) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                replies: Mutex::new(replies.into()),
                delay: Duration::ZERO,
            })
        }

        fn delayed(delay: Duration) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                replies: Mutex::new(VecDeque::new()),
                delay,
            })
        }
    }

    impl DnsResolver for Fake {
        fn resolve<'a>(&'a self, _name: &'a str) -> DnsFuture<'a, Result<DnsAnswer, DnsError>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                if !self.delay.is_zero() {
                    tokio::time::sleep(self.delay).await;
                }
                self.replies
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .pop_front()
                    .unwrap_or(Err(DnsError::Unavailable))
            })
        }
    }

    struct Blocking {
        started: Arc<Notify>,
        release: Arc<Notify>,
    }

    impl DnsResolver for Blocking {
        fn resolve<'a>(&'a self, _name: &'a str) -> DnsFuture<'a, Result<DnsAnswer, DnsError>> {
            Box::pin(async move {
                self.started.notify_one();
                self.release.notified().await;
                Ok(answer(&["127.0.0.1"], 60))
            })
        }
    }

    fn answer(addresses: &[&str], ttl_s: u64) -> DnsAnswer {
        DnsAnswer::new(
            addresses
                .iter()
                .map(|address| address.parse().expect("ip"))
                .collect(),
            Duration::from_secs(ttl_s),
        )
    }

    fn policy(timeout_ms: u64, capacity: usize, max_inflight: usize) -> Policy {
        Policy {
            timeout: Duration::from_millis(timeout_ms),
            capacity,
            min_ttl: Duration::ZERO,
            max_ttl: Duration::from_secs(3600),
            negative_ttl: Duration::from_secs(30),
            max_inflight,
        }
    }

    fn runtime(plan: Plan, policy: Policy) -> Arc<DnsRuntime> {
        Arc::new(DnsRuntime::new(plan, policy, Metrics::new(None)))
    }

    fn injected(resolver: Arc<dyn DnsResolver>) -> Plan {
        Plan::Injected(resolver)
    }

    #[tokio::test]
    async fn caches_positive_answers() {
        let fake = Fake::new(vec![
            Ok(answer(&["127.0.0.1"], 60)),
            Ok(answer(&["127.0.0.2"], 60)),
        ]);
        let runtime = runtime(
            injected(Arc::clone(&fake) as Arc<dyn DnsResolver>),
            policy(100, 8, 4),
        );

        let first = runtime.resolve("example.com").await.expect("first");
        let second = runtime.resolve("example.com").await.expect("second");
        assert_eq!(&*first, &[IpAddr::from([127, 0, 0, 1])]);
        assert_eq!(&*second, &[IpAddr::from([127, 0, 0, 1])]);
        assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
        let snapshot = runtime.metrics.snapshot();
        assert_eq!(snapshot.dns_queries, 1);
        assert_eq!(snapshot.dns_cache_hits, 1);
    }

    #[tokio::test]
    async fn expires_positive_answers() {
        let fake = Fake::new(vec![
            Ok(DnsAnswer::new(
                vec![IpAddr::from([127, 0, 0, 1])],
                Duration::from_millis(5),
            )),
            Ok(answer(&["127.0.0.2"], 60)),
        ]);
        let runtime = runtime(
            injected(Arc::clone(&fake) as Arc<dyn DnsResolver>),
            policy(100, 8, 4),
        );

        runtime.resolve("example.com").await.expect("first");
        tokio::time::sleep(Duration::from_millis(20)).await;
        runtime.resolve("example.com").await.expect("second");
        assert_eq!(fake.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn ttl_churn_keeps_the_eviction_queue_bounded() {
        let mut answers = Vec::new();
        for _ in 0..6 {
            answers.push(Ok(DnsAnswer::new(
                vec![IpAddr::from([127, 0, 0, 1])],
                Duration::from_millis(1),
            )));
        }
        let fake = Fake::new(answers);
        let runtime = runtime(
            injected(Arc::clone(&fake) as Arc<dyn DnsResolver>),
            policy(100, 2, 4),
        );

        for _ in 0..3 {
            runtime.resolve("a.test").await.expect("a");
            runtime.resolve("b.test").await.expect("b");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let cache = runtime
            .cache
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert!(cache.entries.len() <= 2);
        assert!(cache.order.len() <= 2);
    }

    #[tokio::test]
    async fn evicts_the_oldest_entry_at_capacity() {
        let fake = Fake::new(vec![
            Ok(answer(&["127.0.0.1"], 60)),
            Ok(answer(&["127.0.0.2"], 60)),
            Ok(answer(&["127.0.0.3"], 60)),
        ]);
        let runtime = runtime(
            injected(Arc::clone(&fake) as Arc<dyn DnsResolver>),
            policy(100, 1, 4),
        );

        runtime.resolve("a.test").await.expect("a");
        runtime.resolve("b.test").await.expect("b");
        runtime.resolve("a.test").await.expect("a again");
        assert_eq!(fake.calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn disabled_cache_still_queries() {
        let fake = Fake::new(vec![
            Ok(answer(&["127.0.0.1"], 60)),
            Ok(answer(&["127.0.0.1"], 60)),
        ]);
        let runtime = runtime(
            injected(Arc::clone(&fake) as Arc<dyn DnsResolver>),
            policy(100, 0, 4),
        );

        runtime.resolve("example.com").await.expect("first");
        runtime.resolve("example.com").await.expect("second");
        assert_eq!(fake.calls.load(Ordering::SeqCst), 2);
        assert_eq!(runtime.metrics.snapshot().dns_cache_hits, 0);
    }

    #[tokio::test]
    async fn caches_negative_answers() {
        let fake = Fake::new(vec![Err(DnsError::NotFound), Err(DnsError::NotFound)]);
        let runtime = runtime(
            injected(Arc::clone(&fake) as Arc<dyn DnsResolver>),
            policy(100, 8, 4),
        );

        assert!(matches!(
            runtime.resolve("example.com").await,
            Err(DnsError::NotFound)
        ));
        assert!(matches!(
            runtime.resolve("example.com").await,
            Err(DnsError::NotFound)
        ));
        assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.metrics.snapshot().dns_failures, 0);
    }

    #[tokio::test]
    async fn does_not_cache_transport_errors() {
        let fake = Fake::new(vec![Err(DnsError::Unavailable), Err(DnsError::Unavailable)]);
        let runtime = runtime(
            injected(Arc::clone(&fake) as Arc<dyn DnsResolver>),
            policy(100, 8, 4),
        );

        assert!(matches!(
            runtime.resolve("example.com").await,
            Err(DnsError::Unavailable)
        ));
        assert!(matches!(
            runtime.resolve("example.com").await,
            Err(DnsError::Unavailable)
        ));
        assert_eq!(fake.calls.load(Ordering::SeqCst), 2);
        assert_eq!(runtime.metrics.snapshot().dns_failures, 2);
    }

    #[tokio::test]
    async fn uses_fallback_after_a_transport_error() {
        let primary = Fake::new(vec![Err(DnsError::Unavailable)]);
        let fallback = Fake::new(vec![Ok(answer(&["127.0.0.1"], 60))]);
        let runtime = runtime(
            Plan::Builtin {
                primary: Arc::clone(&primary) as Arc<dyn DnsResolver>,
                fallback: Some(Arc::clone(&fallback) as Arc<dyn DnsResolver>),
            },
            policy(100, 8, 4),
        );

        let addresses = runtime.resolve("example.com").await.expect("resolve");
        assert_eq!(&*addresses, &[IpAddr::from([127, 0, 0, 1])]);
        assert_eq!(primary.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fallback.calls.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.metrics.snapshot().dns_fallbacks, 1);
    }

    #[tokio::test]
    async fn does_not_fall_back_on_not_found() {
        let primary = Fake::new(vec![Err(DnsError::NotFound)]);
        let fallback = Fake::new(vec![Ok(answer(&["127.0.0.1"], 60))]);
        let runtime = runtime(
            Plan::Builtin {
                primary: Arc::clone(&primary) as Arc<dyn DnsResolver>,
                fallback: Some(Arc::clone(&fallback) as Arc<dyn DnsResolver>),
            },
            policy(100, 8, 4),
        );

        assert!(matches!(
            runtime.resolve("example.com").await,
            Err(DnsError::NotFound)
        ));
        assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
        assert_eq!(runtime.metrics.snapshot().dns_fallbacks, 0);
    }

    #[tokio::test]
    async fn times_out_a_slow_lookup() {
        let fake: Arc<dyn DnsResolver> = Fake::delayed(Duration::from_millis(50));
        let runtime = runtime(injected(fake), policy(1, 8, 4));

        assert!(matches!(
            runtime.resolve("example.com").await,
            Err(DnsError::Timeout)
        ));
    }

    #[tokio::test]
    async fn rejects_when_in_flight_is_saturated() {
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let resolver: Arc<dyn DnsResolver> = Arc::new(Blocking {
            started: Arc::clone(&started),
            release: Arc::clone(&release),
        });
        let runtime = runtime(injected(resolver), policy(500, 8, 1));

        let first = tokio::spawn({
            let runtime = Arc::clone(&runtime);
            async move { runtime.resolve("first.test").await }
        });
        started.notified().await;
        assert!(matches!(
            runtime.resolve("second.test").await,
            Err(DnsError::Busy)
        ));
        release.notify_one();
        assert!(first.await.expect("first task").is_ok());
    }

    #[tokio::test]
    async fn deduplicates_and_caps_addresses() {
        let mut text = Vec::new();
        for octet in 1..=20 {
            text.push(format!("127.0.0.{octet}"));
        }
        let addresses: Vec<&str> = text.iter().map(String::as_str).collect();
        let mut with_duplicate = addresses.clone();
        with_duplicate.push("127.0.0.1");
        let fake = Fake::new(vec![Ok(answer(&with_duplicate, 60))]);
        let runtime = runtime(
            injected(Arc::clone(&fake) as Arc<dyn DnsResolver>),
            policy(100, 8, 4),
        );

        let resolved = runtime.resolve("example.com").await.expect("resolve");
        assert_eq!(resolved.len(), MAX_ADDRESSES);
        let mut unique = resolved.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), MAX_ADDRESSES);
    }

    #[tokio::test]
    async fn normalizes_case_and_trailing_dot() {
        let fake = Fake::new(vec![Ok(answer(&["127.0.0.1"], 60))]);
        let runtime = runtime(
            injected(Arc::clone(&fake) as Arc<dyn DnsResolver>),
            policy(100, 8, 4),
        );

        runtime.resolve("Example.COM.").await.expect("first");
        runtime.resolve("example.com").await.expect("second");
        assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn build_rejects_conflicting_resolver_and_servers() {
        let config = DnsConfig {
            servers: vec![DnsServer {
                protocol: DnsProtocol::Udp,
                address: "1.1.1.1:53".into(),
                server_name: None,
                path: None,
            }],
            ..DnsConfig::default()
        };
        let fake: Arc<dyn DnsResolver> = Fake::new(Vec::new());
        let result = DnsRuntime::build(Some(&config), Some(fake), Metrics::new(None));
        assert!(matches!(result, Err(DnsBuildError::Conflict)));
    }

    #[test]
    fn build_accepts_injected_policy_only() {
        let config = DnsConfig::default();
        let fake: Arc<dyn DnsResolver> = Fake::new(Vec::new());
        let result = DnsRuntime::build(Some(&config), Some(fake), Metrics::new(None));
        assert!(result.expect("build").is_some());
    }

    #[test]
    fn build_requires_servers_without_injection() {
        let config = DnsConfig::default();
        let result = DnsRuntime::build(Some(&config), None, Metrics::new(None));
        assert!(matches!(result, Err(DnsBuildError::Config(_))));
    }

    #[test]
    fn rejects_an_invalid_tls_server_name() {
        let server = DnsServer {
            protocol: DnsProtocol::Tls,
            address: "1.1.1.1:853".into(),
            server_name: Some("example.com:443".into()),
            path: None,
        };
        assert!(matches!(
            name_server(&server),
            Err(DnsBuildError::Config(_))
        ));
    }

    #[test]
    fn build_is_none_without_config_or_injection() {
        assert!(
            DnsRuntime::build(None, None, Metrics::new(None))
                .expect("build")
                .is_none()
        );
    }
}
