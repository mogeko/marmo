//! Public instance lifecycle: build, bind, serve, shutdown.
//!
//! `Config::from_json` validates the document; `build` compiles the router,
//! checks protocol-specific build constraints, and captures the tokio
//! handle. `bind` performs the only startup I/O; `serve` owns every accept
//! loop and drains connections on cancellation.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use marmo_net::Network;
use tokio::runtime::Handle;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::direct::Dialer;
use crate::dns::DnsRuntime;
use crate::limits::RuntimeLimits;
use crate::metrics::{Metrics, MetricsSink, MetricsSnapshot};
use crate::outbound::Outbound;
use crate::process::{ProcessResolver, ProcessRuntime};
use crate::routing::Router;
use crate::ruleset::{DomainSet, IpSet};
use crate::supervisor::Supervisor;

mod build;
mod context;
mod error;
mod serve;

pub(crate) use context::{Context, InboundSpec, OutboundSpec};
pub use error::{BindError, BuildError, ServeError};
use serve::BoundInbound;

/// A built instance; no sockets are open yet.
pub struct Instance {
    runtime: Handle,
    limits: RuntimeLimits,
    supervisor: Arc<Supervisor>,
    router: Arc<Router>,
    metrics: Arc<Metrics>,
    process: Option<Arc<ProcessRuntime>>,
    dns: Option<Arc<DnsRuntime>>,
    outbounds: Vec<OutboundSpec>,
    inbounds: Vec<InboundSpec>,
}

impl Instance {
    /// Starts a builder. `build()` is pure: it performs no I/O.
    #[must_use]
    pub fn builder(config: Config) -> InstanceBuilder {
        InstanceBuilder {
            config,
            runtime: None,
            shutdown_grace: None,
            metrics: None,
            domain_sets: Vec::new(),
            ip_sets: Vec::new(),
            process_resolver: None,
            #[cfg(feature = "dns")]
            dns_resolver: None,
        }
    }

    /// Returns a cloneable control handle.
    #[must_use]
    pub fn handle(&self) -> InstanceHandle {
        InstanceHandle {
            token: self.supervisor.token(),
            metrics: Arc::clone(&self.metrics),
        }
    }

    /// Returns a point-in-time copy of the instance counters.
    #[must_use]
    pub fn metrics(&self) -> MetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Binds and serves until [`InstanceHandle::shutdown`].
    pub async fn serve(self) -> Result<(), ServeError> {
        self.bind().await?.serve().await
    }

    /// Binds and serves until `shutdown` resolves or the handle is shut down.
    pub async fn serve_with_shutdown<F>(self, shutdown: F) -> Result<(), ServeError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.bind().await?.serve_with_shutdown(shutdown).await
    }
}

/// Builder for [`Instance`].
pub struct InstanceBuilder {
    config: Config,
    runtime: Option<Handle>,
    shutdown_grace: Option<Duration>,
    metrics: Option<Arc<dyn MetricsSink>>,
    domain_sets: Vec<(Arc<str>, Arc<dyn DomainSet>)>,
    ip_sets: Vec<(Arc<str>, Arc<dyn IpSet>)>,
    process_resolver: Option<Arc<dyn ProcessResolver>>,
    #[cfg(feature = "dns")]
    dns_resolver: Option<Arc<dyn crate::dns::DnsResolver>>,
}

/// A bound instance: listeners are open, no accept loop has started.
pub struct BoundInstance {
    runtime: Handle,
    limits: RuntimeLimits,
    supervisor: Arc<Supervisor>,
    router: Arc<Router>,
    metrics: Arc<Metrics>,
    process: Option<Arc<ProcessRuntime>>,
    dialer: Dialer,
    outbounds: Vec<Arc<dyn Outbound>>,
    inbounds: Vec<BoundInbound>,
}

/// A cloneable shutdown handle.
#[derive(Clone)]
pub struct InstanceHandle {
    token: CancellationToken,
    metrics: Arc<Metrics>,
}

impl InstanceHandle {
    /// Requests shutdown. Non-blocking and idempotent.
    pub fn shutdown(&self) {
        self.token.cancel();
    }

    /// Returns true after shutdown was requested.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.token.is_cancelled()
    }

    /// Returns a point-in-time copy of the instance counters.
    #[must_use]
    pub fn metrics(&self) -> MetricsSnapshot {
        self.metrics.snapshot()
    }
}

/// A bound listener address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundAddr<'a> {
    /// Inbound tag.
    pub tag: &'a str,
    /// Transport network.
    pub network: Network,
    /// Bound socket address.
    pub addr: SocketAddr,
}
