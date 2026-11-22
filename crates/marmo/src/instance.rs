//! Public instance lifecycle: build, bind, serve, shutdown.
//!
//! `Config::from_json` validates the document; `build` compiles the router,
//! rejects protocols that are not implemented yet, and captures the tokio
//! handle. `bind` performs the only startup I/O; `serve` owns every accept
//! loop and drains connections on cancellation.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use marmo_net::{Endpoint, Network};
use marmo_proto::shadowsocks::{Key, Method};
use marmo_proto::trojan::PasswordHash;
use marmo_proto::vless::Uuid;
use marmo_proto::vmess::{CmdKey, Security as VmessCipher};
use marmo_transport::h2::{H2Client, H2ClientOptions, H2Server, H2ServerOptions};
use marmo_transport::tls::{TlsClient, TlsClientOptions, TlsServer, TlsServerOptions};
use marmo_transport::ws::{WsClient, WsClientOptions, WsServer, WsServerOptions};
use marmo_transport::{
    BoxStream, Layer, RelayCounters, RelayError, RelayOptions, relay_with_counters,
};
use thiserror::Error;
use tokio::net::{TcpListener, UdpSocket};
use tokio::runtime::Handle;
use tokio::task::JoinSet;
use tokio::time::{interval, timeout};
use tokio_util::sync::CancellationToken;

use crate::config::{
    Config, ConfigError, HealthCheck, InboundProtocol, OutboundProtocol, Strategy, StreamNetwork,
    VmessSecurity,
};
use crate::deadline::Deadline;
use crate::inbound::{self, http, socks5};
use crate::limits::Limits;
use crate::metrics::{MetricEvent, Metrics, MetricsSink, MetricsSnapshot};
use crate::outbound::{self, Outbound, http_connect, udp::UdpOutbound};
use crate::process::{ProcessRequest, ProcessResolver, ProcessRuntime};
use crate::routing::{Action, Metadata, Router, RoutingError};
use crate::ruleset::{DomainSet, IpSet, RuleSets};
use crate::shadowsocks::credentials;
use crate::sniff::Policy;
use crate::supervisor::Supervisor;
use crate::vmess::ReplayFilter;

/// A built instance; no sockets are open yet.
pub struct Instance {
    runtime: Handle,
    limits: Limits,
    supervisor: Arc<Supervisor>,
    router: Arc<Router>,
    metrics: Arc<Metrics>,
    process: Option<Arc<ProcessRuntime>>,
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

    /// Binds every inbound, builds TLS configurations, and returns the
    /// running-bound state. This is the only startup step that performs I/O.
    pub async fn bind(self) -> Result<BoundInstance, BindError> {
        let Self {
            runtime,
            limits,
            supervisor,
            router,
            metrics,
            process,
            outbounds,
            inbounds,
        } = self;

        let mut specs: Vec<Option<OutboundSpec>> = outbounds.into_iter().map(Some).collect();
        let mut kinds: Vec<Option<Arc<dyn Outbound>>> = (0..specs.len()).map(|_| None).collect();
        let mut built = std::collections::HashMap::new();
        for (index, slot) in specs.iter_mut().enumerate() {
            let Some(spec) = slot.as_ref() else {
                continue;
            };
            if spec.is_selector() {
                continue;
            }
            let tag = spec.tag.to_string();
            let spec = slot.take().expect("checked above");
            let outbound = spec.build_node(&metrics)?;
            built.insert(tag, Arc::clone(&outbound));
            kinds[index] = Some(outbound);
        }
        for (index, slot) in specs.iter_mut().enumerate() {
            let Some(spec) = slot.take() else {
                continue;
            };
            kinds[index] = Some(spec.build_selector(&built, Arc::clone(&metrics))?);
        }
        let kinds: Vec<Arc<dyn Outbound>> = kinds
            .into_iter()
            .map(|kind| kind.expect("every outbound is built"))
            .collect();

        let mut bound = Vec::with_capacity(inbounds.len());
        for spec in inbounds {
            let kind = spec.config.build(&spec.tag, &metrics)?;
            let listener =
                TcpListener::bind(spec.listen)
                    .await
                    .map_err(|source| BindError::Inbound {
                        inbound: spec.tag.to_string(),
                        address: spec.listen.to_string(),
                        source,
                    })?;
            let local_addr = listener.local_addr().map_err(|source| BindError::Inbound {
                inbound: spec.tag.to_string(),
                address: spec.listen.to_string(),
                source,
            })?;
            let udp = if matches!(kind, InboundKind::Shadowsocks { .. }) {
                let socket =
                    UdpSocket::bind(local_addr)
                        .await
                        .map_err(|source| BindError::Inbound {
                            inbound: spec.tag.to_string(),
                            address: local_addr.to_string(),
                            source,
                        })?;
                Some(socket)
            } else {
                None
            };
            bound.push(BoundInbound {
                tag: spec.tag,
                kind,
                listener,
                local_addr,
                udp,
                sniffing: spec.sniffing,
            });
        }

        Ok(BoundInstance {
            runtime,
            limits,
            supervisor,
            router,
            metrics,
            process,
            outbounds: kinds,
            inbounds: bound,
        })
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
}

impl InstanceBuilder {
    /// Supplies the runtime handle explicitly. Without this, `build` uses
    /// `Handle::try_current()`.
    #[must_use]
    pub fn runtime(mut self, handle: Handle) -> Self {
        self.runtime = Some(handle);
        self
    }

    /// Overrides the drain deadline from `Config::limits`.
    #[must_use]
    pub fn shutdown_grace(mut self, grace: Duration) -> Self {
        self.shutdown_grace = Some(grace);
        self
    }

    /// Installs an optional metrics sink.
    #[must_use]
    pub fn metrics(mut self, sink: Arc<dyn MetricsSink>) -> Self {
        self.metrics = Some(sink);
        self
    }

    /// Registers a domain set for rules that use `domain_set`.
    ///
    /// The set is supplied by the embedder; the library never loads or
    /// reloads its data. Duplicate or empty tags fail at [`build`](Self::build).
    #[must_use]
    pub fn domain_set(mut self, tag: impl Into<Arc<str>>, set: Arc<dyn DomainSet>) -> Self {
        self.domain_sets.push((tag.into(), set));
        self
    }

    /// Registers an IP set for rules that use `geoip`.
    ///
    /// The set is supplied by the embedder; the library never loads or
    /// reloads its data. Duplicate or empty tags fail at [`build`](Self::build).
    #[must_use]
    pub fn ip_set(mut self, tag: impl Into<Arc<str>>, set: Arc<dyn IpSet>) -> Self {
        self.ip_sets.push((tag.into(), set));
        self
    }

    /// Installs the resolver used by `process_name` and `process_path`.
    ///
    /// The resolver is embedder code and runs on a blocking thread. Without
    /// it, a config that contains process matchers fails to build.
    #[must_use]
    pub fn process_resolver(mut self, resolver: Arc<dyn ProcessResolver>) -> Self {
        self.process_resolver = Some(resolver);
        self
    }

    /// Validates config, compiles rules, and rejects unsupported protocols.
    pub fn build(self) -> Result<Instance, BuildError> {
        self.config.validate()?;
        let runtime = match self.runtime {
            Some(handle) => handle,
            None => Handle::try_current().map_err(|_| BuildError::NoRuntime)?,
        };

        let mut limits = self.config.limits();
        if let Some(grace) = self.shutdown_grace {
            limits.shutdown_grace = grace;
        }

        let mut sets = RuleSets::new();
        for (tag, set) in self.domain_sets {
            sets.add_domain(&tag, set)
                .map_err(|error| BuildError::RuleSet {
                    tag: tag.to_string(),
                    reason: error.to_string(),
                })?;
        }
        for (tag, set) in self.ip_sets {
            sets.add_ip(&tag, set)
                .map_err(|error| BuildError::RuleSet {
                    tag: tag.to_string(),
                    reason: error.to_string(),
                })?;
        }
        let router = Router::compile_with_sets(&self.config, &sets)?;
        if router.needs_process() && self.process_resolver.is_none() {
            return Err(BuildError::MissingProcessResolver);
        }
        let process = self
            .process_resolver
            .map(|resolver| Arc::new(ProcessRuntime::new(&self.config.process, resolver)));

        let mut inbounds = Vec::with_capacity(self.config.inbounds.len());
        for inbound in &self.config.inbounds {
            let config = match inbound.protocol {
                InboundProtocol::Socks5 => InboundConfig::Socks5,
                InboundProtocol::Http => InboundConfig::Http,
                InboundProtocol::Shadowsocks => {
                    let (method, key) =
                        credentials(inbound.method.as_deref(), inbound.password.as_deref())
                            .map_err(|error| BuildError::Credentials {
                                tag: inbound.tag.clone(),
                                reason: error.to_string(),
                            })?;
                    InboundConfig::Shadowsocks { method, key }
                }
                InboundProtocol::Trojan => {
                    let Some(tls) = inbound.tls.as_ref() else {
                        return Err(BuildError::InboundOption {
                            tag: inbound.tag.clone(),
                            reason: "tls is required for trojan".into(),
                        });
                    };
                    let Some(password) = inbound.password.as_deref() else {
                        return Err(BuildError::InboundOption {
                            tag: inbound.tag.clone(),
                            reason: "password is required for trojan".into(),
                        });
                    };
                    let fallback = match inbound.fallback.as_deref() {
                        Some(text) => {
                            let endpoint =
                                Endpoint::parse(text).map_err(|_| BuildError::InboundOption {
                                    tag: inbound.tag.clone(),
                                    reason: format!("invalid fallback '{text}'"),
                                })?;
                            Some(endpoint)
                        }
                        None => None,
                    };
                    InboundConfig::Trojan {
                        password: Arc::new(PasswordHash::derive(password)),
                        tls: InboundTlsConfig::new(tls),
                        fallback,
                    }
                }
                InboundProtocol::Vless => {
                    let mut ws = None;
                    let mut h2 = None;
                    match inbound.transport.as_ref() {
                        None => {}
                        Some(transport) => match transport.network {
                            StreamNetwork::Tcp => {}
                            StreamNetwork::Ws => {
                                ws = Some(WsServerOptions {
                                    path: transport.path.clone(),
                                    subprotocols: transport
                                        .subprotocols
                                        .clone()
                                        .unwrap_or_default(),
                                    compression: transport.compression,
                                });
                            }
                            StreamNetwork::H2 => {
                                h2 = Some(H2ServerOptions {
                                    path: transport.path.clone(),
                                });
                            }
                        },
                    }
                    let Some(tls) = inbound.tls.as_ref() else {
                        return Err(BuildError::InboundOption {
                            tag: inbound.tag.clone(),
                            reason: "tls is required for vless".into(),
                        });
                    };
                    let Some(uuid) = inbound.uuid.as_deref() else {
                        return Err(BuildError::InboundOption {
                            tag: inbound.tag.clone(),
                            reason: "uuid is required for vless".into(),
                        });
                    };
                    let uuid = Uuid::parse(uuid).map_err(|_| BuildError::InboundOption {
                        tag: inbound.tag.clone(),
                        reason: "invalid vless uuid".into(),
                    })?;
                    let mut tls = InboundTlsConfig::new(tls);
                    if h2.is_some() && tls.alpn.is_empty() {
                        tls.alpn.push("h2".into());
                    }
                    InboundConfig::Vless {
                        uuid: Arc::new(uuid),
                        tls,
                        ws,
                        h2,
                    }
                }
                InboundProtocol::Vmess => {
                    let mut ws = None;
                    let mut h2 = None;
                    match inbound.transport.as_ref() {
                        None => {}
                        Some(transport) => match transport.network {
                            StreamNetwork::Tcp => {}
                            StreamNetwork::Ws => {
                                ws = Some(WsServerOptions {
                                    path: transport.path.clone(),
                                    subprotocols: transport
                                        .subprotocols
                                        .clone()
                                        .unwrap_or_default(),
                                    compression: transport.compression,
                                });
                            }
                            StreamNetwork::H2 => {
                                h2 = Some(H2ServerOptions {
                                    path: transport.path.clone(),
                                });
                            }
                        },
                    }
                    let Some(uuid) = inbound.uuid.as_deref() else {
                        return Err(BuildError::InboundOption {
                            tag: inbound.tag.clone(),
                            reason: "uuid is required for vmess".into(),
                        });
                    };
                    let uuid = Uuid::parse(uuid).map_err(|_| BuildError::InboundOption {
                        tag: inbound.tag.clone(),
                        reason: "invalid vmess uuid".into(),
                    })?;
                    let tls = inbound.tls.as_ref().map(|tls| {
                        let mut tls = InboundTlsConfig::new(tls);
                        if h2.is_some() && tls.alpn.is_empty() {
                            tls.alpn.push("h2".into());
                        }
                        tls
                    });
                    if (ws.is_some() || h2.is_some()) && tls.is_none() {
                        return Err(BuildError::InboundOption {
                            tag: inbound.tag.clone(),
                            reason: "tls is required for vmess ws/h2".into(),
                        });
                    }
                    InboundConfig::Vmess {
                        cmd_key: Arc::new(CmdKey::derive(&uuid)),
                        tls,
                        ws,
                        h2,
                    }
                }
            };
            let endpoint =
                Endpoint::parse(&inbound.listen).map_err(|_| BuildError::InboundListen {
                    tag: inbound.tag.clone(),
                    listen: inbound.listen.clone(),
                })?;
            let Some(listen) = endpoint.to_socket_addr() else {
                return Err(BuildError::InboundListen {
                    tag: inbound.tag.clone(),
                    listen: inbound.listen.clone(),
                });
            };
            inbounds.push(InboundSpec {
                tag: Arc::from(inbound.tag.as_str()),
                config,
                listen,
                sniffing: Policy::from_config(inbound.sniffing.as_ref()),
            });
        }

        let mut outbounds = Vec::with_capacity(self.config.outbounds.len());
        for outbound in &self.config.outbounds {
            let config = match outbound.protocol {
                OutboundProtocol::Direct => OutboundConfig::Direct,
                OutboundProtocol::Http => {
                    let Some(server) = outbound.server.as_deref() else {
                        return Err(BuildError::OutboundEndpoint {
                            tag: outbound.tag.clone(),
                            value: String::new(),
                        });
                    };
                    let server =
                        Endpoint::parse(server).map_err(|_| BuildError::OutboundEndpoint {
                            tag: outbound.tag.clone(),
                            value: server.to_string(),
                        })?;
                    OutboundConfig::Http { server }
                }
                OutboundProtocol::Shadowsocks => {
                    let Some(server) = outbound.server.as_deref() else {
                        return Err(BuildError::OutboundEndpoint {
                            tag: outbound.tag.clone(),
                            value: String::new(),
                        });
                    };
                    let server =
                        Endpoint::parse(server).map_err(|_| BuildError::OutboundEndpoint {
                            tag: outbound.tag.clone(),
                            value: server.to_string(),
                        })?;
                    let (method, key) =
                        credentials(outbound.method.as_deref(), outbound.password.as_deref())
                            .map_err(|error| BuildError::Credentials {
                                tag: outbound.tag.clone(),
                                reason: error.to_string(),
                            })?;
                    OutboundConfig::Shadowsocks {
                        server,
                        method,
                        key,
                    }
                }
                OutboundProtocol::Trojan => {
                    let Some(server) = outbound.server.as_deref() else {
                        return Err(BuildError::OutboundEndpoint {
                            tag: outbound.tag.clone(),
                            value: String::new(),
                        });
                    };
                    let server =
                        Endpoint::parse(server).map_err(|_| BuildError::OutboundEndpoint {
                            tag: outbound.tag.clone(),
                            value: server.to_string(),
                        })?;
                    let Some(password) = outbound.password.as_deref() else {
                        return Err(BuildError::OutboundOption {
                            tag: outbound.tag.clone(),
                            reason: "password is required for trojan".into(),
                        });
                    };
                    let Some(tls) = outbound.tls.as_ref() else {
                        return Err(BuildError::OutboundOption {
                            tag: outbound.tag.clone(),
                            reason: "tls is required for trojan".into(),
                        });
                    };
                    let tls = outbound_tls_config(tls, &server, &outbound.tag, None, None)?;
                    OutboundConfig::Trojan {
                        server,
                        password: Arc::new(PasswordHash::derive(password)),
                        tls,
                    }
                }
                OutboundProtocol::Vless => {
                    let Some(server) = outbound.server.as_deref() else {
                        return Err(BuildError::OutboundEndpoint {
                            tag: outbound.tag.clone(),
                            value: String::new(),
                        });
                    };
                    let server =
                        Endpoint::parse(server).map_err(|_| BuildError::OutboundEndpoint {
                            tag: outbound.tag.clone(),
                            value: server.to_string(),
                        })?;
                    let Some(uuid) = outbound.uuid.as_deref() else {
                        return Err(BuildError::OutboundOption {
                            tag: outbound.tag.clone(),
                            reason: "uuid is required for vless".into(),
                        });
                    };
                    let uuid = Uuid::parse(uuid).map_err(|_| BuildError::OutboundOption {
                        tag: outbound.tag.clone(),
                        reason: "invalid vless uuid".into(),
                    })?;
                    let mut ws = None;
                    let mut h2 = None;
                    match outbound.transport.as_ref() {
                        None => {}
                        Some(transport) => match transport.network {
                            StreamNetwork::Tcp => {}
                            StreamNetwork::Ws => {
                                ws = Some(WsClientOptions {
                                    host: transport_host(
                                        transport,
                                        outbound.tls.as_ref(),
                                        &server,
                                        &outbound.tag,
                                        "ws",
                                    )?,
                                    path: transport.path.clone(),
                                    subprotocols: transport
                                        .subprotocols
                                        .clone()
                                        .unwrap_or_default(),
                                    compression: transport.compression,
                                });
                            }
                            StreamNetwork::H2 => {
                                h2 = Some(H2ClientOptions {
                                    host: transport_host(
                                        transport,
                                        outbound.tls.as_ref(),
                                        &server,
                                        &outbound.tag,
                                        "h2",
                                    )?,
                                    path: transport.path.clone(),
                                });
                            }
                        },
                    }
                    let default_alpn = match (ws.as_ref(), h2.as_ref()) {
                        (_, Some(_)) => Some("h2"),
                        (Some(_), None) => Some("http/1.1"),
                        (None, None) => None,
                    };
                    let required_alpn = h2.as_ref().map(|_| "h2");
                    let tls = outbound
                        .tls
                        .as_ref()
                        .map(|tls| {
                            outbound_tls_config(
                                tls,
                                &server,
                                &outbound.tag,
                                default_alpn,
                                required_alpn,
                            )
                        })
                        .transpose()?;
                    OutboundConfig::Vless {
                        server,
                        uuid: Arc::new(uuid),
                        tls,
                        xudp: outbound.xudp,
                        mux: outbound.mux,
                        ws,
                        h2,
                    }
                }
                OutboundProtocol::Vmess => {
                    let Some(server) = outbound.server.as_deref() else {
                        return Err(BuildError::OutboundEndpoint {
                            tag: outbound.tag.clone(),
                            value: String::new(),
                        });
                    };
                    let server =
                        Endpoint::parse(server).map_err(|_| BuildError::OutboundEndpoint {
                            tag: outbound.tag.clone(),
                            value: server.to_string(),
                        })?;
                    let Some(uuid) = outbound.uuid.as_deref() else {
                        return Err(BuildError::OutboundOption {
                            tag: outbound.tag.clone(),
                            reason: "uuid is required for vmess".into(),
                        });
                    };
                    let uuid = Uuid::parse(uuid).map_err(|_| BuildError::OutboundOption {
                        tag: outbound.tag.clone(),
                        reason: "invalid vmess uuid".into(),
                    })?;
                    let mut ws = None;
                    let mut h2 = None;
                    match outbound.transport.as_ref() {
                        None => {}
                        Some(transport) => match transport.network {
                            StreamNetwork::Tcp => {}
                            StreamNetwork::Ws => {
                                ws = Some(WsClientOptions {
                                    host: transport_host(
                                        transport,
                                        outbound.tls.as_ref(),
                                        &server,
                                        &outbound.tag,
                                        "ws",
                                    )?,
                                    path: transport.path.clone(),
                                    subprotocols: transport
                                        .subprotocols
                                        .clone()
                                        .unwrap_or_default(),
                                    compression: transport.compression,
                                });
                            }
                            StreamNetwork::H2 => {
                                h2 = Some(H2ClientOptions {
                                    host: transport_host(
                                        transport,
                                        outbound.tls.as_ref(),
                                        &server,
                                        &outbound.tag,
                                        "h2",
                                    )?,
                                    path: transport.path.clone(),
                                });
                            }
                        },
                    }
                    let default_alpn = match (ws.as_ref(), h2.as_ref()) {
                        (_, Some(_)) => Some("h2"),
                        (Some(_), None) => Some("http/1.1"),
                        (None, None) => None,
                    };
                    let required_alpn = h2.as_ref().map(|_| "h2");
                    let tls = outbound
                        .tls
                        .as_ref()
                        .map(|tls| {
                            outbound_tls_config(
                                tls,
                                &server,
                                &outbound.tag,
                                default_alpn,
                                required_alpn,
                            )
                        })
                        .transpose()?;
                    let security = match outbound.security.unwrap_or_default() {
                        VmessSecurity::Aes128Gcm => VmessCipher::Aes128Gcm,
                        VmessSecurity::ChaCha20Poly1305 => VmessCipher::ChaCha20Poly1305,
                    };
                    OutboundConfig::Vmess {
                        server,
                        cmd_key: Arc::new(CmdKey::derive(&uuid)),
                        security,
                        mux: outbound.mux,
                        tls,
                        ws,
                        h2,
                    }
                }
                OutboundProtocol::Selector => OutboundConfig::Selector {
                    nodes: outbound.nodes.clone().unwrap_or_default(),
                    strategy: outbound.strategy.unwrap_or(Strategy::Manual),
                    health_check: outbound.health_check.clone(),
                },
            };
            outbounds.push(OutboundSpec {
                tag: Arc::from(outbound.tag.as_str()),
                config,
            });
        }

        let supervisor = Arc::new(Supervisor::new(limits.max_connections));
        let metrics = Arc::new(Metrics::new(self.metrics));
        Ok(Instance {
            runtime,
            limits,
            supervisor,
            router: Arc::new(router),
            metrics,
            process,
            outbounds,
            inbounds,
        })
    }
}

/// Records a closed connection even if the handler future is aborted.
struct ConnectionGuard(Arc<Metrics>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.record(MetricEvent::ConnectionClosed);
    }
}

/// Aborts outbound background tasks when serving ends or the future is dropped.
#[derive(Default)]
struct BackgroundTasks(Vec<tokio::task::JoinHandle<()>>);

impl BackgroundTasks {
    fn abort_all(&mut self) {
        for task in self.0.drain(..) {
            task.abort();
        }
    }
}

impl Drop for BackgroundTasks {
    fn drop(&mut self) {
        self.abort_all();
    }
}

/// A bound instance: listeners are open, no accept loop has started.
pub struct BoundInstance {
    runtime: Handle,
    limits: Limits,
    supervisor: Arc<Supervisor>,
    router: Arc<Router>,
    metrics: Arc<Metrics>,
    process: Option<Arc<ProcessRuntime>>,
    outbounds: Vec<Arc<dyn Outbound>>,
    inbounds: Vec<BoundInbound>,
}

impl BoundInstance {
    /// Returns the bound address of every listener: TCP per inbound, plus UDP
    /// for protocols that serve both.
    pub fn local_addrs(&self) -> impl Iterator<Item = BoundAddr<'_>> {
        self.inbounds.iter().flat_map(|inbound| {
            let tcp = BoundAddr {
                tag: inbound.tag.as_ref(),
                network: Network::Tcp,
                addr: inbound.local_addr,
            };
            let udp = inbound
                .udp
                .as_ref()
                .and_then(|socket| socket.local_addr().ok())
                .map(|addr| BoundAddr {
                    tag: inbound.tag.as_ref(),
                    network: Network::Udp,
                    addr,
                });
            std::iter::once(tcp).chain(udp)
        })
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

    /// Accepts until the handle shuts down or a listener fails.
    pub async fn serve(self) -> Result<(), ServeError> {
        let supervisor = Arc::clone(&self.supervisor);
        let runtime = self.runtime.clone();
        let limits = self.limits;
        let context = Arc::new(Context {
            runtime: runtime.clone(),
            supervisor: Arc::clone(&supervisor),
            router: self.router,
            metrics: self.metrics,
            process: self.process,
            direct: Arc::new(crate::direct::DirectOutbound),
            outbounds: self.outbounds,
            limits,
        });
        let token = supervisor.token();
        let mut background = BackgroundTasks::default();
        for outbound in &context.outbounds {
            if let Some(task) = outbound.start(&context.runtime, &token) {
                background.0.push(task);
            }
            if let Some(task) = outbound.start_health(&context.runtime, &token) {
                background.0.push(task);
            }
        }

        let mut tasks = JoinSet::new();
        for inbound in self.inbounds {
            let context = Arc::clone(&context);
            let _ = tasks.spawn_on(serve_inbound(inbound, context), &runtime);
        }

        let mut fatal = None;
        while !tasks.is_empty() {
            tokio::select! {
                _ = token.cancelled() => break,
                result = tasks.join_next() => match result {
                    Some(Ok(Ok(()))) => {}
                    Some(Ok(Err(error))) => {
                        fatal = Some(error);
                        supervisor.cancel();
                        break;
                    }
                    Some(Err(error)) => {
                        fatal = Some(ServeError::Task(error.to_string()));
                        supervisor.cancel();
                        break;
                    }
                    None => break,
                }
            }
        }

        supervisor.cancel();
        background.abort_all();
        let grace = limits.shutdown_grace;
        let drain = async { while tasks.join_next().await.is_some() {} };
        if timeout(grace, drain).await.is_err() {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }
        match fatal {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Like [`BoundInstance::serve`], but also stops when `shutdown` resolves.
    pub async fn serve_with_shutdown<F>(self, shutdown: F) -> Result<(), ServeError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let token = self.supervisor.token();
        let serve = self.serve();
        tokio::pin!(serve);
        tokio::select! {
            result = &mut serve => result,
            _ = shutdown => {
                token.cancel();
                serve.await
            }
        }
    }
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

pub(crate) struct Context {
    pub(crate) runtime: Handle,
    pub(crate) supervisor: Arc<Supervisor>,
    pub(crate) router: Arc<Router>,
    pub(crate) metrics: Arc<Metrics>,
    pub(crate) process: Option<Arc<ProcessRuntime>>,
    pub(crate) direct: Arc<dyn Outbound>,
    pub(crate) outbounds: Vec<Arc<dyn Outbound>>,
    pub(crate) limits: Limits,
}

impl Context {
    pub(crate) async fn route(&self, mut metadata: Metadata<'_>) -> Action {
        if self.router.needs_process() && metadata.process.is_none() {
            if let Some(process) = self.process.as_ref() {
                let request = ProcessRequest {
                    network: metadata.network,
                    source: metadata.source.clone(),
                    destination: metadata.destination.clone(),
                };
                metadata.process = process.lookup(&self.runtime, request).await;
            }
        }
        self.router.route(&metadata)
    }

    pub(crate) fn udp_direct(&self, action: Action) -> bool {
        match action {
            Action::Direct => self.direct.udp_direct(),
            Action::Route(id) => self
                .outbounds
                .get(id.index() as usize)
                .is_some_and(|outbound| outbound.udp_direct()),
            Action::Reject(_) => false,
        }
    }

    pub(crate) async fn connect(
        &self, action: Action, target: &Endpoint,
    ) -> io::Result<outbound::Connected> {
        match action {
            Action::Direct => self.direct.connect(target).await,
            Action::Route(id) => match self.outbounds.get(id.index() as usize) {
                Some(outbound) => outbound.connect(target).await,
                None => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "outbound id is out of range",
                )),
            },
            Action::Reject(_) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "route rejected the connection",
            )),
        }
    }

    /// Relays a TCP pair with the instance limits and cancellation.
    pub(crate) async fn relay_streams(
        &self, client: BoxStream, remote: BoxStream, token: &CancellationToken,
    ) {
        let options = RelayOptions {
            idle_timeout: self.limits.idle_timeout,
            uplink_grace: self.limits.uplink_grace,
            downlink_grace: self.limits.downlink_grace,
        };
        let counters = Arc::new(RelayCounters::default());
        let result = tokio::select! {
            _ = token.cancelled() => None,
            result = relay_with_counters(
                client,
                remote,
                options,
                Arc::clone(&counters),
            ) => Some(result),
        };
        let stats = counters.snapshot();
        if stats.client_to_remote != 0 || stats.remote_to_client != 0 {
            self.metrics.record(MetricEvent::BytesRelayed {
                client_to_remote: stats.client_to_remote,
                remote_to_client: stats.remote_to_client,
            });
        }
        if let Some(Err(RelayError::Idle | RelayError::HalfClose)) = result {
            self.metrics.record(MetricEvent::RelayTimeout);
        }
    }

    /// Opens a datagram path for `action`, or `None` when it has no UDP.
    ///
    /// `target` seeds protocols whose association header carries a
    /// destination, such as Trojan UDP ASSOCIATE.
    pub(crate) async fn udp_outbound(
        &self, action: Action, ipv4: bool, target: &Endpoint,
    ) -> io::Result<Option<UdpOutbound>> {
        match action {
            Action::Direct => self.direct.connect_datagram(target, ipv4).await,
            Action::Route(id) => match self.outbounds.get(id.index() as usize) {
                Some(outbound) => outbound.connect_datagram(target, ipv4).await,
                None => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "outbound id is out of range",
                )),
            },
            Action::Reject(_) => Ok(None),
        }
    }
}

#[derive(Clone)]
enum InboundKind {
    Socks5,
    Http,
    Shadowsocks {
        method: Method,
        key: Arc<Key>,
    },
    Trojan {
        password: Arc<PasswordHash>,
        tls: Arc<TlsServer>,
        fallback: Option<Endpoint>,
    },
    Vless {
        uuid: Arc<Uuid>,
        layers: Arc<[Arc<dyn Layer>]>,
    },
    Vmess {
        cmd_key: Arc<CmdKey>,
        replay: Arc<Mutex<ReplayFilter>>,
        layers: Arc<[Arc<dyn Layer>]>,
    },
}

struct InboundSpec {
    tag: Arc<str>,
    config: InboundConfig,
    listen: SocketAddr,
    sniffing: Option<Policy>,
}

enum InboundConfig {
    Socks5,
    Http,
    Shadowsocks {
        method: Method,
        key: Arc<Key>,
    },
    Trojan {
        password: Arc<PasswordHash>,
        tls: InboundTlsConfig,
        fallback: Option<Endpoint>,
    },
    Vless {
        uuid: Arc<Uuid>,
        tls: InboundTlsConfig,
        ws: Option<WsServerOptions>,
        h2: Option<H2ServerOptions>,
    },
    Vmess {
        cmd_key: Arc<CmdKey>,
        tls: Option<InboundTlsConfig>,
        ws: Option<WsServerOptions>,
        h2: Option<H2ServerOptions>,
    },
}

struct InboundTlsConfig {
    certificate: String,
    private_key: String,
    alpn: Vec<String>,
    client_ca: Option<String>,
    client_auth: crate::config::ClientAuth,
    handshake_timeout: Duration,
}

impl InboundTlsConfig {
    fn new(tls: &crate::config::InboundTls) -> Self {
        Self {
            certificate: tls.certificate.clone(),
            private_key: tls.private_key.clone(),
            alpn: tls.alpn.clone().unwrap_or_default(),
            client_ca: tls.client_ca.clone(),
            client_auth: tls.client_auth,
            handshake_timeout: Duration::from_secs(u64::from(tls.handshake_timeout_s)),
        }
    }
}

impl InboundConfig {
    fn build(self, tag: &str, metrics: &Arc<Metrics>) -> Result<InboundKind, BindError> {
        Ok(match self {
            Self::Socks5 => InboundKind::Socks5,
            Self::Http => InboundKind::Http,
            Self::Shadowsocks { method, key } => InboundKind::Shadowsocks { method, key },
            Self::Trojan {
                password,
                tls,
                fallback,
            } => InboundKind::Trojan {
                password,
                tls: build_tls_server(&tls, tag, metrics)?,
                fallback,
            },
            Self::Vless { uuid, tls, ws, h2 } => {
                let mut layers: Vec<Arc<dyn Layer>> = Vec::new();
                layers.push(build_tls_server(&tls, tag, metrics)?);
                if let Some(options) = ws {
                    layers.push(Arc::new(WsServer::new(options)));
                }
                if let Some(options) = h2 {
                    layers.push(Arc::new(H2Server::new(options)));
                }
                InboundKind::Vless {
                    uuid,
                    layers: Arc::from(layers),
                }
            }
            Self::Vmess {
                cmd_key,
                tls,
                ws,
                h2,
            } => {
                let mut layers: Vec<Arc<dyn Layer>> = Vec::new();
                if let Some(tls) = tls.as_ref() {
                    layers.push(build_tls_server(tls, tag, metrics)?);
                }
                if let Some(options) = ws {
                    layers.push(Arc::new(WsServer::new(options)));
                }
                if let Some(options) = h2 {
                    layers.push(Arc::new(H2Server::new(options)));
                }
                InboundKind::Vmess {
                    cmd_key,
                    replay: Arc::new(Mutex::new(ReplayFilter::new())),
                    layers: Arc::from(layers),
                }
            }
        })
    }
}

struct OutboundSpec {
    tag: Arc<str>,
    config: OutboundConfig,
}

enum OutboundConfig {
    Direct,
    Http {
        server: Endpoint,
    },
    Shadowsocks {
        server: Endpoint,
        method: Method,
        key: Arc<Key>,
    },
    Trojan {
        server: Endpoint,
        password: Arc<PasswordHash>,
        tls: OutboundTlsConfig,
    },
    Vless {
        server: Endpoint,
        uuid: Arc<Uuid>,
        tls: Option<OutboundTlsConfig>,
        xudp: bool,
        mux: bool,
        ws: Option<WsClientOptions>,
        h2: Option<H2ClientOptions>,
    },
    Vmess {
        server: Endpoint,
        cmd_key: Arc<CmdKey>,
        security: VmessCipher,
        mux: bool,
        tls: Option<OutboundTlsConfig>,
        ws: Option<WsClientOptions>,
        h2: Option<H2ClientOptions>,
    },
    Selector {
        nodes: Vec<String>,
        strategy: Strategy,
        health_check: Option<HealthCheck>,
    },
}

struct OutboundTlsConfig {
    server_name: String,
    alpn: Vec<String>,
    required_alpn: Option<String>,
    insecure: bool,
    client_certificate: Option<String>,
    client_private_key: Option<String>,
    handshake_timeout: Duration,
}

impl OutboundSpec {
    fn is_selector(&self) -> bool {
        matches!(self.config, OutboundConfig::Selector { .. })
    }

    fn build_node(self, metrics: &Arc<Metrics>) -> Result<Arc<dyn Outbound>, BindError> {
        let Self { tag, config } = self;
        Ok(match config {
            OutboundConfig::Direct => Arc::new(crate::direct::DirectOutbound),
            OutboundConfig::Http { server } => Arc::new(http_connect::HttpOutbound { server }),
            OutboundConfig::Shadowsocks {
                server,
                method,
                key,
            } => Arc::new(outbound::shadowsocks::ShadowsocksOutbound {
                server,
                method,
                key,
            }),
            OutboundConfig::Trojan {
                server,
                password,
                tls,
            } => Arc::new(outbound::trojan::TrojanOutbound {
                server,
                password,
                tls: build_tls_client(&tls, &tag, metrics)?,
            }),
            OutboundConfig::Vless {
                server,
                uuid,
                tls,
                xudp,
                mux,
                ws,
                h2,
            } => {
                let mut layers: Vec<Arc<dyn Layer>> = Vec::new();
                if let Some(tls) = tls.as_ref() {
                    layers.push(build_tls_client(tls, &tag, metrics)?);
                }
                if let Some(options) = ws {
                    layers.push(Arc::new(WsClient::new(options)));
                }
                if let Some(options) = h2 {
                    layers.push(Arc::new(H2Client::new(options)));
                }
                Arc::new(outbound::vless::VlessOutbound {
                    server,
                    uuid,
                    xudp,
                    mux,
                    layers,
                    pool: OnceLock::new(),
                })
            }
            OutboundConfig::Vmess {
                server,
                cmd_key,
                security,
                mux,
                tls,
                ws,
                h2,
            } => {
                let mut layers: Vec<Arc<dyn Layer>> = Vec::new();
                if let Some(tls) = tls.as_ref() {
                    layers.push(build_tls_client(tls, &tag, metrics)?);
                }
                if let Some(options) = ws {
                    layers.push(Arc::new(WsClient::new(options)));
                }
                if let Some(options) = h2 {
                    layers.push(Arc::new(H2Client::new(options)));
                }
                Arc::new(outbound::vmess::VmessOutbound {
                    server,
                    cmd_key,
                    security,
                    mux,
                    layers,
                    pool: OnceLock::new(),
                })
            }
            OutboundConfig::Selector { .. } => {
                unreachable!("selectors are built in the second pass")
            }
        })
    }

    fn build_selector(
        self, built: &std::collections::HashMap<String, Arc<dyn Outbound>>, metrics: Arc<Metrics>,
    ) -> Result<Arc<dyn Outbound>, BindError> {
        let Self { tag, config } = self;
        let OutboundConfig::Selector {
            nodes,
            strategy,
            health_check,
        } = config
        else {
            unreachable!("non-selectors are built in the first pass");
        };
        let mut resolved = Vec::with_capacity(nodes.len());
        for node in nodes {
            let Some(outbound) = built.get(&node) else {
                return Err(BindError::Selector {
                    tag: tag.to_string(),
                    reason: format!("unknown selector node '{node}'"),
                });
            };
            resolved.push(Arc::clone(outbound));
        }
        Ok(Arc::new(outbound::selector::SelectorOutbound::new(
            tag.to_string(),
            metrics,
            resolved,
            strategy,
            health_check,
        )))
    }
}

fn transport_host(
    transport: &crate::config::StreamTransport, tls: Option<&crate::config::Tls>,
    server: &Endpoint, tag: &str, kind: &str,
) -> Result<String, BuildError> {
    transport
        .host
        .clone()
        .or_else(|| tls.and_then(|tls| tls.sni.clone()))
        .or_else(|| server.domain().map(str::to_owned))
        .or_else(|| server.ip().map(host_from_ip))
        .ok_or_else(|| BuildError::OutboundOption {
            tag: tag.to_owned(),
            reason: format!("{kind} host is missing"),
        })
}

fn host_from_ip(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(address) => address.to_string(),
        std::net::IpAddr::V6(address) => format!("[{address}]"),
    }
}

fn build_tls_server(
    tls: &InboundTlsConfig, tag: &str, metrics: &Arc<Metrics>,
) -> Result<Arc<TlsServer>, BindError> {
    let options = TlsServerOptions {
        certificate: &tls.certificate,
        private_key: &tls.private_key,
        alpn: &tls.alpn,
        client_ca: tls.client_ca.as_deref(),
        client_auth: transport_client_auth(tls.client_auth),
        handshake_timeout: Some(tls.handshake_timeout),
    };
    let server = TlsServer::new(&options).map_err(|error| BindError::Tls {
        tag: tag.to_owned(),
        reason: error.to_string(),
    })?;
    let metrics = Arc::clone(metrics);
    Ok(Arc::new(server.with_timeout_observer(Arc::new(
        move || {
            metrics.record(MetricEvent::HandshakeTimeout);
        },
    ))))
}

fn build_tls_client(
    tls: &OutboundTlsConfig, tag: &str, metrics: &Arc<Metrics>,
) -> Result<Arc<TlsClient>, BindError> {
    let options = TlsClientOptions {
        server_name: &tls.server_name,
        alpn: &tls.alpn,
        required_alpn: tls.required_alpn.as_deref(),
        insecure: tls.insecure,
        client_certificate: tls.client_certificate.as_deref(),
        client_private_key: tls.client_private_key.as_deref(),
        handshake_timeout: Some(tls.handshake_timeout),
    };
    let client = TlsClient::new(&options).map_err(|error| BindError::Tls {
        tag: tag.to_owned(),
        reason: error.to_string(),
    })?;
    let metrics = Arc::clone(metrics);
    Ok(Arc::new(client.with_timeout_observer(Arc::new(
        move || {
            metrics.record(MetricEvent::HandshakeTimeout);
        },
    ))))
}

fn outbound_tls_config(
    tls: &crate::config::Tls, server: &Endpoint, tag: &str, default_alpn: Option<&str>,
    required_alpn: Option<&str>,
) -> Result<OutboundTlsConfig, BuildError> {
    let server_name = tls
        .sni
        .clone()
        .or_else(|| server.domain().map(str::to_owned))
        .or_else(|| server.ip().map(|ip| ip.to_string()))
        .ok_or_else(|| BuildError::OutboundOption {
            tag: tag.to_owned(),
            reason: "tls.sni is required".into(),
        })?;
    let alpn = match tls.alpn.clone() {
        Some(alpn) => alpn,
        None => default_alpn.map(str::to_owned).into_iter().collect(),
    };
    Ok(OutboundTlsConfig {
        server_name,
        alpn,
        required_alpn: tls
            .required_alpn
            .clone()
            .or_else(|| required_alpn.map(str::to_owned)),
        insecure: tls.insecure,
        client_certificate: tls.client_certificate.clone(),
        client_private_key: tls.client_private_key.clone(),
        handshake_timeout: Duration::from_secs(u64::from(tls.handshake_timeout_s)),
    })
}

fn transport_client_auth(auth: crate::config::ClientAuth) -> marmo_transport::tls::ClientAuth {
    match auth {
        crate::config::ClientAuth::None => marmo_transport::tls::ClientAuth::None,
        crate::config::ClientAuth::Optional => marmo_transport::tls::ClientAuth::Optional,
        crate::config::ClientAuth::Required => marmo_transport::tls::ClientAuth::Required,
    }
}

struct BoundInbound {
    tag: Arc<str>,
    kind: InboundKind,
    listener: TcpListener,
    local_addr: SocketAddr,
    udp: Option<UdpSocket>,
    sniffing: Option<Policy>,
}

async fn serve_inbound(mut inbound: BoundInbound, context: Arc<Context>) -> Result<(), ServeError> {
    let token = context.supervisor.token();
    let mut connections = JoinSet::new();
    let mut reap = interval(Duration::from_secs(1));
    let mut fatal = None;
    let runtime = context.runtime.clone();

    if let Some(socket) = inbound.udp.take() {
        if let InboundKind::Shadowsocks { method, key } = &inbound.kind {
            let udp_context = Arc::clone(&context);
            let tag = Arc::clone(&inbound.tag);
            let (method, key) = (*method, Arc::clone(key));
            let _ = connections.spawn_on(
                inbound::shadowsocks_udp::serve(socket, udp_context, tag, method, key),
                &runtime,
            );
        }
    }

    loop {
        while connections.try_join_next().is_some() {}
        tokio::select! {
            _ = token.cancelled() => break,
            _ = reap.tick() => {
                while connections.try_join_next().is_some() {}
            }
            accepted = inbound.listener.accept() => {
                let (stream, _peer) = match accepted {
                    Ok(pair) => pair,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::ConnectionAborted | io::ErrorKind::Interrupted
                        ) =>
                    {
                        continue;
                    }
                    Err(source) => {
                        fatal = Some(ServeError::Accept {
                            inbound: inbound.tag.to_string(),
                            source,
                        });
                        break;
                    }
                };

                let Some(permit) = context.supervisor.try_acquire() else {
                    context.metrics.record(MetricEvent::ConnectionRejected);
                    drop(stream);
                    continue;
                };
                context.metrics.record(MetricEvent::ConnectionAccepted);
                let tag = Arc::clone(&inbound.tag);
                let kind = inbound.kind.clone();
                let sniffing = inbound.sniffing;
                let task_context = Arc::clone(&context);
                let deadline = Deadline::after(
                    context.limits.handshake_timeout,
                    Arc::clone(&context.metrics),
                );
                let guard = ConnectionGuard(Arc::clone(&context.metrics));
                let runtime = context.runtime.clone();
                let _ = connections.spawn_on(async move {
                    let _permit = permit;
                    let _guard = guard;
                    match kind {
                        InboundKind::Socks5 => {
                            socks5::handle(stream, task_context, tag, sniffing, deadline).await;
                        }
                        InboundKind::Http => {
                            http::handle(stream, task_context, tag, sniffing, deadline).await;
                        }
                        InboundKind::Shadowsocks { method, key } => {
                            inbound::shadowsocks::handle(
                                stream,
                                task_context,
                                tag,
                                method,
                                key,
                                sniffing,
                                deadline,
                            )
                            .await;
                        }
                        InboundKind::Trojan {
                            password,
                            tls,
                            fallback,
                        } => {
                            inbound::trojan::handle(
                                stream,
                                task_context,
                                tag,
                                tls,
                                password,
                                fallback,
                                sniffing,
                                deadline,
                            )
                            .await;
                        }
                        InboundKind::Vless { uuid, layers } => {
                            inbound::vless::handle(
                                stream,
                                task_context,
                                tag,
                                uuid,
                                layers,
                                sniffing,
                                deadline,
                            )
                            .await;
                        }
                        InboundKind::Vmess {
                            cmd_key,
                            replay,
                            layers,
                        } => {
                            inbound::vmess::handle(
                                stream,
                                task_context,
                                tag,
                                cmd_key,
                                replay,
                                layers,
                                sniffing,
                                deadline,
                            )
                            .await;
                        }
                    }
                }, &runtime);
            }
        }
    }

    let grace = context.limits.shutdown_grace;
    let drain = async { while connections.join_next().await.is_some() {} };
    if timeout(grace, drain).await.is_err() {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    match fatal {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Why an instance could not be built.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BuildError {
    /// The configuration failed validation.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// The routing rules could not be compiled.
    #[error(transparent)]
    Routing(#[from] RoutingError),
    /// The configuration has process matchers but no resolver was injected.
    #[error("process rules require .process_resolver(...)")]
    MissingProcessResolver,
    /// A rule-set tag could not be registered.
    #[error("rule set '{tag}' registration failed: {reason}")]
    RuleSet {
        /// The rejected tag.
        tag: String,
        /// Why registration failed.
        reason: String,
    },
    /// No tokio runtime was supplied and none is current.
    #[error("no tokio runtime; call .runtime(handle) or build inside a runtime")]
    NoRuntime,
    /// The inbound protocol is not implemented yet.
    #[error("inbound '{tag}' protocol {protocol:?} is not implemented")]
    UnsupportedInbound {
        /// Inbound tag.
        tag: String,
        /// Configured protocol.
        protocol: InboundProtocol,
    },
    /// The listen endpoint is not an IP literal.
    #[error("inbound '{tag}' listen is not an IP endpoint: {listen}")]
    InboundListen {
        /// Inbound tag.
        tag: String,
        /// Configured listen string.
        listen: String,
    },
    /// The outbound server endpoint is missing or invalid.
    #[error("outbound '{tag}' has an invalid server: {value}")]
    OutboundEndpoint {
        /// Outbound tag.
        tag: String,
        /// Configured server string.
        value: String,
    },
    /// An inbound option could not be used.
    #[error("inbound '{tag}' has an invalid option: {reason}")]
    InboundOption {
        /// Inbound tag.
        tag: String,
        /// Why the option was rejected.
        reason: String,
    },
    /// An outbound option could not be used.
    #[error("outbound '{tag}' has an invalid option: {reason}")]
    OutboundOption {
        /// Outbound tag.
        tag: String,
        /// Why the option was rejected.
        reason: String,
    },
    /// The configured credentials could not be used.
    #[error("'{tag}' has invalid credentials: {reason}")]
    Credentials {
        /// Inbound or outbound tag.
        tag: String,
        /// Why the credentials were rejected.
        reason: String,
    },
}

/// Why binding failed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BindError {
    /// A selector graph was rejected while binding.
    #[error("selector '{tag}' failed: {reason}")]
    Selector {
        /// Selector tag.
        tag: String,
        /// Why the selector was rejected.
        reason: String,
    },
    /// A TLS configuration was rejected while binding.
    #[error("'{tag}' TLS setup failed: {reason}")]
    Tls {
        /// Inbound or outbound tag.
        tag: String,
        /// Why the TLS configuration was rejected.
        reason: String,
    },
    /// One inbound could not bind.
    #[error("inbound '{inbound}' failed to bind {address}: {source}")]
    Inbound {
        /// Inbound tag.
        inbound: String,
        /// Configured address.
        address: String,
        /// Underlying socket error.
        #[source]
        source: io::Error,
    },
}

/// Why serving stopped with an error.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ServeError {
    /// Binding failed before serving started.
    #[error(transparent)]
    Bind(#[from] BindError),
    /// A listener could not accept.
    #[error("inbound '{inbound}' accept failed: {source}")]
    Accept {
        /// Inbound tag.
        inbound: String,
        /// Underlying socket error.
        #[source]
        source: io::Error,
    },
    /// An inbound task panicked.
    #[error("inbound task failed: {0}")]
    Task(String),
}
