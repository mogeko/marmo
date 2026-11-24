//! Pure build steps: configuration compilation and listener binding.

use std::sync::Arc;
use std::time::Duration;

use marmo_proto::trojan::PasswordHash;
use marmo_proto::vmess::{CmdKey, Security as VmessCipher};
use tokio::net::{TcpListener, UdpSocket};
use tokio::runtime::Handle;

use crate::config::{Inbound, Outbound as ConfigOutbound, VmessSecurity};
use crate::direct::Dialer;
use crate::dns::DnsRuntime;
use crate::metrics::{Metrics, MetricsSink};
use crate::outbound::Outbound;
use crate::process::{ProcessResolver, ProcessRuntime};
use crate::routing::Router;
use crate::ruleset::{DomainSet, IpSet, RuleSets};
use crate::shadowsocks::credentials;
use crate::sniff::Policy;
use crate::supervisor::Supervisor;

use super::context::{
    InboundConfig, InboundKind, InboundSpec, InboundTlsConfig, OutboundConfig, OutboundSpec,
    client_transport, outbound_tls_config, server_transport, transport_default_alpn,
};
use super::serve::BoundInbound;
use super::{BindError, BoundInstance, BuildError, Instance, InstanceBuilder};

impl Instance {
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
            dns,
            outbounds,
            inbounds,
        } = self;

        let dialer = Dialer::new(dns);
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
            let outbound = spec.build_node(&metrics, &dialer)?;
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
            dialer,
            outbounds: kinds,
            inbounds: bound,
        })
    }
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

    /// Installs an embedder DNS resolver.
    ///
    /// The resolver replaces the built-in hickory upstream. The library still
    /// applies its cache, timeout, in-flight limit, deduplication, and address
    /// cap. When this is set, `dns.servers`, `dns.fallback`, and `dns.tls` must
    /// be absent; the `dns` block may still supply policy fields.
    #[cfg(feature = "dns")]
    #[must_use]
    pub fn dns_resolver(mut self, resolver: Arc<dyn crate::dns::DnsResolver>) -> Self {
        self.dns_resolver = Some(resolver);
        self
    }

    /// Validates config, compiles rules, and rejects unsupported protocols.
    pub fn build(self) -> Result<Instance, BuildError> {
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
            .map(|resolver| Arc::new(ProcessRuntime::new(&self.config.inner.process, resolver)));

        let mut inbounds = Vec::with_capacity(self.config.inner.inbounds.len());
        for inbound in &self.config.inner.inbounds {
            let tag = inbound.tag();
            let config = match inbound {
                Inbound::Socks5 { .. } => InboundConfig::Socks5,
                Inbound::Http { .. } => InboundConfig::Http,
                Inbound::Shadowsocks {
                    method, password, ..
                } => {
                    let (method, key) = credentials(Some(method.as_str()), Some(password.expose()))
                        .map_err(|error| BuildError::Credentials {
                            tag: tag.to_owned(),
                            reason: error.to_string(),
                        })?;
                    InboundConfig::Shadowsocks { method, key }
                }
                Inbound::Trojan {
                    password,
                    tls,
                    fallback,
                    ..
                } => InboundConfig::Trojan {
                    password: Arc::new(PasswordHash::derive(password.expose())),
                    tls: InboundTlsConfig::new(tls),
                    fallback: fallback.clone(),
                },
                Inbound::Vless {
                    uuid,
                    tls,
                    transport,
                    ..
                } => {
                    let (ws, h2) = server_transport(transport.as_ref());
                    let mut tls = InboundTlsConfig::new(tls);
                    if h2.is_some() && tls.alpn.is_empty() {
                        tls.alpn.push("h2".into());
                    }
                    InboundConfig::Vless {
                        uuid: Arc::new(uuid.clone()),
                        tls,
                        ws,
                        h2,
                    }
                }
                Inbound::Vmess {
                    uuid,
                    tls,
                    transport,
                    ..
                } => {
                    let (ws, h2) = server_transport(transport.as_ref());
                    let tls = tls.as_ref().map(|tls| {
                        let mut tls = InboundTlsConfig::new(tls);
                        if h2.is_some() && tls.alpn.is_empty() {
                            tls.alpn.push("h2".into());
                        }
                        tls
                    });
                    if (ws.is_some() || h2.is_some()) && tls.is_none() {
                        return Err(BuildError::InboundOption {
                            tag: tag.to_owned(),
                            reason: "tls is required for vmess ws/h2".into(),
                        });
                    }
                    InboundConfig::Vmess {
                        cmd_key: Arc::new(CmdKey::derive(uuid)),
                        tls,
                        ws,
                        h2,
                    }
                }
            };
            let Some(listen) = inbound.listen().to_socket_addr() else {
                return Err(BuildError::InboundListen {
                    tag: tag.to_owned(),
                    listen: inbound.listen().to_string(),
                });
            };
            inbounds.push(InboundSpec {
                tag: Arc::from(tag),
                config,
                listen,
                sniffing: Policy::from_config(inbound.sniffing()),
            });
        }

        let mut outbounds = Vec::with_capacity(self.config.inner.outbounds.len());
        for outbound in &self.config.inner.outbounds {
            let tag = outbound.tag();
            let config = match outbound {
                ConfigOutbound::Direct { .. } => OutboundConfig::Direct,
                ConfigOutbound::Http { server, .. } => OutboundConfig::Http {
                    server: server.clone(),
                },
                ConfigOutbound::Shadowsocks {
                    server,
                    method,
                    password,
                    ..
                } => {
                    let (method, key) = credentials(Some(method.as_str()), Some(password.expose()))
                        .map_err(|error| BuildError::Credentials {
                            tag: tag.to_owned(),
                            reason: error.to_string(),
                        })?;
                    OutboundConfig::Shadowsocks {
                        server: server.clone(),
                        method,
                        key,
                    }
                }
                ConfigOutbound::Trojan {
                    server,
                    password,
                    tls,
                    ..
                } => OutboundConfig::Trojan {
                    server: server.clone(),
                    password: Arc::new(PasswordHash::derive(password.expose())),
                    tls: outbound_tls_config(tls, server, tag, None, None)?,
                },
                ConfigOutbound::Vless {
                    server,
                    uuid,
                    tls,
                    transport,
                    xudp,
                    mux,
                    ..
                } => {
                    let (ws, h2) = client_transport(transport.as_ref(), tls.as_ref(), server, tag)?;
                    let tls = tls
                        .as_ref()
                        .map(|tls| {
                            outbound_tls_config(
                                tls,
                                server,
                                tag,
                                transport_default_alpn(ws.as_ref(), h2.as_ref()),
                                h2.as_ref().map(|_| "h2"),
                            )
                        })
                        .transpose()?;
                    OutboundConfig::Vless {
                        server: server.clone(),
                        uuid: Arc::new(uuid.clone()),
                        tls,
                        xudp: *xudp,
                        mux: *mux,
                        ws,
                        h2,
                    }
                }
                ConfigOutbound::Vmess {
                    server,
                    uuid,
                    tls,
                    transport,
                    mux,
                    security,
                    ..
                } => {
                    let (ws, h2) = client_transport(transport.as_ref(), tls.as_ref(), server, tag)?;
                    let tls = tls
                        .as_ref()
                        .map(|tls| {
                            outbound_tls_config(
                                tls,
                                server,
                                tag,
                                transport_default_alpn(ws.as_ref(), h2.as_ref()),
                                h2.as_ref().map(|_| "h2"),
                            )
                        })
                        .transpose()?;
                    let security = match security {
                        VmessSecurity::Aes128Gcm => VmessCipher::Aes128Gcm,
                        VmessSecurity::ChaCha20Poly1305 => VmessCipher::ChaCha20Poly1305,
                    };
                    OutboundConfig::Vmess {
                        server: server.clone(),
                        cmd_key: Arc::new(CmdKey::derive(uuid)),
                        security,
                        mux: *mux,
                        tls,
                        ws,
                        h2,
                    }
                }
                ConfigOutbound::Selector {
                    nodes,
                    strategy,
                    health_check,
                    ..
                } => OutboundConfig::Selector {
                    nodes: nodes.clone(),
                    strategy: *strategy,
                    health_check: health_check.clone(),
                },
            };
            outbounds.push(OutboundSpec {
                tag: Arc::from(tag),
                config,
            });
        }

        let supervisor = Arc::new(Supervisor::new(limits.max_connections));
        let metrics = Arc::new(Metrics::new(self.metrics));
        #[cfg(feature = "dns")]
        let dns = DnsRuntime::build(
            self.config.inner.dns.as_ref(),
            self.dns_resolver,
            (*metrics).clone(),
        )
        .map_err(|error| match error {
            crate::dns::DnsBuildError::Conflict => BuildError::DnsResolverConflict,
            other => BuildError::Dns {
                reason: other.to_string(),
            },
        })?;
        #[cfg(not(feature = "dns"))]
        let dns = None;
        Ok(Instance {
            runtime,
            limits,
            supervisor,
            router: Arc::new(router),
            metrics,
            process,
            dns,
            outbounds,
            inbounds,
        })
    }
}
