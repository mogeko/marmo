//! Compiled inbound and outbound state shared by the lifecycle.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use marmo_net::Endpoint;
use marmo_proto::shadowsocks::{Key, Method};
use marmo_proto::trojan::PasswordHash;
use marmo_proto::vless::Uuid;
use marmo_proto::vmess::{CmdKey, Security as VmessCipher};
use marmo_transport::h2::{H2ClientOptions, H2ServerOptions};
use marmo_transport::tls::{TlsClient, TlsClientOptions, TlsServer, TlsServerOptions};
use marmo_transport::ws::{WsClient, WsClientOptions, WsServer, WsServerOptions};
use marmo_transport::{
    BoxStream, Layer, RelayCounters, RelayError, RelayOptions, relay_with_counters,
};
use tokio::runtime::Handle;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroize;

use super::error::{BindError, BuildError};
use crate::config::{HealthCheck, Strategy, StreamNetwork, StreamTransport};
use crate::direct::Dialer;
use crate::limits::RuntimeLimits;
use crate::metrics::{MetricEvent, Metrics};
use crate::outbound::{self, Outbound, datagram::BoxDatagram, http_connect};
use crate::process::{ProcessRequest, ProcessRuntime};
use crate::routing::{Action, Metadata, Router};
use crate::shadowsocks::SaltReplay;
use crate::sniff::Policy;
use crate::supervisor::Supervisor;
use crate::vmess::ReplayFilter;

pub(crate) struct Context {
    pub(crate) runtime: Handle,
    pub(crate) supervisor: Arc<Supervisor>,
    pub(crate) router: Arc<Router>,
    pub(crate) metrics: Arc<Metrics>,
    pub(crate) process: Option<Arc<ProcessRuntime>>,
    pub(crate) direct: Arc<dyn Outbound>,
    pub(crate) dialer: Dialer,
    pub(crate) outbounds: Vec<Arc<dyn Outbound>>,
    pub(crate) limits: RuntimeLimits,
}

impl Context {
    pub(crate) async fn route(&self, mut metadata: Metadata<'_>) -> Action {
        if self.router.needs_process()
            && metadata.process.is_none()
            && let Some(process) = self.process.as_ref()
        {
            let request = ProcessRequest {
                network: metadata.network,
                source: metadata.source.clone(),
                destination: metadata.destination.clone(),
            };
            metadata.process = process.lookup(&self.runtime, request).await;
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
    ) -> io::Result<Option<BoxDatagram>> {
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
pub(crate) enum InboundKind {
    Socks5,
    Http,
    Shadowsocks {
        method: Method,
        key: Arc<Key>,
        replay: Arc<Mutex<SaltReplay>>,
    },
    Trojan {
        password: Arc<PasswordHash>,
        tls: Arc<TlsServer>,
        fallback: Option<Endpoint>,
    },
    Vless {
        uuid: Arc<Uuid>,
        layers: Arc<[Arc<dyn Layer>]>,
        h2: Option<H2ServerOptions>,
    },
    Vmess {
        cmd_key: Arc<CmdKey>,
        replay: Arc<Mutex<ReplayFilter>>,
        layers: Arc<[Arc<dyn Layer>]>,
        h2: Option<H2ServerOptions>,
    },
}

pub(crate) struct InboundSpec {
    pub(crate) tag: Arc<str>,
    pub(crate) config: InboundConfig,
    pub(crate) listen: SocketAddr,
    pub(crate) sniffing: Option<Policy>,
}

pub(crate) enum InboundConfig {
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

pub(crate) struct InboundTlsConfig {
    pub(crate) certificate: String,
    pub(crate) private_key: String,
    pub(crate) alpn: Vec<String>,
    client_ca: Option<String>,
    client_auth: crate::config::ClientAuth,
    handshake_timeout: Duration,
}

impl InboundTlsConfig {
    pub(crate) fn new(tls: &crate::config::InboundTls) -> Self {
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

impl Drop for InboundTlsConfig {
    fn drop(&mut self) {
        self.certificate.zeroize();
        self.private_key.zeroize();
        if let Some(ca) = self.client_ca.as_mut() {
            ca.zeroize();
        }
    }
}

impl InboundConfig {
    pub(crate) fn build(self, tag: &str, metrics: &Arc<Metrics>) -> Result<InboundKind, BindError> {
        Ok(match self {
            Self::Socks5 => InboundKind::Socks5,
            Self::Http => InboundKind::Http,
            Self::Shadowsocks { method, key } => InboundKind::Shadowsocks {
                method,
                key,
                replay: Arc::new(Mutex::new(SaltReplay::new())),
            },
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
                InboundKind::Vless {
                    uuid,
                    layers: Arc::from(layers),
                    h2,
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
                InboundKind::Vmess {
                    cmd_key,
                    replay: Arc::new(Mutex::new(ReplayFilter::new())),
                    layers: Arc::from(layers),
                    h2,
                }
            }
        })
    }
}

pub(crate) struct OutboundSpec {
    pub(crate) tag: Arc<str>,
    pub(crate) config: OutboundConfig,
}

pub(crate) enum OutboundConfig {
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

pub(super) fn outbound_tls_config(
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

pub(crate) struct OutboundTlsConfig {
    server_name: String,
    alpn: Vec<String>,
    required_alpn: Option<String>,
    insecure: bool,
    client_certificate: Option<String>,
    client_private_key: Option<String>,
    handshake_timeout: Duration,
}

impl Drop for OutboundTlsConfig {
    fn drop(&mut self) {
        if let Some(certificate) = self.client_certificate.as_mut() {
            certificate.zeroize();
        }
        if let Some(key) = self.client_private_key.as_mut() {
            key.zeroize();
        }
    }
}

impl OutboundSpec {
    pub(crate) fn is_selector(&self) -> bool {
        matches!(self.config, OutboundConfig::Selector { .. })
    }

    pub(crate) fn build_node(
        self, metrics: &Arc<Metrics>, dialer: &Dialer,
    ) -> Result<Arc<dyn Outbound>, BindError> {
        let Self { tag, config } = self;
        Ok(match config {
            OutboundConfig::Direct => Arc::new(crate::direct::DirectOutbound::new(dialer.clone())),
            OutboundConfig::Http { server } => Arc::new(http_connect::HttpOutbound {
                server,
                dialer: dialer.clone(),
            }),
            OutboundConfig::Shadowsocks {
                server,
                method,
                key,
            } => Arc::new(outbound::shadowsocks::ShadowsocksOutbound {
                server,
                method,
                key,
                dialer: dialer.clone(),
            }),
            OutboundConfig::Trojan {
                server,
                password,
                tls,
            } => Arc::new(outbound::trojan::TrojanOutbound {
                server,
                password,
                tls: build_tls_client(&tls, &tag, metrics)?,
                dialer: dialer.clone(),
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
                Arc::new(outbound::vless::VlessOutbound {
                    server,
                    uuid,
                    xudp,
                    mux,
                    layers,
                    h2,
                    h2_pool: OnceLock::new(),
                    pool: OnceLock::new(),
                    dialer: dialer.clone(),
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
                Arc::new(outbound::vmess::VmessOutbound {
                    server,
                    cmd_key,
                    security,
                    mux,
                    layers,
                    h2,
                    h2_pool: OnceLock::new(),
                    pool: OnceLock::new(),
                    dialer: dialer.clone(),
                })
            }
            OutboundConfig::Selector { .. } => {
                unreachable!("selectors are built in the second pass")
            }
        })
    }

    pub(crate) fn build_selector(
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

pub(super) fn server_transport(
    transport: Option<&StreamTransport>,
) -> (Option<WsServerOptions>, Option<H2ServerOptions>) {
    match transport.map(|transport| transport.network) {
        Some(StreamNetwork::Ws) => {
            let transport = transport.expect("ws transport");
            (
                Some(WsServerOptions {
                    path: transport.path.clone(),
                    subprotocols: transport.subprotocols.clone().unwrap_or_default(),
                    compression: transport.compression,
                    origins: transport.origins.clone().unwrap_or_default(),
                }),
                None,
            )
        }
        Some(StreamNetwork::H2) => {
            let transport = transport.expect("h2 transport");
            (
                None,
                Some(H2ServerOptions {
                    path: transport.path.clone(),
                }),
            )
        }
        Some(StreamNetwork::Tcp) | None => (None, None),
    }
}

pub(super) fn client_transport(
    transport: Option<&StreamTransport>, tls: Option<&crate::config::Tls>, server: &Endpoint,
    tag: &str,
) -> Result<(Option<WsClientOptions>, Option<H2ClientOptions>), BuildError> {
    let Some(transport) = transport else {
        return Ok((None, None));
    };
    match transport.network {
        StreamNetwork::Tcp => Ok((None, None)),
        StreamNetwork::Ws => Ok((
            Some(WsClientOptions {
                host: transport_host(transport, tls, server, tag, "ws")?,
                path: transport.path.clone(),
                subprotocols: transport.subprotocols.clone().unwrap_or_default(),
                compression: transport.compression,
            }),
            None,
        )),
        StreamNetwork::H2 => Ok((
            None,
            Some(H2ClientOptions {
                host: transport_host(transport, tls, server, tag, "h2")?,
                path: transport.path.clone(),
                tls: tls.is_some(),
            }),
        )),
    }
}

pub(super) fn transport_default_alpn(
    ws: Option<&WsClientOptions>, h2: Option<&H2ClientOptions>,
) -> Option<&'static str> {
    match (ws, h2) {
        (_, Some(_)) => Some("h2"),
        (Some(_), None) => Some("http/1.1"),
        (None, None) => None,
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

fn transport_client_auth(auth: crate::config::ClientAuth) -> marmo_transport::tls::ClientAuth {
    match auth {
        crate::config::ClientAuth::None => marmo_transport::tls::ClientAuth::None,
        crate::config::ClientAuth::Optional => marmo_transport::tls::ClientAuth::Optional,
        crate::config::ClientAuth::Required => marmo_transport::tls::ClientAuth::Required,
    }
}
