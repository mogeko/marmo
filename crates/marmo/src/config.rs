//! Strict JSON configuration.
//!
//! This module is the data model and parser: unknown fields, duplicate fields,
//! bad enum tags, and oversized documents are rejected here. Semantic
//! validation (tag references, selector graphs, credential shapes) lives in
//! `validate`.

use std::fmt;
use std::str::FromStr;

use marmo_net::{Endpoint, Network};
use marmo_proto::shadowsocks::Method as SsMethod;
use marmo_proto::vless::Uuid;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Upper bound for a configuration document (4 MiB).
pub const MAX_CONFIG_BYTES: usize = 4 * 1024 * 1024;

/// The whole configuration document, after validation (ADR-0032).
///
/// The fields are private. Construct one with [`Config::from_json`] or
/// [`ConfigBuilder`], both of which reject invalid documents before returning.
#[derive(Clone, PartialEq)]
pub struct Config {
    pub(crate) inner: ConfigInner,
}

/// Validated configuration state.
#[derive(Clone, PartialEq)]
pub(crate) struct ConfigInner {
    pub(crate) version: u8,
    pub(crate) limits: Limits,
    pub(crate) process: Process,
    pub(crate) dns: Option<Dns>,
    pub(crate) inbounds: Vec<Inbound>,
    pub(crate) outbounds: Vec<Outbound>,
    pub(crate) route: Route,
}

/// The strict JSON document.
///
/// This type is crate-private: it can represent an invalid configuration and is
/// never handed to an embedder. `Config::from_json` and `ConfigBuilder` validate
/// it before constructing a [`Config`].
#[derive(Clone, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct RawConfig {
    /// Schema version; only `2` is defined today.
    pub(crate) version: u8,
    /// Global connection and timeout policy.
    pub(crate) limits: Limits,
    /// Process-identity lookup bounds.
    pub(crate) process: Process,
    /// Optional DNS resolver policy. `None` uses the system resolver.
    #[serde(default)]
    pub(crate) dns: Option<Dns>,
    /// Configured inbounds.
    pub(crate) inbounds: Vec<RawInbound>,
    /// Configured outbounds.
    pub(crate) outbounds: Vec<RawOutbound>,
    /// Rule list and default action.
    pub(crate) route: Route,
}

impl Config {
    /// Parses strict JSON.
    ///
    /// The document is rejected before parsing when it exceeds
    /// [`MAX_CONFIG_BYTES`]. Unknown fields, duplicate fields, bad enum tags,
    /// and trailing data are errors carrying a JSON path. A parsed value is
    /// semantically valid.
    pub fn from_json(text: &str) -> Result<Self, ConfigError> {
        let raw = RawConfig::from_json(text)?;
        raw.validate()?;
        Ok(Self {
            inner: ConfigInner::from_raw(&raw)?,
        })
    }

    /// Starts a programmatic configuration.
    #[must_use]
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::new()
    }

    /// Schema version; only `2` is defined today.
    #[must_use]
    pub fn version(&self) -> u8 {
        self.inner.version
    }

    /// Returns the runtime limits derived from this configuration.
    #[must_use]
    pub fn limits(&self) -> crate::limits::RuntimeLimits {
        crate::limits::RuntimeLimits::from_config(&self.inner.limits)
    }

    /// Process-identity lookup bounds.
    #[must_use]
    pub fn process(&self) -> &Process {
        &self.inner.process
    }

    /// Optional DNS resolver policy.
    #[must_use]
    pub fn dns(&self) -> Option<&Dns> {
        self.inner.dns.as_ref()
    }

    /// Configured inbounds.
    #[must_use]
    pub fn inbounds(&self) -> &[Inbound] {
        &self.inner.inbounds
    }

    /// Configured outbounds.
    #[must_use]
    pub fn outbounds(&self) -> &[Outbound] {
        &self.inner.outbounds
    }

    /// Rule list and default action.
    #[must_use]
    pub fn route(&self) -> &Route {
        &self.inner.route
    }
}

impl RawConfig {
    fn from_json(text: &str) -> Result<Self, ConfigError> {
        if text.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge);
        }

        let mut deserializer = serde_json::Deserializer::from_str(text);
        let config: Self =
            serde_path_to_error::deserialize(&mut deserializer).map_err(|error| {
                ConfigError::Json {
                    path: error.path().to_string(),
                    source: error.into_inner(),
                }
            })?;
        deserializer.end().map_err(|source| ConfigError::Json {
            path: ".".into(),
            source,
        })?;
        Ok(config)
    }
}

/// Builds a validated [`Config`] without JSON.
///
/// Each call replaces or appends one section. [`ConfigBuilder::build`] runs the
/// same semantic validation as [`Config::from_json`].
#[derive(Clone)]
pub struct ConfigBuilder {
    limits: Limits,
    process: Process,
    dns: Option<Dns>,
    inbounds: Vec<Inbound>,
    outbounds: Vec<Outbound>,
    route: Route,
}

impl ConfigBuilder {
    /// Starts from schema defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            limits: Limits::default(),
            process: Process::default(),
            dns: None,
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            route: Route::default(),
        }
    }

    /// Replaces global connection and timeout limits.
    #[must_use]
    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Replaces process-identity lookup bounds.
    #[must_use]
    pub fn process(mut self, process: Process) -> Self {
        self.process = process;
        self
    }

    /// Replaces the optional DNS policy.
    #[must_use]
    pub fn dns(mut self, dns: Option<Dns>) -> Self {
        self.dns = dns;
        self
    }

    /// Appends one inbound.
    #[must_use]
    pub fn inbound(mut self, inbound: Inbound) -> Self {
        self.inbounds.push(inbound);
        self
    }

    /// Appends one outbound.
    #[must_use]
    pub fn outbound(mut self, outbound: Outbound) -> Self {
        self.outbounds.push(outbound);
        self
    }

    /// Replaces the rule list and default action.
    #[must_use]
    pub fn route(mut self, route: Route) -> Self {
        self.route = route;
        self
    }

    /// Validates the assembled configuration.
    pub fn build(self) -> Result<Config, ConfigError> {
        let raw = RawConfig {
            version: 2,
            limits: self.limits.clone(),
            process: self.process.clone(),
            dns: self.dns.clone(),
            inbounds: self.inbounds.iter().map(Inbound::to_raw).collect(),
            outbounds: self.outbounds.iter().map(Outbound::to_raw).collect(),
            route: self.route.clone(),
        };
        raw.validate()?;
        Ok(Config {
            inner: ConfigInner {
                version: 2,
                limits: self.limits,
                process: self.process,
                dns: self.dns,
                inbounds: self.inbounds,
                outbounds: self.outbounds,
                route: self.route,
            },
        })
    }
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            inner: ConfigInner {
                version: 2,
                limits: Limits::default(),
                process: Process::default(),
                dns: None,
                inbounds: Vec::new(),
                outbounds: Vec::new(),
                route: Route::default(),
            },
        }
    }
}

impl Default for RawConfig {
    fn default() -> Self {
        Self {
            version: 2,
            limits: Limits::default(),
            process: Process::default(),
            dns: None,
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            route: Route::default(),
        }
    }
}

impl FromStr for Config {
    type Err = ConfigError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::from_json(text)
    }
}

/// Global limits as they appear in JSON (seconds).
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Maximum accepted TCP streams; `0` rejects all.
    pub max_connections: u32,
    /// Absolute deadline from accept through the protocol handshake.
    pub handshake_timeout_s: u16,
    /// Activity-based idle timeout; `0` disables it.
    pub idle_timeout_s: u32,
    /// Grace after the client uplink closes; `0` closes immediately.
    pub uplink_only_s: u32,
    /// Grace after the remote downlink closes; `0` closes immediately.
    pub downlink_only_s: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            handshake_timeout_s: 10,
            idle_timeout_s: 300,
            uplink_only_s: 1,
            downlink_only_s: 1,
        }
    }
}

/// Bounds for the injected process resolver.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Process {
    /// Cache entry lifetime in seconds; `0` disables the library cache.
    pub cache_ttl_s: u16,
    /// Maximum cache entries; `0` disables the library cache.
    pub cache_capacity: u16,
    /// Maximum wait for one resolver call in milliseconds.
    pub lookup_timeout_ms: u16,
    /// Maximum concurrent resolver calls.
    pub max_inflight: u16,
}

impl Default for Process {
    fn default() -> Self {
        Self {
            cache_ttl_s: 5,
            cache_capacity: 1024,
            lookup_timeout_ms: 50,
            max_inflight: 64,
        }
    }
}

/// DNS resolver configuration.
///
/// The DNS subsystem and this configuration are inert unless the `dns` Cargo
/// feature is enabled. With the feature enabled, `None` keeps the system
/// resolver and `Some` installs the configured cache and upstreams.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Dns {
    /// Preferred upstream servers, tried first.
    pub servers: Vec<DnsServer>,
    /// Servers tried only after every preferred server fails.
    pub fallback: Vec<DnsServer>,
    /// Total deadline for one lookup across both tiers.
    pub timeout_ms: u16,
    /// Maximum concurrent upstream lookups.
    pub max_inflight: u16,
    /// Maximum cache entries; `0` disables the library cache.
    pub cache_capacity: u16,
    /// Lower bound applied to a positive answer's TTL.
    pub min_ttl_s: u32,
    /// Upper bound applied to a positive answer's TTL.
    pub max_ttl_s: u32,
    /// Cache lifetime for NXDOMAIN/NODATA; `0` disables negative caching.
    pub negative_ttl_s: u16,
    /// TLS trust configuration for DoT/DoH servers.
    pub tls: Option<DnsTls>,
}

impl Default for Dns {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            fallback: Vec::new(),
            timeout_ms: 5000,
            max_inflight: 64,
            cache_capacity: 1024,
            min_ttl_s: 0,
            max_ttl_s: 3600,
            negative_ttl_s: 30,
            tls: None,
        }
    }
}

/// One configured DNS upstream.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsServer {
    /// Transport protocol.
    pub protocol: DnsProtocol,
    /// Literal `IP:port` address; hostnames are rejected.
    pub address: String,
    /// TLS server name for `tls`/`https`; defaults to the address literal.
    #[serde(default)]
    pub server_name: Option<String>,
    /// HTTP path for `https`; defaults to `/dns-query`.
    #[serde(default)]
    pub path: Option<String>,
}

/// DNS upstream transport.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsProtocol {
    /// Plaintext DNS over UDP.
    Udp,
    /// Plaintext DNS over TCP.
    Tcp,
    /// DNS over TLS.
    Tls,
    /// DNS over HTTPS (HTTP/2).
    Https,
}

/// TLS trust configuration for DNS servers.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsTls {
    /// Inline PEM trust anchors; replaces platform roots when present.
    pub ca: Option<String>,
}

/// An inbound listener.
#[derive(Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawInbound {
    /// Unique, non-empty tag.
    pub tag: String,
    /// Protocol spoken on this listener.
    pub protocol: RawInboundProtocol,
    /// Listen endpoint, for example `127.0.0.1:1080`.
    pub listen: String,
    /// Shadowsocks method.
    #[serde(default)]
    pub method: Option<String>,
    /// Shadowsocks password or Trojan password.
    #[serde(default)]
    pub password: Option<String>,
    /// VLESS UUID.
    #[serde(default)]
    pub uuid: Option<String>,
    /// TLS settings for protocols that terminate TLS.
    #[serde(default)]
    pub tls: Option<InboundTls>,
    /// L7 stream transport for protocols that support one.
    #[serde(default)]
    pub transport: Option<StreamTransport>,
    /// Trojan fallback endpoint for unauthenticated traffic.
    #[serde(default)]
    pub fallback: Option<String>,
    /// Opt-in sniffing of the first stream bytes before routing.
    #[serde(default)]
    pub sniffing: Option<Sniffing>,
}

impl Drop for RawInbound {
    fn drop(&mut self) {
        if let Some(password) = self.password.as_mut() {
            password.zeroize();
        }
        if let Some(uuid) = self.uuid.as_mut() {
            uuid.zeroize();
        }
    }
}

/// Inbound protocols.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RawInboundProtocol {
    /// HTTP CONNECT and forward proxying.
    Http,
    /// Shadowsocks 2022.
    Shadowsocks,
    /// SOCKS5.
    Socks5,
    /// Trojan over TLS.
    Trojan,
    /// VLESS.
    Vless,
    /// VMess AEAD.
    Vmess,
}

/// A validated inbound listener.
///
/// The protocol variant carries exactly the fields that protocol uses; endpoint
/// and UUID parsing has already happened. Construct one through
/// [`ConfigBuilder::inbound`].
#[derive(Clone, PartialEq)]
#[non_exhaustive]
pub enum Inbound {
    /// SOCKS5 CONNECT and UDP ASSOCIATE.
    Socks5 {
        /// Unique, non-empty tag.
        tag: String,
        /// Bound listen endpoint.
        listen: Endpoint,
        /// Opt-in sniffing policy.
        sniffing: Option<Sniffing>,
    },
    /// HTTP CONNECT and forward proxying.
    Http {
        /// Unique, non-empty tag.
        tag: String,
        /// Bound listen endpoint.
        listen: Endpoint,
        /// Opt-in sniffing policy.
        sniffing: Option<Sniffing>,
    },
    /// Shadowsocks 2022.
    Shadowsocks {
        /// Unique, non-empty tag.
        tag: String,
        /// Bound listen endpoint.
        listen: Endpoint,
        /// AEAD method.
        method: SsMethod,
        /// Base64 PSK; redacted and zeroized.
        password: SecretString,
        /// Opt-in sniffing policy.
        sniffing: Option<Sniffing>,
    },
    /// Trojan over TLS.
    Trojan {
        /// Unique, non-empty tag.
        tag: String,
        /// Bound listen endpoint.
        listen: Endpoint,
        /// Authentication password; redacted and zeroized.
        password: SecretString,
        /// TLS termination settings.
        tls: InboundTls,
        /// Fallback endpoint for unauthenticated traffic.
        fallback: Option<Endpoint>,
        /// Opt-in sniffing policy.
        sniffing: Option<Sniffing>,
    },
    /// VLESS over TLS.
    Vless {
        /// Unique, non-empty tag.
        tag: String,
        /// Bound listen endpoint.
        listen: Endpoint,
        /// Client UUID.
        uuid: Uuid,
        /// TLS termination settings.
        tls: InboundTls,
        /// Optional L7 stream transport.
        transport: Option<StreamTransport>,
        /// Opt-in sniffing policy.
        sniffing: Option<Sniffing>,
    },
    /// VMess AEAD.
    Vmess {
        /// Unique, non-empty tag.
        tag: String,
        /// Bound listen endpoint.
        listen: Endpoint,
        /// Client UUID.
        uuid: Uuid,
        /// Optional TLS termination settings.
        tls: Option<InboundTls>,
        /// Optional L7 stream transport.
        transport: Option<StreamTransport>,
        /// Opt-in sniffing policy.
        sniffing: Option<Sniffing>,
    },
}

impl Inbound {
    /// Unique tag.
    #[must_use]
    pub fn tag(&self) -> &str {
        match self {
            Self::Socks5 { tag, .. }
            | Self::Http { tag, .. }
            | Self::Shadowsocks { tag, .. }
            | Self::Trojan { tag, .. }
            | Self::Vless { tag, .. }
            | Self::Vmess { tag, .. } => tag,
        }
    }

    /// Bound listen endpoint.
    #[must_use]
    pub fn listen(&self) -> &Endpoint {
        match self {
            Self::Socks5 { listen, .. }
            | Self::Http { listen, .. }
            | Self::Shadowsocks { listen, .. }
            | Self::Trojan { listen, .. }
            | Self::Vless { listen, .. }
            | Self::Vmess { listen, .. } => listen,
        }
    }

    /// Opt-in sniffing policy.
    #[must_use]
    pub fn sniffing(&self) -> Option<&Sniffing> {
        match self {
            Self::Socks5 { sniffing, .. }
            | Self::Http { sniffing, .. }
            | Self::Shadowsocks { sniffing, .. }
            | Self::Trojan { sniffing, .. }
            | Self::Vless { sniffing, .. }
            | Self::Vmess { sniffing, .. } => sniffing.as_ref(),
        }
    }

    fn from_raw(raw: &RawInbound, index: usize) -> Result<Self, ConfigError> {
        let tag = raw.tag.clone();
        let listen = conversion_endpoint(&raw.listen, format!("inbounds[{index}].listen"))?;
        let sniffing = raw.sniffing.clone();
        match raw.protocol {
            RawInboundProtocol::Socks5 => Ok(Self::Socks5 {
                tag,
                listen,
                sniffing,
            }),
            RawInboundProtocol::Http => Ok(Self::Http {
                tag,
                listen,
                sniffing,
            }),
            RawInboundProtocol::Shadowsocks => {
                Self::shadowsocks_from_raw(raw, index, tag, listen, sniffing)
            }
            RawInboundProtocol::Trojan => Self::trojan_from_raw(raw, index, tag, listen, sniffing),
            RawInboundProtocol::Vless => Self::vless_from_raw(raw, index, tag, listen, sniffing),
            RawInboundProtocol::Vmess => Ok(Self::Vmess {
                tag,
                listen,
                uuid: conversion_uuid_text(raw.uuid.as_deref(), format!("inbounds[{index}].uuid"))?,
                tls: raw.tls.clone(),
                transport: raw.transport.clone(),
                sniffing,
            }),
        }
    }

    fn shadowsocks_from_raw(
        raw: &RawInbound, index: usize, tag: String, listen: Endpoint, sniffing: Option<Sniffing>,
    ) -> Result<Self, ConfigError> {
        let method =
            conversion_method_text(raw.method.as_deref(), format!("inbounds[{index}].method"))?;
        let password = conversion_secret_text(
            raw.password.as_deref(),
            format!("inbounds[{index}].password"),
        )?;
        Ok(Self::Shadowsocks {
            tag,
            listen,
            method,
            password,
            sniffing,
        })
    }

    fn trojan_from_raw(
        raw: &RawInbound, index: usize, tag: String, listen: Endpoint, sniffing: Option<Sniffing>,
    ) -> Result<Self, ConfigError> {
        let password = conversion_secret_text(
            raw.password.as_deref(),
            format!("inbounds[{index}].password"),
        )?;
        let tls = raw.tls.clone().ok_or_else(|| {
            conversion_error(format!("inbounds[{index}].tls"), "required for trojan")
        })?;
        let fallback = match raw.fallback.as_deref() {
            Some(text) => Some(conversion_endpoint(
                text,
                format!("inbounds[{index}].fallback"),
            )?),
            None => None,
        };
        Ok(Self::Trojan {
            tag,
            listen,
            password,
            tls,
            fallback,
            sniffing,
        })
    }

    fn vless_from_raw(
        raw: &RawInbound, index: usize, tag: String, listen: Endpoint, sniffing: Option<Sniffing>,
    ) -> Result<Self, ConfigError> {
        let uuid = conversion_uuid_text(raw.uuid.as_deref(), format!("inbounds[{index}].uuid"))?;
        let tls = raw.tls.clone().ok_or_else(|| {
            conversion_error(format!("inbounds[{index}].tls"), "required for vless")
        })?;
        Ok(Self::Vless {
            tag,
            listen,
            uuid,
            tls,
            transport: raw.transport.clone(),
            sniffing,
        })
    }

    fn to_raw(&self) -> RawInbound {
        let mut raw = RawInbound {
            tag: self.tag().into(),
            protocol: RawInboundProtocol::Socks5,
            listen: self.listen().to_string(),
            method: None,
            password: None,
            uuid: None,
            tls: None,
            transport: None,
            fallback: None,
            sniffing: self.sniffing().cloned(),
        };
        match self {
            Self::Socks5 { .. } => raw.protocol = RawInboundProtocol::Socks5,
            Self::Http { .. } => raw.protocol = RawInboundProtocol::Http,
            Self::Shadowsocks {
                method, password, ..
            } => {
                raw.protocol = RawInboundProtocol::Shadowsocks;
                raw.method = Some(method.to_string());
                raw.password = Some(password.expose().to_owned());
            }
            Self::Trojan {
                password,
                tls,
                fallback,
                ..
            } => {
                raw.protocol = RawInboundProtocol::Trojan;
                raw.password = Some(password.expose().to_owned());
                raw.tls = Some(tls.clone());
                raw.fallback = fallback.as_ref().map(ToString::to_string);
            }
            Self::Vless {
                uuid,
                tls,
                transport,
                ..
            } => {
                raw.protocol = RawInboundProtocol::Vless;
                raw.uuid = Some(uuid.to_string());
                raw.tls = Some(tls.clone());
                raw.transport = transport.clone();
            }
            Self::Vmess {
                uuid,
                tls,
                transport,
                ..
            } => {
                raw.protocol = RawInboundProtocol::Vmess;
                raw.uuid = Some(uuid.to_string());
                raw.tls = tls.clone();
                raw.transport = transport.clone();
            }
        }
        raw
    }
}

/// A validated outbound or selector.
///
/// Construct one through [`ConfigBuilder::outbound`].
#[derive(Clone, PartialEq)]
#[non_exhaustive]
pub enum Outbound {
    /// Direct dial.
    Direct {
        /// Unique, non-empty tag.
        tag: String,
    },
    /// HTTP CONNECT.
    Http {
        /// Unique, non-empty tag.
        tag: String,
        /// Proxy server endpoint.
        server: Endpoint,
    },
    /// Outbound selector.
    Selector {
        /// Unique, non-empty tag.
        tag: String,
        /// Member tags in preference order.
        nodes: Vec<String>,
        /// Selection strategy.
        strategy: Strategy,
        /// Optional health check.
        health_check: Option<HealthCheck>,
    },
    /// Shadowsocks 2022.
    Shadowsocks {
        /// Unique, non-empty tag.
        tag: String,
        /// Proxy server endpoint.
        server: Endpoint,
        /// AEAD method.
        method: SsMethod,
        /// Base64 PSK; redacted and zeroized.
        password: SecretString,
    },
    /// Trojan over TLS.
    Trojan {
        /// Unique, non-empty tag.
        tag: String,
        /// Proxy server endpoint.
        server: Endpoint,
        /// Authentication password; redacted and zeroized.
        password: SecretString,
        /// TLS client settings.
        tls: Tls,
    },
    /// VLESS.
    Vless {
        /// Unique, non-empty tag.
        tag: String,
        /// Proxy server endpoint.
        server: Endpoint,
        /// Client UUID.
        uuid: Uuid,
        /// Optional TLS client settings.
        tls: Option<Tls>,
        /// Optional L7 stream transport.
        transport: Option<StreamTransport>,
        /// VLESS XUDP framing.
        xudp: bool,
        /// Client-side Mux.Cool pooling.
        mux: bool,
    },
    /// VMess AEAD.
    Vmess {
        /// Unique, non-empty tag.
        tag: String,
        /// Proxy server endpoint.
        server: Endpoint,
        /// Client UUID.
        uuid: Uuid,
        /// Optional TLS client settings.
        tls: Option<Tls>,
        /// Optional L7 stream transport.
        transport: Option<StreamTransport>,
        /// Client-side Mux.Cool pooling.
        mux: bool,
        /// Body cipher.
        security: VmessSecurity,
    },
}

impl Outbound {
    /// Unique tag.
    #[must_use]
    pub fn tag(&self) -> &str {
        match self {
            Self::Direct { tag }
            | Self::Http { tag, .. }
            | Self::Selector { tag, .. }
            | Self::Shadowsocks { tag, .. }
            | Self::Trojan { tag, .. }
            | Self::Vless { tag, .. }
            | Self::Vmess { tag, .. } => tag,
        }
    }

    fn from_raw(raw: &RawOutbound, index: usize) -> Result<Self, ConfigError> {
        match raw.protocol {
            RawOutboundProtocol::Direct => Ok(Self::Direct {
                tag: raw.tag.clone(),
            }),
            RawOutboundProtocol::Http => Ok(Self::Http {
                tag: raw.tag.clone(),
                server: conversion_server(raw, index)?,
            }),
            RawOutboundProtocol::Selector => Ok(Self::Selector {
                tag: raw.tag.clone(),
                nodes: raw.nodes.clone().unwrap_or_default(),
                strategy: raw.strategy.ok_or_else(|| {
                    conversion_error(format!("outbounds[{index}].strategy"), "required")
                })?,
                health_check: raw.health_check.clone(),
            }),
            RawOutboundProtocol::Shadowsocks => Ok(Self::Shadowsocks {
                tag: raw.tag.clone(),
                server: conversion_server(raw, index)?,
                method: conversion_method_text(
                    raw.method.as_deref(),
                    format!("outbounds[{index}].method"),
                )?,
                password: conversion_secret_text(
                    raw.password.as_deref(),
                    format!("outbounds[{index}].password"),
                )?,
            }),
            RawOutboundProtocol::Trojan => Ok(Self::Trojan {
                tag: raw.tag.clone(),
                server: conversion_server(raw, index)?,
                password: conversion_secret_text(
                    raw.password.as_deref(),
                    format!("outbounds[{index}].password"),
                )?,
                tls: raw.tls.clone().ok_or_else(|| {
                    conversion_error(format!("outbounds[{index}].tls"), "required for trojan")
                })?,
            }),
            RawOutboundProtocol::Vless => Ok(Self::Vless {
                tag: raw.tag.clone(),
                server: conversion_server(raw, index)?,
                uuid: conversion_uuid_text(
                    raw.uuid.as_deref(),
                    format!("outbounds[{index}].uuid"),
                )?,
                tls: raw.tls.clone(),
                transport: raw.transport.clone(),
                xudp: raw.xudp,
                mux: raw.mux,
            }),
            RawOutboundProtocol::Vmess => Ok(Self::Vmess {
                tag: raw.tag.clone(),
                server: conversion_server(raw, index)?,
                uuid: conversion_uuid_text(
                    raw.uuid.as_deref(),
                    format!("outbounds[{index}].uuid"),
                )?,
                tls: raw.tls.clone(),
                transport: raw.transport.clone(),
                mux: raw.mux,
                security: raw.security.unwrap_or_default(),
            }),
        }
    }

    fn to_raw(&self) -> RawOutbound {
        match self {
            Self::Direct { tag } => Self::raw_base(tag, RawOutboundProtocol::Direct),
            Self::Http { tag, server } => Self::server_raw(tag, RawOutboundProtocol::Http, server),
            Self::Selector {
                tag,
                nodes,
                strategy,
                health_check,
            } => Self::selector_raw(tag, nodes, *strategy, health_check.clone()),
            Self::Shadowsocks {
                tag,
                server,
                method,
                password,
            } => {
                let mut raw = Self::server_raw(tag, RawOutboundProtocol::Shadowsocks, server);
                raw.method = Some(method.to_string());
                raw.password = Some(password.expose().to_owned());
                raw
            }
            Self::Trojan {
                tag,
                server,
                password,
                tls,
            } => {
                let mut raw = Self::server_raw(tag, RawOutboundProtocol::Trojan, server);
                raw.password = Some(password.expose().to_owned());
                raw.tls = Some(tls.clone());
                raw
            }
            Self::Vless {
                tag,
                server,
                uuid,
                tls,
                transport,
                xudp,
                mux,
            } => Self::vless_raw(tag, server, uuid, tls, transport, *xudp, *mux),
            Self::Vmess {
                tag,
                server,
                uuid,
                tls,
                transport,
                mux,
                security,
            } => Self::vmess_raw(tag, server, uuid, tls, transport, *mux, *security),
        }
    }

    fn selector_raw(
        tag: &str, nodes: &[String], strategy: Strategy, health_check: Option<HealthCheck>,
    ) -> RawOutbound {
        let mut raw = Self::raw_base(tag, RawOutboundProtocol::Selector);
        raw.nodes = Some(nodes.to_vec());
        raw.strategy = Some(strategy);
        raw.health_check = health_check;
        raw
    }

    fn vless_raw(
        tag: &str, server: &Endpoint, uuid: &Uuid, tls: &Option<Tls>,
        transport: &Option<StreamTransport>, xudp: bool, mux: bool,
    ) -> RawOutbound {
        let mut raw = Self::server_raw(tag, RawOutboundProtocol::Vless, server);
        raw.uuid = Some(uuid.to_string());
        raw.tls = tls.clone();
        raw.transport = transport.clone();
        raw.xudp = xudp;
        raw.mux = mux;
        raw
    }

    fn vmess_raw(
        tag: &str, server: &Endpoint, uuid: &Uuid, tls: &Option<Tls>,
        transport: &Option<StreamTransport>, mux: bool, security: VmessSecurity,
    ) -> RawOutbound {
        let mut raw = Self::server_raw(tag, RawOutboundProtocol::Vmess, server);
        raw.uuid = Some(uuid.to_string());
        raw.tls = tls.clone();
        raw.transport = transport.clone();
        raw.mux = mux;
        raw.security = Some(security);
        raw
    }

    fn raw_base(tag: &str, protocol: RawOutboundProtocol) -> RawOutbound {
        RawOutbound {
            tag: tag.into(),
            protocol,
            server: None,
            method: None,
            password: None,
            uuid: None,
            tls: None,
            transport: None,
            xudp: false,
            mux: false,
            security: None,
            nodes: None,
            strategy: None,
            health_check: None,
        }
    }

    fn server_raw(tag: &str, protocol: RawOutboundProtocol, server: &Endpoint) -> RawOutbound {
        let mut raw = Self::raw_base(tag, protocol);
        raw.server = Some(server.to_string());
        raw
    }
}

impl ConfigInner {
    fn from_raw(raw: &RawConfig) -> Result<Self, ConfigError> {
        let mut inbounds = Vec::with_capacity(raw.inbounds.len());
        for (index, inbound) in raw.inbounds.iter().enumerate() {
            inbounds.push(Inbound::from_raw(inbound, index)?);
        }
        let mut outbounds = Vec::with_capacity(raw.outbounds.len());
        for (index, outbound) in raw.outbounds.iter().enumerate() {
            outbounds.push(Outbound::from_raw(outbound, index)?);
        }
        Ok(Self {
            version: raw.version,
            limits: raw.limits.clone(),
            process: raw.process.clone(),
            dns: raw.dns.clone(),
            inbounds,
            outbounds,
            route: raw.route.clone(),
        })
    }
}

/// A secret configuration value.
///
/// The value is zeroized on drop and never printed by `Debug`.
#[derive(Clone, PartialEq)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Wraps an owned secret.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// Exposes the secret to the library.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

fn conversion_error(path: String, message: impl Into<String>) -> ConfigError {
    ConfigError::Validate {
        path,
        message: message.into(),
    }
}

fn conversion_endpoint(text: &str, path: String) -> Result<Endpoint, ConfigError> {
    Endpoint::parse(text).map_err(|_| conversion_error(path, format!("invalid endpoint '{text}'")))
}

fn conversion_server(raw: &RawOutbound, index: usize) -> Result<Endpoint, ConfigError> {
    let text = raw
        .server
        .as_deref()
        .ok_or_else(|| conversion_error(format!("outbounds[{index}].server"), "required"))?;
    conversion_endpoint(text, format!("outbounds[{index}].server"))
}

fn conversion_method_text(method: Option<&str>, path: String) -> Result<SsMethod, ConfigError> {
    method
        .and_then(SsMethod::parse)
        .ok_or_else(|| conversion_error(path, "required or unsupported shadowsocks method"))
}

fn conversion_secret_text(value: Option<&str>, path: String) -> Result<SecretString, ConfigError> {
    value
        .map(|text| SecretString::new(text.to_owned()))
        .ok_or_else(|| conversion_error(path, "required"))
}

fn conversion_uuid_text(text: Option<&str>, path: String) -> Result<Uuid, ConfigError> {
    text.and_then(|value| Uuid::parse(value).ok())
        .ok_or_else(|| conversion_error(path, "required or invalid UUID"))
}

/// Opt-in sniffing of the first stream bytes before routing.
///
/// Sniffing fills the routing domain when the inbound protocol supplied only an
/// IP destination. An inbound-provided domain always wins. The buffered bytes
/// are replayed to the relay unchanged.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Sniffing {
    /// Whether this inbound sniffs before routing.
    pub enabled: bool,
    /// Protocols to inspect; defaults to all supported protocols.
    pub protocols: Option<Vec<SniffProtocol>>,
}

/// A stream protocol the sniffer recognises.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SniffProtocol {
    /// TLS `ClientHello` server name.
    Tls,
    /// HTTP/1 request `Host` header.
    Http,
    /// HTTP/2 request `:authority` (plaintext HTTP/2).
    Http2,
}

/// L7 stream transport carried between the protocol and TLS/TCP.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct StreamTransport {
    /// Transport network.
    pub network: StreamNetwork,
    /// HTTP path; must start with `/`.
    pub path: String,
    /// HTTP `Host`/`:authority` for outbounds.
    pub host: Option<String>,
    /// WebSocket permessage-deflate.
    pub compression: bool,
    /// WebSocket subprotocols in preference order.
    pub subprotocols: Option<Vec<String>>,
}

impl Default for StreamTransport {
    fn default() -> Self {
        Self {
            network: StreamNetwork::Tcp,
            path: "/".into(),
            host: None,
            compression: false,
            subprotocols: None,
        }
    }
}

/// L7 stream network.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamNetwork {
    /// Plain TCP.
    Tcp,
    /// RFC 6455 WebSocket.
    Ws,
    /// HTTP/2 stream (PUT on the client per ADR-0022).
    H2,
}

/// Inbound TLS termination.
#[derive(Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InboundTls {
    /// Inline PEM certificate chain, leaf first (ADR-0023).
    pub certificate: String,
    /// Inline PEM ECDSA/Ed25519 private key (ADR-0023).
    pub private_key: String,
    /// ALPN protocols in server preference order.
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
    /// Inline PEM client-certificate trust anchors (ADR-0023).
    #[serde(default)]
    pub client_ca: Option<String>,
    /// Whether a client certificate is requested and verified.
    #[serde(default)]
    pub client_auth: ClientAuth,
    /// TLS handshake deadline.
    #[serde(default = "default_handshake_timeout_s")]
    pub handshake_timeout_s: u16,
}

impl Drop for InboundTls {
    fn drop(&mut self) {
        self.certificate.zeroize();
        self.private_key.zeroize();
        if let Some(ca) = self.client_ca.as_mut() {
            ca.zeroize();
        }
    }
}

/// Client-certificate policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuth {
    /// No client certificate.
    #[default]
    None,
    /// Request a certificate and verify it if present.
    Optional,
    /// Require and verify a client certificate.
    Required,
}

/// An outbound node or selector.
#[derive(Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawOutbound {
    /// Unique, non-empty tag.
    pub tag: String,
    /// Protocol or selector kind.
    pub protocol: RawOutboundProtocol,
    /// Server endpoint for proxy protocols.
    #[serde(default)]
    pub server: Option<String>,
    /// Shadowsocks method.
    #[serde(default)]
    pub method: Option<String>,
    /// Password.
    #[serde(default)]
    pub password: Option<String>,
    /// VLESS UUID.
    #[serde(default)]
    pub uuid: Option<String>,
    /// TLS settings.
    #[serde(default)]
    pub tls: Option<Tls>,
    /// L7 stream transport.
    #[serde(default)]
    pub transport: Option<StreamTransport>,
    /// VLESS XUDP framing.
    #[serde(default)]
    pub xudp: bool,
    /// Client-side Mux.Cool pooling for VMess and VLESS.
    #[serde(default)]
    pub mux: bool,
    /// VMess body cipher.
    #[serde(default)]
    pub security: Option<VmessSecurity>,
    /// Selector nodes.
    #[serde(default)]
    pub nodes: Option<Vec<String>>,
    /// Selector strategy.
    #[serde(default)]
    pub strategy: Option<Strategy>,
    /// Selector health check.
    #[serde(default)]
    pub health_check: Option<HealthCheck>,
}

impl Drop for RawOutbound {
    fn drop(&mut self) {
        if let Some(password) = self.password.as_mut() {
            password.zeroize();
        }
        if let Some(uuid) = self.uuid.as_mut() {
            uuid.zeroize();
        }
    }
}

/// Outbound protocols.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RawOutboundProtocol {
    /// Direct dial.
    Direct,
    /// HTTP CONNECT.
    Http,
    /// Outbound selector.
    Selector,
    /// Shadowsocks 2022.
    Shadowsocks,
    /// Trojan over TLS.
    Trojan,
    /// VLESS.
    Vless,
    /// VMess AEAD.
    Vmess,
}

/// VMess body cipher.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
pub enum VmessSecurity {
    /// AES-128-GCM.
    #[default]
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    /// ChaCha20-Poly1305.
    #[serde(rename = "chacha20-poly1305")]
    ChaCha20Poly1305,
}

/// Outbound TLS settings.
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    /// SNI override.
    #[serde(default)]
    pub sni: Option<String>,
    /// Skip certificate verification for a loopback test server.
    ///
    /// Validation rejects this for any non-loopback server; use a trusted
    /// certificate or a private CA instead.
    #[serde(default)]
    pub insecure: bool,
    /// ALPN protocols in client preference order.
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
    /// Require the server to select this protocol.
    #[serde(default)]
    pub required_alpn: Option<String>,
    /// Inline PEM client certificate chain (ADR-0023).
    #[serde(default)]
    pub client_certificate: Option<String>,
    /// Inline PEM client private key (ADR-0023).
    #[serde(default)]
    pub client_private_key: Option<String>,
    /// TLS handshake deadline.
    #[serde(default = "default_handshake_timeout_s")]
    pub handshake_timeout_s: u16,
}

impl Default for Tls {
    fn default() -> Self {
        Self {
            sni: None,
            insecure: false,
            alpn: None,
            required_alpn: None,
            client_certificate: None,
            client_private_key: None,
            handshake_timeout_s: 10,
        }
    }
}

impl fmt::Debug for Tls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tls")
            .field("sni", &self.sni)
            .field("insecure", &self.insecure)
            .field("alpn", &self.alpn)
            .field("required_alpn", &self.required_alpn)
            .field(
                "client_certificate",
                &self.client_certificate.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "client_private_key",
                &self.client_private_key.as_ref().map(|_| "<redacted>"),
            )
            .field("handshake_timeout_s", &self.handshake_timeout_s)
            .finish()
    }
}

impl Drop for Tls {
    fn drop(&mut self) {
        if let Some(certificate) = self.client_certificate.as_mut() {
            certificate.zeroize();
        }
        if let Some(key) = self.client_private_key.as_mut() {
            key.zeroize();
        }
    }
}

/// Selector strategy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    /// First node, advance on failure.
    Fallback,
    /// Lowest EWMA latency.
    LeastLatency,
    /// Fixed node.
    Manual,
    /// Uniform random.
    Random,
    /// Rotate per connection.
    RoundRobin,
}

/// Selector health check.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheck {
    /// `host:port` probed with TCP connect.
    pub target: String,
    /// Probe interval.
    #[serde(default = "default_health_interval_s")]
    pub interval_s: u16,
    /// Probe timeout.
    #[serde(default = "default_health_timeout_s")]
    pub timeout_s: u16,
}

/// Routing rules and the final action.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Route {
    /// Ordered rules; first match wins.
    pub rules: Vec<Rule>,
    /// Action when no rule matches.
    #[serde(rename = "final")]
    pub final_outbound: String,
}

impl Default for Route {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            final_outbound: "direct".into(),
        }
    }
}

/// One routing rule: all matchers are ANDed.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Exact domain matches.
    #[serde(default)]
    pub domain: Option<Vec<String>>,
    /// Domain suffix matches.
    #[serde(default)]
    pub domain_suffix: Option<Vec<String>>,
    /// Domain keyword matches.
    #[serde(default)]
    pub domain_keyword: Option<Vec<String>>,
    /// Domain set tags.
    #[serde(default)]
    pub domain_set: Option<Vec<String>>,
    /// CIDR matches.
    #[serde(default)]
    pub ip_cidr: Option<Vec<String>>,
    /// IP set tags.
    #[serde(default)]
    pub geoip: Option<Vec<String>>,
    /// Destination port matches.
    #[serde(default)]
    pub port: Option<Vec<u16>>,
    /// Destination port ranges as inclusive `[start, end]` pairs.
    #[serde(default)]
    pub port_range: Option<Vec<[u16; 2]>>,
    /// Transport network.
    #[serde(default)]
    pub network: Option<Network>,
    /// Inbound tags.
    #[serde(default)]
    pub inbound: Option<Vec<String>>,
    /// Process executable names.
    #[serde(default)]
    pub process_name: Option<Vec<String>>,
    /// Process executable paths.
    #[serde(default)]
    pub process_path: Option<Vec<String>>,
    /// Outbound tag selected on match.
    pub outbound: String,
}

fn default_handshake_timeout_s() -> u16 {
    10
}

fn default_health_interval_s() -> u16 {
    30
}

fn default_health_timeout_s() -> u16 {
    5
}

/// Why a configuration document was rejected.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The document exceeded [`MAX_CONFIG_BYTES`].
    #[error("configuration exceeds {} bytes", MAX_CONFIG_BYTES)]
    TooLarge,
    /// The JSON was malformed, had unknown or duplicate fields, or bad values.
    #[error("invalid configuration JSON at {path}: {source}")]
    Json {
        /// JSON path reported by `serde_path_to_error`; `.` is the root.
        path: String,
        /// The underlying serde error.
        #[source]
        source: serde_json::Error,
    },
    /// The document parsed but violates a cross-field constraint.
    #[error("invalid configuration at {path}: {message}")]
    Validate {
        /// JSON-like field path, for example `inbounds[0].tag`.
        path: String,
        /// What is wrong.
        message: String,
    },
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print credentials: the config carries passwords and UUIDs.
        f.debug_struct("Config")
            .field("version", &self.inner.version)
            .field("limits", &self.inner.limits)
            .field(
                "dns",
                &self
                    .inner
                    .dns
                    .as_ref()
                    .map(|dns| (dns.servers.len(), dns.fallback.len())),
            )
            .field("inbounds", &self.inner.inbounds.len())
            .field("outbounds", &self.inner.outbounds.len())
            .field("route", &self.inner.route)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"
    {
      "version": 2,
      "limits": {
        "max_connections": 16,
        "handshake_timeout_s": 3,
        "idle_timeout_s": 0,
        "uplink_only_s": 2,
        "downlink_only_s": 4
      },
      "inbounds": [
        {
          "tag": "in-vless",
          "protocol": "vless",
          "listen": "127.0.0.1:443",
          "uuid": "00000000-0000-0000-0000-000000000001",
          "tls": {
            "certificate": "-----BEGIN CERTIFICATE----- x -----END CERTIFICATE-----",
            "private_key": "-----BEGIN PRIVATE KEY----- x -----END PRIVATE KEY-----",
            "alpn": ["h2", "http/1.1"],
            "client_ca": "-----BEGIN CERTIFICATE----- x -----END CERTIFICATE-----",
            "client_auth": "required"
          },
          "transport": {
            "network": "ws",
            "path": "/vless",
            "host": "example.com",
            "compression": true,
            "subprotocols": ["vless"]
          },
          "sniffing": { "enabled": true, "protocols": ["tls", "http2"] }
        }
      ],
      "outbounds": [
        { "tag": "direct", "protocol": "direct" },
        {
          "tag": "group",
          "protocol": "selector",
          "nodes": ["direct"],
          "strategy": "least_latency",
          "health_check": { "target": "example.com:443", "interval_s": 10 }
        }
      ],
      "route": {
        "rules": [
          {
            "domain_suffix": ["example.com"],
            "port": [443],
            "network": "tcp",
            "outbound": "group"
          }
        ],
        "final": "direct"
      }
    }
    "#;

    #[test]
    fn parses_defaults() {
        let config = Config::from_json("{}").expect("parse");
        assert_eq!(config.version(), 2);
        assert_eq!(config.limits().max_connections, 1024);
        assert_eq!(config.process(), &Process::default());
        assert!(config.dns().is_none());
        assert!(config.inbounds().is_empty());
        assert!(config.outbounds().is_empty());
        assert_eq!(config.route().final_outbound, "direct");
    }

    #[cfg(feature = "dns")]
    #[test]
    fn parses_dns_config() {
        let text = r#"{
          "dns": {
            "servers": [
              {
                "protocol": "https",
                "address": "1.1.1.1:443",
                "server_name": "cloudflare-dns.com",
                "path": "/dns-query"
              },
              { "protocol": "tls", "address": "8.8.8.8:853" }
            ],
            "fallback": [{ "protocol": "udp", "address": "1.0.0.1:53" }],
            "timeout_ms": 1500,
            "cache_capacity": 0,
            "tls": { "ca": "cert" }
          }
        }"#;
        let config = Config::from_json(text).expect("parse");
        let dns = config.dns().expect("dns");
        assert_eq!(dns.servers.len(), 2);
        assert_eq!(dns.servers[0].protocol, DnsProtocol::Https);
        assert_eq!(dns.servers[0].path.as_deref(), Some("/dns-query"));
        assert_eq!(dns.fallback[0].protocol, DnsProtocol::Udp);
        assert_eq!(dns.timeout_ms, 1500);
        assert_eq!(dns.cache_capacity, 0);
        assert_eq!(
            dns.tls.as_ref().and_then(|tls| tls.ca.as_deref()),
            Some("cert")
        );
    }

    #[cfg(not(feature = "dns"))]
    #[test]
    fn rejects_dns_when_feature_is_disabled() {
        let error = Config::from_json(r#"{"dns":{"servers":[]}}"#).expect_err("reject");
        match error {
            ConfigError::Validate { path, message } => {
                assert_eq!(path, "dns");
                assert!(message.contains("dns support is not compiled in"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn parses_full_config() {
        let config = Config::from_json(FULL).expect("parse");
        assert_eq!(config.limits().max_connections, 16);
        assert_eq!(config.limits().idle_timeout, None);

        let Inbound::Vless {
            tag,
            tls,
            transport,
            sniffing,
            ..
        } = &config.inbounds()[0]
        else {
            panic!("expected a VLESS inbound");
        };
        assert_eq!(tag, "in-vless");
        assert_eq!(
            transport.as_ref().expect("transport").network,
            StreamNetwork::Ws
        );
        assert!(transport.as_ref().expect("transport").compression);
        assert_eq!(tls.client_auth, ClientAuth::Required);
        let sniffing = sniffing.as_ref().expect("sniffing");
        assert!(sniffing.enabled);
        assert_eq!(
            sniffing.protocols.as_deref(),
            Some([SniffProtocol::Tls, SniffProtocol::Http2].as_slice())
        );

        let Outbound::Selector {
            strategy,
            health_check,
            ..
        } = &config.outbounds()[1]
        else {
            panic!("expected a selector outbound");
        };
        assert_eq!(*strategy, Strategy::LeastLatency);
        assert_eq!(health_check.as_ref().expect("health").interval_s, 10);
        assert_eq!(health_check.as_ref().expect("health").timeout_s, 5);

        let rule = &config.route().rules[0];
        assert_eq!(rule.network, Some(Network::Tcp));
        assert_eq!(rule.port.as_deref(), Some([443_u16].as_slice()));
        assert_eq!(rule.outbound, "group");
    }

    #[test]
    fn redacts_tls_private_key_in_debug() {
        let mut tls = Tls::default();
        tls.client_private_key = Some("SECRET-KEY".into());
        tls.client_certificate = Some("SECRET-CERT".into());
        let text = format!("{tls:?}");
        assert!(!text.contains("SECRET-KEY"));
        assert!(!text.contains("SECRET-CERT"));
        assert!(text.contains("<redacted>"));
    }

    #[test]
    fn rejects_unknown_fields() {
        let error = Config::from_json(r#"{"unknown": true}"#).expect_err("unknown");
        match error {
            ConfigError::Json { path, .. } => assert!(path.contains("unknown")),
            other => panic!("unexpected error: {other:?}"),
        }

        let error = Config::from_json(
            r#"{"inbounds":[{"tag":"x","protocol":"http","listen":"127.0.0.1:1","tls":null,"extra":1}]}"#,
        )
        .expect_err("unknown nested");
        match error {
            ConfigError::Json { path, .. } => assert!(path.contains("inbounds[0]")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn rejects_duplicate_fields() {
        let error = Config::from_json(r#"{"version":2,"version":2}"#).expect_err("duplicate");
        assert!(matches!(error, ConfigError::Json { .. }));
    }

    #[test]
    fn rejects_bad_enum() {
        let error = Config::from_json(
            r#"{"inbounds":[{"tag":"x","protocol":"nope","listen":"127.0.0.1:1"}]}"#,
        )
        .expect_err("bad enum");
        assert!(matches!(error, ConfigError::Json { .. }));
    }

    #[test]
    fn rejects_trailing_data() {
        let error = Config::from_json(r#"{} {}"#).expect_err("trailing");
        assert!(matches!(error, ConfigError::Json { .. }));
    }

    #[test]
    fn rejects_oversized_documents() {
        let text = " ".repeat(MAX_CONFIG_BYTES + 1);
        assert!(matches!(
            Config::from_json(&text),
            Err(ConfigError::TooLarge)
        ));
    }

    #[test]
    fn reports_nested_path() {
        let error =
            Config::from_json(r#"{"limits":{"max_connections":"many"}}"#).expect_err("type error");
        match error {
            ConfigError::Json { path, .. } => assert!(path.contains("max_connections")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn from_str_matches_from_json() {
        let config: Config = "{}".parse().expect("parse");
        assert_eq!(config.version(), 2);
    }

    #[test]
    fn parses_json_and_typed_accessors_agree() {
        let config = Config::from_json(FULL).expect("parse");
        assert_eq!(config.inbounds().len(), 1);
        assert_eq!(config.outbounds().len(), 2);
        assert_eq!(config.outbounds()[1].tag(), "group");
        assert_eq!(config.inbounds()[0].tag(), "in-vless");
    }
}
