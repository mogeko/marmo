//! Validated configuration values and their conversion from the raw document.

use marmo_net::Endpoint;
use marmo_proto::shadowsocks::Method as SsMethod;
use marmo_proto::vless::Uuid;

use super::raw::{RawConfig, RawInbound, RawInboundProtocol, RawOutbound, RawOutboundProtocol};
use super::secret::SecretString;
use super::{
    ConfigError, ConfigInner, HealthCheck, InboundTls, Sniffing, Strategy, StreamTransport, Tls,
    VmessSecurity,
};

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

    pub(super) fn to_raw(&self) -> RawInbound {
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

    pub(super) fn to_raw(&self) -> RawOutbound {
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
    pub(super) fn from_raw(raw: &RawConfig) -> Result<Self, ConfigError> {
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
