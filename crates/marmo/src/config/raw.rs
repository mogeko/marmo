//! The strict serde document; never exposed to embedders.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::{
    ConfigError, Dns, HealthCheck, InboundTls, Limits, MAX_CONFIG_BYTES, Process, Route, Sniffing,
    Strategy, StreamTransport, Tls, VmessSecurity,
};

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

impl RawConfig {
    pub(super) fn from_json(text: &str) -> Result<Self, ConfigError> {
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
