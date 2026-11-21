//! Strict JSON configuration.
//!
//! This module is the data model and parser: unknown fields, duplicate fields,
//! bad enum tags, and oversized documents are rejected here. Semantic
//! validation (tag references, selector graphs, credential shapes) lives in
//! `validate`.

use std::fmt;
use std::str::FromStr;

use marmo_net::Network;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

/// Upper bound for a configuration document (4 MiB).
pub const MAX_CONFIG_BYTES: usize = 4 * 1024 * 1024;

/// The whole configuration document.
#[derive(Clone, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Schema version; only `2` is defined today.
    pub version: u8,
    /// Global connection and timeout policy.
    pub limits: Limits,
    /// Configured inbounds.
    pub inbounds: Vec<Inbound>,
    /// Configured outbounds.
    pub outbounds: Vec<Outbound>,
    /// Rule list and default action.
    pub route: Route,
}

impl Config {
    /// Parses strict JSON.
    ///
    /// The document is rejected before parsing when it exceeds
    /// [`MAX_CONFIG_BYTES`]. Unknown fields, duplicate fields, bad enum tags,
    /// and trailing data are errors carrying a JSON path.
    pub fn from_json(text: &str) -> Result<Self, ConfigError> {
        if text.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge);
        }

        let mut deserializer = serde_json::Deserializer::from_str(text);
        let config: Config =
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
        config.validate()?;
        Ok(config)
    }

    /// Returns the runtime limits derived from this configuration.
    #[must_use]
    pub fn limits(&self) -> crate::Limits {
        crate::Limits::from_config(&self.limits)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: 2,
            limits: Limits::default(),
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

/// An inbound listener.
#[derive(Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Inbound {
    /// Unique, non-empty tag.
    pub tag: String,
    /// Protocol spoken on this listener.
    pub protocol: InboundProtocol,
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
}

impl Drop for Inbound {
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
pub enum InboundProtocol {
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
pub struct Outbound {
    /// Unique, non-empty tag.
    pub tag: String,
    /// Protocol or selector kind.
    pub protocol: OutboundProtocol,
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

impl Drop for Outbound {
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
pub enum OutboundProtocol {
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
    /// CIDR matches.
    #[serde(default)]
    pub ip_cidr: Option<Vec<String>>,
    /// Destination port matches.
    #[serde(default)]
    pub port: Option<Vec<u16>>,
    /// Transport network.
    #[serde(default)]
    pub network: Option<Network>,
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
            .field("version", &self.version)
            .field("limits", &self.limits)
            .field("inbounds", &self.inbounds.len())
            .field("outbounds", &self.outbounds.len())
            .field("route", &self.route)
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
          }
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
        assert_eq!(config.version, 2);
        assert_eq!(config.limits, Limits::default());
        assert!(config.inbounds.is_empty());
        assert!(config.outbounds.is_empty());
        assert_eq!(config.route.final_outbound, "direct");
    }

    #[test]
    fn parses_full_config() {
        let config = Config::from_json(FULL).expect("parse");
        assert_eq!(config.limits.max_connections, 16);
        assert_eq!(config.limits.idle_timeout_s, 0);

        let inbound = &config.inbounds[0];
        assert_eq!(inbound.tag, "in-vless");
        assert_eq!(inbound.protocol, InboundProtocol::Vless);
        assert_eq!(
            inbound.transport.as_ref().expect("transport").network,
            StreamNetwork::Ws
        );
        assert!(inbound.transport.as_ref().expect("transport").compression);
        assert_eq!(
            inbound.tls.as_ref().expect("tls").client_auth,
            ClientAuth::Required
        );

        let selector = &config.outbounds[1];
        assert_eq!(selector.protocol, OutboundProtocol::Selector);
        assert_eq!(selector.strategy, Some(Strategy::LeastLatency));
        assert_eq!(
            selector.health_check.as_ref().expect("health").interval_s,
            10
        );
        assert_eq!(selector.health_check.as_ref().expect("health").timeout_s, 5);

        let rule = &config.route.rules[0];
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
        assert_eq!(config.version, 2);
    }

    #[test]
    fn round_trips() {
        let config = Config::from_json(FULL).expect("parse");
        let encoded = serde_json::to_string(&config).expect("encode");
        let decoded = Config::from_json(&encoded).expect("decode");
        assert_eq!(decoded, config);
    }
}
