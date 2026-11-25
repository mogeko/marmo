//! Shared configuration schema values.

use std::fmt;

use marmo_net::Network;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

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
