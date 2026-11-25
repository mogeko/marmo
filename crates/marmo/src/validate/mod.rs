//! Semantic validation for [`Config`].
//!
//! Parsing rejects unknown fields and malformed JSON. This module rejects
//! documents that are structurally valid but inconsistent: duplicate tags,
//! missing credentials, unsupported transport combinations, selector graphs,
//! and route targets. Paths match the JSON field layout.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use marmo_net::{Cidr, Endpoint};
use zeroize::Zeroize as _;

use std::collections::HashSet;
use std::net::SocketAddr;

use crate::config::{
    ClientAuth, ConfigError, Dns as ConfigDns, DnsProtocol, DnsServer, Limits as ConfigLimits,
    Process as ConfigProcess, RawConfig, RawInbound, RawInboundProtocol, RawOutbound,
    RawOutboundProtocol, Route, Rule, Sniffing, StreamNetwork, StreamTransport, Tls,
};

mod dns;
mod inbound;
mod outbound;
mod route;
mod transport;

use dns::validate_dns;
use inbound::validate_inbounds;
use outbound::validate_outbounds;
use route::validate_route;

impl RawConfig {
    /// Validates cross-field constraints.
    ///
    /// Called by `Config::from_json` and `ConfigBuilder::build`; the result is
    /// never exposed as an unvalidated `Config`.
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if self.version != 2 {
            let message = if self.version == 1 {
                "version 1 is not supported by the Rust schema; version 2 carries inline PEM TLS credentials (ADR-0023)"
                    .to_owned()
            } else {
                format!("unsupported version {}", self.version)
            };
            return Err(fail("version", message));
        }
        validate_limits(&self.limits)?;
        validate_process(&self.process)?;
        if self.dns.is_some() && !cfg!(feature = "dns") {
            return Err(fail(
                "dns",
                "dns support is not compiled in; enable the `dns` feature",
            ));
        }
        if let Some(dns) = self.dns.as_ref() {
            validate_dns(dns)?;
        }
        validate_inbounds(&self.inbounds)?;
        validate_outbounds(&self.outbounds)?;
        validate_route(&self.route, &self.outbounds, &self.inbounds)?;
        Ok(())
    }
}

fn validate_limits(limits: &ConfigLimits) -> Result<(), ConfigError> {
    if limits.max_connections > 65_535 {
        return Err(fail("limits.max_connections", "must be at most 65535"));
    }
    if !(1..=600).contains(&limits.handshake_timeout_s) {
        return Err(fail("limits.handshake_timeout_s", "must be 1..600"));
    }
    if limits.idle_timeout_s > 86_400 {
        return Err(fail("limits.idle_timeout_s", "must be at most 86400"));
    }
    if limits.uplink_only_s > 86_400 {
        return Err(fail("limits.uplink_only_s", "must be at most 86400"));
    }
    if limits.downlink_only_s > 86_400 {
        return Err(fail("limits.downlink_only_s", "must be at most 86400"));
    }
    Ok(())
}

fn validate_process(process: &ConfigProcess) -> Result<(), ConfigError> {
    if process.cache_ttl_s > 3600 {
        return Err(fail("process.cache_ttl_s", "must be at most 3600"));
    }
    if !(1..=500).contains(&process.lookup_timeout_ms) {
        return Err(fail("process.lookup_timeout_ms", "must be 1..500"));
    }
    if !(1..=1024).contains(&process.max_inflight) {
        return Err(fail("process.max_inflight", "must be 1..1024"));
    }
    Ok(())
}

fn reject_selector_fields(outbound: &RawOutbound, index: usize) -> Result<(), ConfigError> {
    if outbound.nodes.is_some() || outbound.strategy.is_some() || outbound.health_check.is_some() {
        return Err(fail(
            format!("outbounds[{index}]"),
            "group fields only apply to selector",
        ));
    }
    Ok(())
}

fn reject_vless_fields(outbound: &RawOutbound, index: usize) -> Result<(), ConfigError> {
    if outbound.uuid.is_some()
        || outbound.tls.is_some()
        || outbound.xudp
        || outbound.mux
        || outbound.security.is_some()
    {
        return Err(fail(
            format!("outbounds[{index}]"),
            "uuid/xudp/mux/security only apply to vless or vmess; tls applies to vless/trojan/vmess",
        ));
    }
    if outbound.transport.is_some() {
        return Err(fail(
            format!("outbounds[{index}].transport"),
            "only applies to vless or vmess",
        ));
    }
    Ok(())
}

fn ss2022_key_len(method: &str) -> Option<usize> {
    match method {
        "2022-blake3-aes-128-gcm" => Some(16),
        "2022-blake3-aes-256-gcm" => Some(32),
        _ => None,
    }
}

fn valid_ss2022_key(password: &str, expected_len: usize) -> bool {
    let Ok(mut decoded) = STANDARD.decode(password) else {
        return false;
    };
    let valid = decoded.len() == expected_len;
    decoded.zeroize();
    valid
}

fn valid_uuid(text: &str) -> bool {
    match text.len() {
        32 => text.bytes().all(|byte| byte.is_ascii_hexdigit()),
        36 => {
            let bytes = text.as_bytes();
            for (index, byte) in bytes.iter().enumerate() {
                if matches!(index, 8 | 13 | 18 | 23) {
                    if *byte != b'-' {
                        return false;
                    }
                } else if !byte.is_ascii_hexdigit() {
                    return false;
                }
            }
            true
        }
        _ => false,
    }
}

fn is_loopback(endpoint: &Endpoint) -> bool {
    // Only a literal loopback IP is a test server. A name such as `localhost`
    // is resolved later and can be pointed at a non-loopback address by hosts
    // files, search domains, or a custom resolver.
    endpoint.ip().is_some_and(|ip| ip.is_loopback())
}

fn valid_pem(text: &str) -> bool {
    let text = text.trim_start();
    text.starts_with("-----BEGIN ") && text.contains("-----END ")
}

fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 255
        && path.starts_with('/')
        && !path.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
}

fn valid_host(host: &str) -> bool {
    !host.is_empty() && host.len() <= 255 && !host.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
}

fn is_http_token(text: &str) -> bool {
    text.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            )
    })
}

fn contains(protocols: &[String], wanted: &str) -> bool {
    protocols.iter().any(|protocol| protocol == wanted)
}

fn fail(path: impl Into<String>, message: impl Into<String>) -> ConfigError {
    ConfigError::Validate {
        path: path.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests;
