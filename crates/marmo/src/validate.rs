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
    ClientAuth, Config, ConfigError, Dns as ConfigDns, DnsProtocol, DnsServer, Inbound,
    InboundProtocol, Limits as ConfigLimits, Outbound, OutboundProtocol, Process as ConfigProcess,
    Route, Rule, Sniffing, StreamNetwork, StreamTransport, Tls,
};

impl Config {
    /// Validates cross-field constraints.
    ///
    /// [`Config::from_json`] calls this, so a parsed config is ready for
    /// `Instance`. A programmatically built `Config` must call it explicitly.
    pub fn validate(&self) -> Result<(), ConfigError> {
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

fn validate_dns(dns: &ConfigDns) -> Result<(), ConfigError> {
    if dns.servers.len() > 8 {
        return Err(fail("dns.servers", "must have at most 8 entries"));
    }
    if dns.fallback.len() > 8 {
        return Err(fail("dns.fallback", "must have at most 8 entries"));
    }
    if dns.servers.len() + dns.fallback.len() > 16 {
        return Err(fail(
            "dns",
            "must have at most 16 servers across servers and fallback",
        ));
    }
    if dns.servers.is_empty() && !dns.fallback.is_empty() {
        return Err(fail(
            "dns.fallback",
            "requires at least one dns.servers entry",
        ));
    }

    let mut seen = HashSet::new();
    for (index, server) in dns.servers.iter().enumerate() {
        let path = format!("dns.servers[{index}]");
        let address = validate_dns_server(server, &path)?;
        if !seen.insert((server.protocol, address)) {
            return Err(fail(path, "duplicate protocol and address"));
        }
    }
    for (index, server) in dns.fallback.iter().enumerate() {
        let path = format!("dns.fallback[{index}]");
        let address = validate_dns_server(server, &path)?;
        if !seen.insert((server.protocol, address)) {
            return Err(fail(path, "duplicate protocol and address"));
        }
    }

    if !(100..=30_000).contains(&dns.timeout_ms) {
        return Err(fail("dns.timeout_ms", "must be 100..30000"));
    }
    if !(1..=1024).contains(&dns.max_inflight) {
        return Err(fail("dns.max_inflight", "must be 1..1024"));
    }
    if dns.min_ttl_s > 86_400 {
        return Err(fail("dns.min_ttl_s", "must be at most 86400"));
    }
    if !(1..=86_400).contains(&dns.max_ttl_s) {
        return Err(fail("dns.max_ttl_s", "must be 1..86400"));
    }
    if dns.min_ttl_s > dns.max_ttl_s {
        return Err(fail("dns.min_ttl_s", "must not exceed dns.max_ttl_s"));
    }
    if dns.negative_ttl_s > 3600 {
        return Err(fail("dns.negative_ttl_s", "must be at most 3600"));
    }
    if let Some(ca) = dns.tls.as_ref().and_then(|tls| tls.ca.as_deref()) {
        if ca.is_empty() {
            return Err(fail("dns.tls.ca", "must not be empty"));
        }
        if ca.len() > 64 * 1024 {
            return Err(fail("dns.tls.ca", "must be at most 65536 bytes"));
        }
    }
    Ok(())
}

fn validate_dns_server(server: &DnsServer, path: &str) -> Result<SocketAddr, ConfigError> {
    let address = server.address.parse::<SocketAddr>().map_err(|_| {
        fail(
            format!("{path}.address"),
            "must be an IP address with a port",
        )
    })?;
    if address.port() == 0 {
        return Err(fail(format!("{path}.address"), "port must not be zero"));
    }

    if let Some(name) = server.server_name.as_deref() {
        if name.is_empty() {
            return Err(fail(format!("{path}.server_name"), "must not be empty"));
        }
        if name.len() > 253 {
            return Err(fail(
                format!("{path}.server_name"),
                "must be at most 253 bytes",
            ));
        }
        if !name.is_ascii() || name.bytes().any(|byte| byte <= 0x20 || byte == 0x7f) {
            return Err(fail(
                format!("{path}.server_name"),
                "must be printable ASCII",
            ));
        }
    }

    match server.protocol {
        DnsProtocol::Udp | DnsProtocol::Tcp => {
            if server.server_name.is_some() {
                return Err(fail(
                    format!("{path}.server_name"),
                    "is only valid for tls or https",
                ));
            }
            if server.path.is_some() {
                return Err(fail(format!("{path}.path"), "is only valid for https"));
            }
        }
        DnsProtocol::Tls => {
            if server.path.is_some() {
                return Err(fail(format!("{path}.path"), "is only valid for https"));
            }
        }
        DnsProtocol::Https => {
            if let Some(path_value) = server.path.as_deref() {
                if !path_value.starts_with('/') {
                    return Err(fail(format!("{path}.path"), "must start with '/'"));
                }
                if path_value.len() > 512 {
                    return Err(fail(format!("{path}.path"), "must be at most 512 bytes"));
                }
            }
        }
    }
    Ok(address)
}

fn validate_inbounds(inbounds: &[Inbound]) -> Result<(), ConfigError> {
    for (index, inbound) in inbounds.iter().enumerate() {
        if inbound.tag.is_empty() {
            return Err(fail(format!("inbounds[{index}].tag"), "must not be empty"));
        }
        for previous in &inbounds[..index] {
            if previous.tag == inbound.tag {
                return Err(fail(
                    format!("inbounds[{index}].tag"),
                    format!("duplicate '{}'", inbound.tag),
                ));
            }
        }

        let endpoint = Endpoint::parse(&inbound.listen).map_err(|_| {
            fail(
                format!("inbounds[{index}].listen"),
                format!("invalid endpoint '{}'", inbound.listen),
            )
        })?;
        if !endpoint.is_ip() {
            return Err(fail(
                format!("inbounds[{index}].listen"),
                "must be an IP endpoint",
            ));
        }

        validate_sniffing(inbound.sniffing.as_ref(), index)?;

        match inbound.protocol {
            InboundProtocol::Socks5 | InboundProtocol::Http => {
                if inbound.method.is_some()
                    || inbound.password.is_some()
                    || inbound.uuid.is_some()
                    || inbound.tls.is_some()
                    || inbound.transport.is_some()
                    || inbound.fallback.is_some()
                {
                    return Err(fail(
                        format!("inbounds[{index}]"),
                        "socks5/http do not take credentials, TLS, or fallback",
                    ));
                }
            }
            InboundProtocol::Shadowsocks => validate_shadowsocks_inbound(inbound, index)?,
            InboundProtocol::Trojan => validate_trojan_inbound(inbound, index)?,
            InboundProtocol::Vless => validate_vless_inbound(inbound, index)?,
            InboundProtocol::Vmess => validate_vmess_inbound(inbound, index)?,
        }
    }
    Ok(())
}

fn validate_sniffing(sniffing: Option<&Sniffing>, index: usize) -> Result<(), ConfigError> {
    let Some(sniffing) = sniffing else {
        return Ok(());
    };
    let Some(protocols) = sniffing.protocols.as_deref() else {
        return Ok(());
    };
    if !sniffing.enabled {
        return Err(fail(
            format!("inbounds[{index}].sniffing.protocols"),
            "requires enabled",
        ));
    }
    if protocols.is_empty() {
        return Err(fail(
            format!("inbounds[{index}].sniffing.protocols"),
            "must not be empty",
        ));
    }
    for (protocol_index, protocol) in protocols.iter().enumerate() {
        if protocols[..protocol_index].contains(protocol) {
            return Err(fail(
                format!("inbounds[{index}].sniffing.protocols[{protocol_index}]"),
                "duplicate value",
            ));
        }
    }
    Ok(())
}

fn validate_shadowsocks_inbound(inbound: &Inbound, index: usize) -> Result<(), ConfigError> {
    if inbound.uuid.is_some()
        || inbound.tls.is_some()
        || inbound.transport.is_some()
        || inbound.fallback.is_some()
    {
        return Err(fail(
            format!("inbounds[{index}]"),
            "uuid/tls/transport/fallback do not apply to shadowsocks",
        ));
    }
    let method = inbound.method.as_deref().ok_or_else(|| {
        fail(
            format!("inbounds[{index}].method"),
            "required for shadowsocks",
        )
    })?;
    let Some(key_len) = ss2022_key_len(method) else {
        return Err(fail(
            format!("inbounds[{index}].method"),
            format!("unsupported '{method}'"),
        ));
    };
    let password = inbound.password.as_deref().ok_or_else(|| {
        fail(
            format!("inbounds[{index}].password"),
            "required for shadowsocks",
        )
    })?;
    if !valid_ss2022_key(password, key_len) {
        return Err(fail(
            format!("inbounds[{index}].password"),
            "invalid base64 or key length",
        ));
    }
    Ok(())
}

fn validate_trojan_inbound(inbound: &Inbound, index: usize) -> Result<(), ConfigError> {
    if inbound.method.is_some() || inbound.uuid.is_some() {
        return Err(fail(
            format!("inbounds[{index}]"),
            "trojan does not take method or uuid",
        ));
    }
    if inbound.transport.is_some() {
        return Err(fail(
            format!("inbounds[{index}].transport"),
            "only applies to vless",
        ));
    }
    let password = inbound
        .password
        .as_deref()
        .ok_or_else(|| fail(format!("inbounds[{index}].password"), "required for trojan"))?;
    if password.is_empty() {
        return Err(fail(
            format!("inbounds[{index}].password"),
            "must not be empty",
        ));
    }
    let tls = inbound
        .tls
        .as_ref()
        .ok_or_else(|| fail(format!("inbounds[{index}].tls"), "required for trojan"))?;
    validate_inbound_tls(tls, index)?;
    validate_inbound_tls_auth(tls, index)?;

    if let Some(fallback) = inbound.fallback.as_deref() {
        if fallback.is_empty() {
            return Err(fail(
                format!("inbounds[{index}].fallback"),
                "must not be empty",
            ));
        }
        if Endpoint::parse(fallback).is_err() {
            return Err(fail(
                format!("inbounds[{index}].fallback"),
                format!("invalid endpoint '{fallback}'"),
            ));
        }
    }
    Ok(())
}

fn validate_vless_inbound(inbound: &Inbound, index: usize) -> Result<(), ConfigError> {
    if inbound.method.is_some() || inbound.password.is_some() || inbound.fallback.is_some() {
        return Err(fail(
            format!("inbounds[{index}]"),
            "vless does not take method, password, or fallback",
        ));
    }
    let uuid = inbound
        .uuid
        .as_deref()
        .ok_or_else(|| fail(format!("inbounds[{index}].uuid"), "required for vless"))?;
    if !valid_uuid(uuid) {
        return Err(fail(format!("inbounds[{index}].uuid"), "invalid UUID"));
    }
    let tls = inbound
        .tls
        .as_ref()
        .ok_or_else(|| fail(format!("inbounds[{index}].tls"), "required for vless"))?;
    validate_inbound_tls(tls, index)?;
    validate_inbound_tls_auth(tls, index)?;
    validate_alpn(tls.alpn.as_deref(), None, &format!("inbounds[{index}].tls"))?;
    validate_inbound_transport(inbound, index, true)
}

fn validate_vmess_inbound(inbound: &Inbound, index: usize) -> Result<(), ConfigError> {
    if inbound.method.is_some() || inbound.password.is_some() || inbound.fallback.is_some() {
        return Err(fail(
            format!("inbounds[{index}]"),
            "vmess does not take method, password, or fallback",
        ));
    }
    let uuid = inbound
        .uuid
        .as_deref()
        .ok_or_else(|| fail(format!("inbounds[{index}].uuid"), "required for vmess"))?;
    if !valid_uuid(uuid) {
        return Err(fail(format!("inbounds[{index}].uuid"), "invalid UUID"));
    }
    if let Some(tls) = inbound.tls.as_ref() {
        validate_inbound_tls(tls, index)?;
        validate_inbound_tls_auth(tls, index)?;
        validate_alpn(tls.alpn.as_deref(), None, &format!("inbounds[{index}].tls"))?;
    }
    validate_inbound_transport(inbound, index, false)
}

fn validate_inbound_tls(tls: &crate::config::InboundTls, index: usize) -> Result<(), ConfigError> {
    if !valid_pem(&tls.certificate) {
        return Err(fail(
            format!("inbounds[{index}].tls.certificate"),
            "must be inline PEM (ADR-0023); file paths are not accepted",
        ));
    }
    if !valid_pem(&tls.private_key) {
        return Err(fail(
            format!("inbounds[{index}].tls.private_key"),
            "must be inline PEM (ADR-0023); file paths are not accepted",
        ));
    }
    if tls.handshake_timeout_s == 0 {
        return Err(fail(
            format!("inbounds[{index}].tls.handshake_timeout_s"),
            "must be positive",
        ));
    }
    Ok(())
}

fn validate_inbound_tls_auth(
    tls: &crate::config::InboundTls, index: usize,
) -> Result<(), ConfigError> {
    match (tls.client_auth, tls.client_ca.as_deref()) {
        (ClientAuth::None, None) => Ok(()),
        (ClientAuth::None, Some("")) => Err(fail(
            format!("inbounds[{index}].tls.client_ca"),
            "must not be empty",
        )),
        (ClientAuth::None, Some(_)) => Err(fail(
            format!("inbounds[{index}].tls.client_ca"),
            "requires client_auth",
        )),
        (_, None) => Err(fail(
            format!("inbounds[{index}].tls.client_ca"),
            "required when client_auth is enabled",
        )),
        (_, Some(value)) if !valid_pem(value) => Err(fail(
            format!("inbounds[{index}].tls.client_ca"),
            "must be inline PEM (ADR-0023); file paths are not accepted",
        )),
        (_, Some(_)) => Ok(()),
    }
}

fn validate_inbound_transport(
    inbound: &Inbound, index: usize, tls_required: bool,
) -> Result<(), ConfigError> {
    let Some(transport) = inbound.transport.as_ref() else {
        return Ok(());
    };
    let base = format!("inbounds[{index}].transport");
    validate_transport_shape(transport, &base)?;
    if !tls_required && transport.network == StreamNetwork::Tcp {
        return Ok(());
    }

    let tls = inbound.tls.as_ref().ok_or_else(|| {
        fail(
            format!("inbounds[{index}].tls"),
            "required for the ws/h2 transport",
        )
    })?;
    match transport.network {
        StreamNetwork::H2 => {
            if let Some(alpn) = tls.alpn.as_deref() {
                if !contains(alpn, "h2") {
                    return Err(fail(
                        format!("inbounds[{index}].tls.alpn"),
                        "must contain 'h2' for the h2 transport",
                    ));
                }
            }
        }
        StreamNetwork::Ws => {
            if let Some(alpn) = tls.alpn.as_deref() {
                if !alpn.is_empty() && !contains(alpn, "http/1.1") {
                    return Err(fail(
                        format!("inbounds[{index}].tls.alpn"),
                        "must contain 'http/1.1' for the ws transport",
                    ));
                }
            }
        }
        StreamNetwork::Tcp => {}
    }
    Ok(())
}

fn validate_outbounds(outbounds: &[Outbound]) -> Result<(), ConfigError> {
    for (index, outbound) in outbounds.iter().enumerate() {
        if outbound.tag.is_empty() {
            return Err(fail(format!("outbounds[{index}].tag"), "must not be empty"));
        }
        if outbound.tag == "reject" {
            return Err(fail(
                format!("outbounds[{index}].tag"),
                "'reject' is reserved",
            ));
        }
        if outbound.tag == "direct" && outbound.protocol != OutboundProtocol::Direct {
            return Err(fail(
                format!("outbounds[{index}].tag"),
                "'direct' is reserved for direct",
            ));
        }
        for previous in &outbounds[..index] {
            if previous.tag == outbound.tag {
                return Err(fail(
                    format!("outbounds[{index}].tag"),
                    format!("duplicate '{}'", outbound.tag),
                ));
            }
        }

        match outbound.protocol {
            OutboundProtocol::Direct => validate_direct(outbound, index)?,
            OutboundProtocol::Http => validate_http(outbound, index)?,
            OutboundProtocol::Shadowsocks => {
                validate_shadowsocks_outbound(outbound, index)?;
            }
            OutboundProtocol::Selector => {
                validate_selector(outbound, index, outbounds)?;
            }
            OutboundProtocol::Trojan => validate_trojan(outbound, index)?,
            OutboundProtocol::Vless => validate_vless(outbound, index)?,
            OutboundProtocol::Vmess => validate_vmess(outbound, index)?,
        }
    }
    Ok(())
}

fn validate_direct(outbound: &Outbound, index: usize) -> Result<(), ConfigError> {
    reject_selector_fields(outbound, index)?;
    reject_vless_fields(outbound, index)?;
    if outbound.server.is_some() || outbound.method.is_some() || outbound.password.is_some() {
        return Err(fail(
            format!("outbounds[{index}]"),
            "direct does not take server or credentials",
        ));
    }
    Ok(())
}

fn validate_http(outbound: &Outbound, index: usize) -> Result<(), ConfigError> {
    reject_selector_fields(outbound, index)?;
    reject_vless_fields(outbound, index)?;
    let server = outbound
        .server
        .as_deref()
        .ok_or_else(|| fail(format!("outbounds[{index}].server"), "required for http"))?;
    if Endpoint::parse(server).is_err() {
        return Err(fail(
            format!("outbounds[{index}].server"),
            format!("invalid endpoint '{server}'"),
        ));
    }
    if outbound.method.is_some() || outbound.password.is_some() {
        return Err(fail(
            format!("outbounds[{index}]"),
            "http does not take method or password",
        ));
    }
    Ok(())
}

fn validate_shadowsocks_outbound(outbound: &Outbound, index: usize) -> Result<(), ConfigError> {
    reject_selector_fields(outbound, index)?;
    reject_vless_fields(outbound, index)?;
    let server = outbound.server.as_deref().ok_or_else(|| {
        fail(
            format!("outbounds[{index}].server"),
            "required for shadowsocks",
        )
    })?;
    if Endpoint::parse(server).is_err() {
        return Err(fail(
            format!("outbounds[{index}].server"),
            format!("invalid endpoint '{server}'"),
        ));
    }
    let method = outbound.method.as_deref().ok_or_else(|| {
        fail(
            format!("outbounds[{index}].method"),
            "required for shadowsocks",
        )
    })?;
    let Some(key_len) = ss2022_key_len(method) else {
        return Err(fail(
            format!("outbounds[{index}].method"),
            format!("unsupported '{method}'"),
        ));
    };
    let password = outbound.password.as_deref().ok_or_else(|| {
        fail(
            format!("outbounds[{index}].password"),
            "required for shadowsocks",
        )
    })?;
    if !valid_ss2022_key(password, key_len) {
        return Err(fail(
            format!("outbounds[{index}].password"),
            "invalid base64 or key length",
        ));
    }
    Ok(())
}

fn validate_selector(
    outbound: &Outbound, index: usize, outbounds: &[Outbound],
) -> Result<(), ConfigError> {
    reject_vless_fields(outbound, index)?;
    if outbound.server.is_some() || outbound.method.is_some() || outbound.password.is_some() {
        return Err(fail(
            format!("outbounds[{index}]"),
            "selector does not take server or credentials",
        ));
    }
    let nodes = outbound
        .nodes
        .as_deref()
        .ok_or_else(|| fail(format!("outbounds[{index}].nodes"), "required for selector"))?;
    if nodes.is_empty() {
        return Err(fail(
            format!("outbounds[{index}].nodes"),
            "must not be empty",
        ));
    }
    if outbound.strategy.is_none() {
        return Err(fail(
            format!("outbounds[{index}].strategy"),
            "required for selector",
        ));
    }
    if let Some(health) = outbound.health_check.as_ref() {
        if Endpoint::parse(&health.target).is_err() {
            return Err(fail(
                format!("outbounds[{index}].health_check.target"),
                "invalid endpoint",
            ));
        }
        if health.interval_s == 0 || health.timeout_s == 0 {
            return Err(fail(
                format!("outbounds[{index}].health_check"),
                "intervals must be positive",
            ));
        }
        if health.timeout_s > health.interval_s {
            return Err(fail(
                format!("outbounds[{index}].health_check"),
                "timeout exceeds interval",
            ));
        }
    }

    for (node_index, node) in nodes.iter().enumerate() {
        if node.is_empty() {
            return Err(fail(
                format!("outbounds[{index}].nodes[{node_index}]"),
                "empty tag",
            ));
        }
        if node == &outbound.tag {
            return Err(fail(
                format!("outbounds[{index}].nodes[{node_index}]"),
                "refers to itself",
            ));
        }
        let Some(candidate) = outbounds.iter().find(|item| &item.tag == node) else {
            return Err(fail(
                format!("outbounds[{index}].nodes[{node_index}]"),
                format!("unknown '{node}'"),
            ));
        };
        if candidate.protocol == OutboundProtocol::Selector {
            return Err(fail(
                format!("outbounds[{index}].nodes[{node_index}]"),
                "nested selectors are not supported",
            ));
        }
    }
    Ok(())
}

fn validate_trojan(outbound: &Outbound, index: usize) -> Result<(), ConfigError> {
    reject_selector_fields(outbound, index)?;
    if outbound.method.is_some()
        || outbound.uuid.is_some()
        || outbound.xudp
        || outbound.mux
        || outbound.security.is_some()
    {
        return Err(fail(
            format!("outbounds[{index}]"),
            "trojan does not take method, uuid, xudp, mux, or security",
        ));
    }
    if outbound.transport.is_some() {
        return Err(fail(
            format!("outbounds[{index}].transport"),
            "only applies to vless or vmess",
        ));
    }
    let server_text = outbound
        .server
        .as_deref()
        .ok_or_else(|| fail(format!("outbounds[{index}].server"), "required for trojan"))?;
    let server = Endpoint::parse(server_text).map_err(|_| {
        fail(
            format!("outbounds[{index}].server"),
            format!("invalid endpoint '{server_text}'"),
        )
    })?;
    let password = outbound.password.as_deref().ok_or_else(|| {
        fail(
            format!("outbounds[{index}].password"),
            "required for trojan",
        )
    })?;
    if password.is_empty() {
        return Err(fail(
            format!("outbounds[{index}].password"),
            "must not be empty",
        ));
    }
    let tls = outbound
        .tls
        .as_ref()
        .ok_or_else(|| fail(format!("outbounds[{index}].tls"), "required for trojan"))?;
    validate_outbound_tls(tls, &server, index)
}

fn validate_vless(outbound: &Outbound, index: usize) -> Result<(), ConfigError> {
    reject_selector_fields(outbound, index)?;
    if outbound.method.is_some() || outbound.password.is_some() {
        return Err(fail(
            format!("outbounds[{index}]"),
            "vless does not take method or password",
        ));
    }
    if outbound.security.is_some() {
        return Err(fail(
            format!("outbounds[{index}].security"),
            "only applies to vmess",
        ));
    }
    if outbound.mux && outbound.xudp {
        return Err(fail(
            format!("outbounds[{index}]"),
            "mux and xudp are mutually exclusive",
        ));
    }
    let server_text = outbound
        .server
        .as_deref()
        .ok_or_else(|| fail(format!("outbounds[{index}].server"), "required for vless"))?;
    let server = Endpoint::parse(server_text).map_err(|_| {
        fail(
            format!("outbounds[{index}].server"),
            format!("invalid endpoint '{server_text}'"),
        )
    })?;
    let uuid = outbound
        .uuid
        .as_deref()
        .ok_or_else(|| fail(format!("outbounds[{index}].uuid"), "required for vless"))?;
    if !valid_uuid(uuid) {
        return Err(fail(format!("outbounds[{index}].uuid"), "invalid UUID"));
    }
    if let Some(tls) = outbound.tls.as_ref() {
        validate_outbound_tls(tls, &server, index)?;
    }
    validate_outbound_transport(outbound, index)
}

fn validate_vmess(outbound: &Outbound, index: usize) -> Result<(), ConfigError> {
    reject_selector_fields(outbound, index)?;
    if outbound.method.is_some() || outbound.password.is_some() || outbound.xudp {
        return Err(fail(
            format!("outbounds[{index}]"),
            "vmess does not take method, password, or xudp",
        ));
    }
    let server_text = outbound
        .server
        .as_deref()
        .ok_or_else(|| fail(format!("outbounds[{index}].server"), "required for vmess"))?;
    let server = Endpoint::parse(server_text).map_err(|_| {
        fail(
            format!("outbounds[{index}].server"),
            format!("invalid endpoint '{server_text}'"),
        )
    })?;
    let uuid = outbound
        .uuid
        .as_deref()
        .ok_or_else(|| fail(format!("outbounds[{index}].uuid"), "required for vmess"))?;
    if !valid_uuid(uuid) {
        return Err(fail(format!("outbounds[{index}].uuid"), "invalid UUID"));
    }
    if let Some(tls) = outbound.tls.as_ref() {
        validate_outbound_tls(tls, &server, index)?;
    }
    validate_outbound_transport(outbound, index)
}

fn validate_outbound_tls(tls: &Tls, server: &Endpoint, index: usize) -> Result<(), ConfigError> {
    if let Some(sni) = tls.sni.as_deref() {
        if sni.is_empty() {
            return Err(fail(
                format!("outbounds[{index}].tls.sni"),
                "must not be empty",
            ));
        }
    }
    if !tls.insecure && tls.sni.is_none() && server.is_ip() {
        return Err(fail(
            format!("outbounds[{index}].tls.sni"),
            "required for an IP server",
        ));
    }
    if tls.insecure && !is_loopback(server) {
        return Err(fail(
            format!("outbounds[{index}].tls.insecure"),
            "only allowed for a loopback test server; use a trusted certificate",
        ));
    }
    if tls.handshake_timeout_s == 0 {
        return Err(fail(
            format!("outbounds[{index}].tls.handshake_timeout_s"),
            "must be positive",
        ));
    }
    let has_certificate = tls.client_certificate.is_some();
    let has_private_key = tls.client_private_key.is_some();
    if has_certificate != has_private_key {
        return Err(fail(
            format!("outbounds[{index}].tls.client_certificate"),
            "requires client_private_key and vice versa",
        ));
    }
    if let Some(value) = tls.client_certificate.as_deref() {
        if !valid_pem(value) {
            return Err(fail(
                format!("outbounds[{index}].tls.client_certificate"),
                "must be inline PEM (ADR-0023); file paths are not accepted",
            ));
        }
    }
    if let Some(value) = tls.client_private_key.as_deref() {
        if !valid_pem(value) {
            return Err(fail(
                format!("outbounds[{index}].tls.client_private_key"),
                "must be inline PEM (ADR-0023); file paths are not accepted",
            ));
        }
    }
    validate_alpn(
        tls.alpn.as_deref(),
        tls.required_alpn.as_deref(),
        &format!("outbounds[{index}].tls"),
    )
}

fn validate_outbound_transport(outbound: &Outbound, index: usize) -> Result<(), ConfigError> {
    let Some(transport) = outbound.transport.as_ref() else {
        return Ok(());
    };
    let base = format!("outbounds[{index}].transport");
    validate_transport_shape(transport, &base)?;

    match transport.network {
        StreamNetwork::Ws => {
            if let Some(tls) = outbound.tls.as_ref() {
                if let Some(alpn) = tls.alpn.as_deref() {
                    if !alpn.is_empty() && !contains(alpn, "http/1.1") {
                        return Err(fail(
                            format!("outbounds[{index}].tls.alpn"),
                            "must contain 'http/1.1' for the ws transport",
                        ));
                    }
                }
            }
        }
        StreamNetwork::H2 => {
            let tls = outbound.tls.as_ref().ok_or_else(|| {
                fail(
                    format!("outbounds[{index}].tls"),
                    "required for the h2 transport",
                )
            })?;
            if let Some(alpn) = tls.alpn.as_deref() {
                if !contains(alpn, "h2") {
                    return Err(fail(
                        format!("outbounds[{index}].tls.alpn"),
                        "must contain 'h2' for the h2 transport",
                    ));
                }
            }
            if let Some(required) = tls.required_alpn.as_deref() {
                if required != "h2" {
                    return Err(fail(
                        format!("outbounds[{index}].tls.required_alpn"),
                        "must be 'h2' for the h2 transport",
                    ));
                }
            }
        }
        StreamNetwork::Tcp => {}
    }
    Ok(())
}

fn validate_transport_shape(transport: &StreamTransport, base: &str) -> Result<(), ConfigError> {
    match transport.network {
        StreamNetwork::Tcp => {
            if transport.path != "/"
                || transport.host.is_some()
                || transport.compression
                || transport.subprotocols.is_some()
            {
                return Err(fail(
                    base.to_string(),
                    "tcp does not take path, host, compression, or subprotocols",
                ));
            }
        }
        StreamNetwork::Ws | StreamNetwork::H2 => {
            if !valid_path(&transport.path) {
                return Err(fail(
                    format!("{base}.path"),
                    format!("invalid path '{}'", transport.path),
                ));
            }
            if let Some(host) = transport.host.as_deref() {
                if !valid_host(host) {
                    return Err(fail(format!("{base}.host"), "invalid host"));
                }
            }
            if transport.network == StreamNetwork::H2 {
                if transport.compression || transport.subprotocols.is_some() {
                    return Err(fail(
                        base.to_string(),
                        "compression and subprotocols only apply to ws",
                    ));
                }
            } else if let Some(protocols) = transport.subprotocols.as_deref() {
                validate_subprotocols(protocols, base)?;
            }
        }
    }
    Ok(())
}

fn validate_subprotocols(protocols: &[String], base: &str) -> Result<(), ConfigError> {
    if protocols.len() > 16 {
        return Err(fail(format!("{base}.subprotocols"), "too many values"));
    }
    for (index, protocol) in protocols.iter().enumerate() {
        if protocol.is_empty() || protocol.len() > 64 || !is_http_token(protocol) {
            return Err(fail(
                format!("{base}.subprotocols[{index}]"),
                "invalid token",
            ));
        }
    }
    Ok(())
}

fn validate_alpn(
    protocols: Option<&[String]>, required: Option<&str>, base: &str,
) -> Result<(), ConfigError> {
    let list = protocols.unwrap_or(&[]);
    if list.is_empty() && required.is_some() {
        return Err(fail(
            format!("{base}.required_alpn"),
            "requires alpn protocols",
        ));
    }
    if list.len() > 32 {
        return Err(fail(format!("{base}.alpn"), "too many protocols"));
    }
    for (index, protocol) in list.iter().enumerate() {
        if protocol.is_empty() || protocol.len() > 255 {
            return Err(fail(
                format!("{base}.alpn[{index}]"),
                "invalid protocol name",
            ));
        }
        for previous in &list[..index] {
            if previous == protocol {
                return Err(fail(
                    format!("{base}.alpn[{index}]"),
                    format!("duplicate '{protocol}'"),
                ));
            }
        }
    }
    if let Some(needed) = required {
        if !list.iter().any(|protocol| protocol == needed) {
            return Err(fail(format!("{base}.required_alpn"), "not present in alpn"));
        }
    }
    Ok(())
}

fn validate_route(
    route: &Route, outbounds: &[Outbound], inbounds: &[Inbound],
) -> Result<(), ConfigError> {
    if !is_valid_route_target(&route.final_outbound, outbounds) {
        return Err(fail(
            "route.final",
            format!("unknown outbound '{}'", route.final_outbound),
        ));
    }
    for (index, rule) in route.rules.iter().enumerate() {
        if !is_valid_route_target(&rule.outbound, outbounds) {
            return Err(fail(
                format!("route.rules[{index}].outbound"),
                format!("unknown '{}'", rule.outbound),
            ));
        }
        validate_rule(rule, index, inbounds)?;
    }
    Ok(())
}

fn validate_rule(rule: &Rule, index: usize, inbounds: &[Inbound]) -> Result<(), ConfigError> {
    if let Some(domains) = rule.domain.as_deref() {
        for domain in domains {
            if domain.is_empty() {
                return Err(fail(format!("route.rules[{index}].domain"), "empty value"));
            }
        }
    }
    if let Some(suffixes) = rule.domain_suffix.as_deref() {
        for suffix in suffixes {
            if suffix.is_empty() {
                return Err(fail(
                    format!("route.rules[{index}].domain_suffix"),
                    "empty value",
                ));
            }
        }
    }
    validate_rule_values(
        rule.domain_keyword.as_deref(),
        &format!("route.rules[{index}].domain_keyword"),
        Some(128),
    )?;
    validate_rule_values(
        rule.domain_set.as_deref(),
        &format!("route.rules[{index}].domain_set"),
        Some(128),
    )?;
    validate_rule_values(
        rule.geoip.as_deref(),
        &format!("route.rules[{index}].geoip"),
        Some(128),
    )?;
    if let Some(cidrs) = rule.ip_cidr.as_deref() {
        for cidr in cidrs {
            if Cidr::parse(cidr).is_err() {
                return Err(fail(
                    format!("route.rules[{index}].ip_cidr"),
                    format!("invalid '{cidr}'"),
                ));
            }
        }
    }
    if let Some(ports) = rule.port.as_deref() {
        if ports.is_empty() {
            return Err(fail(
                format!("route.rules[{index}].port"),
                "must not be empty",
            ));
        }
    }
    validate_port_ranges(rule.port_range.as_deref(), index)?;
    validate_rule_inbounds(rule.inbound.as_deref(), index, inbounds)?;
    validate_rule_values(
        rule.process_name.as_deref(),
        &format!("route.rules[{index}].process_name"),
        Some(255),
    )?;
    validate_rule_values(
        rule.process_path.as_deref(),
        &format!("route.rules[{index}].process_path"),
        Some(4096),
    )?;
    Ok(())
}

fn validate_rule_values(
    values: Option<&[String]>, path: &str, max_len: Option<usize>,
) -> Result<(), ConfigError> {
    let Some(values) = values else {
        return Ok(());
    };
    if values.is_empty() {
        return Err(fail(path, "must not be empty"));
    }
    for (index, value) in values.iter().enumerate() {
        if value.is_empty() {
            return Err(fail(format!("{path}[{index}]"), "empty value"));
        }
        if value.contains('\0') {
            return Err(fail(format!("{path}[{index}]"), "must not contain NUL"));
        }
        if let Some(max_len) = max_len {
            if value.len() > max_len {
                return Err(fail(
                    format!("{path}[{index}]"),
                    format!("must be at most {max_len} bytes"),
                ));
            }
        }
        if values[..index].contains(value) {
            return Err(fail(format!("{path}[{index}]"), "duplicate value"));
        }
    }
    Ok(())
}

fn validate_port_ranges(ranges: Option<&[[u16; 2]]>, rule_index: usize) -> Result<(), ConfigError> {
    let Some(ranges) = ranges else {
        return Ok(());
    };
    if ranges.is_empty() {
        return Err(fail(
            format!("route.rules[{rule_index}].port_range"),
            "must not be empty",
        ));
    }
    for (index, &[start, end]) in ranges.iter().enumerate() {
        let path = format!("route.rules[{rule_index}].port_range[{index}]");
        if start > end {
            return Err(fail(path, "start must not exceed end"));
        }
        if ranges[..index].contains(&[start, end]) {
            return Err(fail(path, "duplicate range"));
        }
    }
    Ok(())
}

fn validate_rule_inbounds(
    tags: Option<&[String]>, rule_index: usize, inbounds: &[Inbound],
) -> Result<(), ConfigError> {
    let Some(tags) = tags else {
        return Ok(());
    };
    validate_rule_values(
        Some(tags),
        &format!("route.rules[{rule_index}].inbound"),
        None,
    )?;
    for (index, tag) in tags.iter().enumerate() {
        if !inbounds.iter().any(|inbound| inbound.tag == *tag) {
            return Err(fail(
                format!("route.rules[{rule_index}].inbound[{index}]"),
                format!("unknown inbound '{tag}'"),
            ));
        }
    }
    Ok(())
}

fn is_valid_route_target(tag: &str, outbounds: &[Outbound]) -> bool {
    tag == "direct" || tag == "reject" || outbounds.iter().any(|item| item.tag == tag)
}

fn reject_selector_fields(outbound: &Outbound, index: usize) -> Result<(), ConfigError> {
    if outbound.nodes.is_some() || outbound.strategy.is_some() || outbound.health_check.is_some() {
        return Err(fail(
            format!("outbounds[{index}]"),
            "group fields only apply to selector",
        ));
    }
    Ok(())
}

fn reject_vless_fields(outbound: &Outbound, index: usize) -> Result<(), ConfigError> {
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
    endpoint.ip().is_some_and(|ip| ip.is_loopback()) || endpoint.domain() == Some("localhost")
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
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Config, ConfigError> {
        Config::from_json(text)
    }

    fn error(text: &str) -> ConfigError {
        parse(text).expect_err("config should be rejected")
    }

    fn assert_path(error: ConfigError, expected: &str) {
        match error {
            ConfigError::Validate { path, .. } => assert_eq!(path, expected),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    fn assert_json_path(error: ConfigError, expected: &str) {
        match error {
            ConfigError::Json { path, .. } => assert_eq!(path, expected),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn default_config_is_valid() {
        assert!(parse("{}").is_ok());
    }

    #[test]
    fn rejects_unsupported_version() {
        assert_path(error(r#"{"version":1}"#), "version");
        assert_path(error(r#"{"version":3}"#), "version");
    }

    #[test]
    fn rejects_invalid_limits() {
        assert_path(
            error(r#"{"limits":{"max_connections":70000}}"#),
            "limits.max_connections",
        );
        assert_path(
            error(r#"{"limits":{"handshake_timeout_s":0}}"#),
            "limits.handshake_timeout_s",
        );
        assert_path(
            error(r#"{"limits":{"idle_timeout_s":86401}}"#),
            "limits.idle_timeout_s",
        );
    }

    #[test]
    fn rejects_duplicate_inbound_tags() {
        let text = r#"{"inbounds":[
            {"tag":"a","protocol":"socks5","listen":"127.0.0.1:1"},
            {"tag":"a","protocol":"socks5","listen":"127.0.0.1:2"}
        ]}"#;
        assert_path(error(text), "inbounds[1].tag");
    }

    #[test]
    fn rejects_domain_listen() {
        let text = r#"{"inbounds":[
            {"tag":"a","protocol":"socks5","listen":"localhost:1080"}
        ]}"#;
        assert_path(error(text), "inbounds[0].listen");
    }

    #[test]
    fn rejects_socks5_credentials() {
        let text = r#"{"inbounds":[
            {"tag":"a","protocol":"socks5","listen":"127.0.0.1:1080","password":"x"}
        ]}"#;
        assert_path(error(text), "inbounds[0]");
    }

    #[test]
    fn validates_shadowsocks_inbound() {
        let good = r#"{"inbounds":[{
            "tag":"ss","protocol":"shadowsocks","listen":"127.0.0.1:8388",
            "method":"2022-blake3-aes-128-gcm",
            "password":"MDEyMzQ1Njc4OWFiY2RlZg=="
        }]}"#;
        assert!(parse(good).is_ok());

        let bad_method = r#"{"inbounds":[{
            "tag":"ss","protocol":"shadowsocks","listen":"127.0.0.1:8388",
            "method":"aes-128-gcm","password":"MDEyMzQ1Njc4OWFiY2RlZg=="
        }]}"#;
        assert_path(error(bad_method), "inbounds[0].method");

        let bad_key = r#"{"inbounds":[{
            "tag":"ss","protocol":"shadowsocks","listen":"127.0.0.1:8388",
            "method":"2022-blake3-aes-128-gcm","password":"short"
        }]}"#;
        assert_path(error(bad_key), "inbounds[0].password");
    }

    #[test]
    fn rejects_file_paths_as_credentials() {
        let inbound_path = r#"{"inbounds":[{
            "tag":"vl","protocol":"vless","listen":"127.0.0.1:443",
            "uuid":"00000000-0000-0000-0000-000000000001",
            "tls":{"certificate":"/etc/marmo/server.pem",
                   "private_key":"-----BEGIN PRIVATE KEY----- x -----END PRIVATE KEY-----"}
        }]}"#;
        assert_path(error(inbound_path), "inbounds[0].tls.certificate");

        let outbound_path = r#"{"outbounds":[{
            "tag":"vl","protocol":"vless","server":"example.com:443",
            "uuid":"00000000-0000-0000-0000-000000000001",
            "tls":{"client_certificate":"/etc/marmo/client.pem",
                   "client_private_key":"-----BEGIN PRIVATE KEY----- x -----END PRIVATE KEY-----"}
        }]}"#;
        assert_path(error(outbound_path), "outbounds[0].tls.client_certificate");
    }

    #[test]
    fn validates_trojan_inbound() {
        let good = r#"{"inbounds":[{
            "tag":"tj","protocol":"trojan","listen":"127.0.0.1:443",
            "password":"secret",
            "tls":{"certificate":"-----BEGIN CERTIFICATE----- x -----END CERTIFICATE-----","private_key":"-----BEGIN PRIVATE KEY----- x -----END PRIVATE KEY-----"}
        }]}"#;
        assert!(parse(good).is_ok());

        let missing_tls = r#"{"inbounds":[{
            "tag":"tj","protocol":"trojan","listen":"127.0.0.1:443",
            "password":"secret"
        }]}"#;
        assert_path(error(missing_tls), "inbounds[0].tls");

        let bad_fallback = r#"{"inbounds":[{
            "tag":"tj","protocol":"trojan","listen":"127.0.0.1:443",
            "password":"secret","fallback":"not-an-endpoint",
            "tls":{"certificate":"-----BEGIN CERTIFICATE----- x -----END CERTIFICATE-----","private_key":"-----BEGIN PRIVATE KEY----- x -----END PRIVATE KEY-----"}
        }]}"#;
        assert_path(error(bad_fallback), "inbounds[0].fallback");
    }

    #[test]
    fn validates_vless_inbound() {
        let good = r#"{"inbounds":[{
            "tag":"vl","protocol":"vless","listen":"127.0.0.1:443",
            "uuid":"00000000-0000-0000-0000-000000000001",
            "tls":{"certificate":"-----BEGIN CERTIFICATE----- x -----END CERTIFICATE-----","private_key":"-----BEGIN PRIVATE KEY----- x -----END PRIVATE KEY-----"}
        }]}"#;
        assert!(parse(good).is_ok());

        let bad_uuid = r#"{"inbounds":[{
            "tag":"vl","protocol":"vless","listen":"127.0.0.1:443",
            "uuid":"nope",
            "tls":{"certificate":"-----BEGIN CERTIFICATE----- x -----END CERTIFICATE-----","private_key":"-----BEGIN PRIVATE KEY----- x -----END PRIVATE KEY-----"}
        }]}"#;
        assert_path(error(bad_uuid), "inbounds[0].uuid");

        let missing_ca = r#"{"inbounds":[{
            "tag":"vl","protocol":"vless","listen":"127.0.0.1:443",
            "uuid":"00000000-0000-0000-0000-000000000001",
            "tls":{"certificate":"-----BEGIN CERTIFICATE----- x -----END CERTIFICATE-----","private_key":"-----BEGIN PRIVATE KEY----- x -----END PRIVATE KEY-----","client_auth":"required"}
        }]}"#;
        assert_path(error(missing_ca), "inbounds[0].tls.client_ca");
    }

    #[test]
    fn validates_vmess() {
        let good = r#"{"inbounds":[{
            "tag":"vm","protocol":"vmess","listen":"127.0.0.1:1080",
            "uuid":"00000000-0000-0000-0000-000000000001"
        }],"outbounds":[{
            "tag":"vm","protocol":"vmess","server":"example.com:443",
            "uuid":"00000000-0000-0000-0000-000000000001",
            "security":"chacha20-poly1305"
        }]}"#;
        assert!(parse(good).is_ok());

        let ws_without_tls = r#"{"inbounds":[{
            "tag":"vm","protocol":"vmess","listen":"127.0.0.1:1080",
            "uuid":"00000000-0000-0000-0000-000000000001",
            "transport":{"network":"ws","path":"/ws"}
        }]}"#;
        assert_path(error(ws_without_tls), "inbounds[0].tls");

        let missing_uuid = r#"{"inbounds":[{
            "tag":"vm","protocol":"vmess","listen":"127.0.0.1:1080"
        }]}"#;
        assert_path(error(missing_uuid), "inbounds[0].uuid");

        let bad_security = r#"{"outbounds":[{
            "tag":"vm","protocol":"vmess","server":"example.com:443",
            "uuid":"00000000-0000-0000-0000-000000000001",
            "security":"none"
        }]}"#;
        assert_json_path(error(bad_security), "outbounds[0].security");

        let vless_security = r#"{"outbounds":[{
            "tag":"vl","protocol":"vless","server":"example.com:443",
            "uuid":"00000000-0000-0000-0000-000000000001",
            "security":"aes-128-gcm"
        }]}"#;
        assert_path(error(vless_security), "outbounds[0].security");

        let vmess_xudp = r#"{"outbounds":[{
            "tag":"vm","protocol":"vmess","server":"example.com:443",
            "uuid":"00000000-0000-0000-0000-000000000001",
            "xudp":true
        }]}"#;
        assert_path(error(vmess_xudp), "outbounds[0]");

        let h2_without_tls = r#"{"outbounds":[{
            "tag":"vm","protocol":"vmess","server":"example.com:443",
            "uuid":"00000000-0000-0000-0000-000000000001",
            "transport":{"network":"h2"}
        }]}"#;
        assert_path(error(h2_without_tls), "outbounds[0].tls");
    }

    #[test]
    fn validates_mux_option() {
        let vless = r#"{"outbounds":[{
            "tag":"vl","protocol":"vless","server":"example.com:443",
            "uuid":"00000000-0000-0000-0000-000000000001","mux":true
        }]}"#;
        assert!(parse(vless).is_ok());

        let vmess = r#"{"outbounds":[{
            "tag":"vm","protocol":"vmess","server":"example.com:443",
            "uuid":"00000000-0000-0000-0000-000000000001","mux":true
        }]}"#;
        assert!(parse(vmess).is_ok());

        let both = r#"{"outbounds":[{
            "tag":"vl","protocol":"vless","server":"example.com:443",
            "uuid":"00000000-0000-0000-0000-000000000001",
            "mux":true,"xudp":true
        }]}"#;
        assert_path(error(both), "outbounds[0]");

        let trojan = r#"{"outbounds":[{
            "tag":"tr","protocol":"trojan","server":"example.com:443",
            "password":"secret","tls":{"insecure":true},"mux":true
        }]}"#;
        assert_path(error(trojan), "outbounds[0]");

        let direct = r#"{"outbounds":[{
            "tag":"d","protocol":"direct","mux":true
        }]}"#;
        assert_path(error(direct), "outbounds[0]");
    }

    #[test]
    fn validates_transport_shapes() {
        let tcp_with_path = r#"{"inbounds":[{
            "tag":"vl","protocol":"vless","listen":"127.0.0.1:443",
            "uuid":"00000000-0000-0000-0000-000000000001",
            "tls":{"certificate":"-----BEGIN CERTIFICATE----- x -----END CERTIFICATE-----","private_key":"-----BEGIN PRIVATE KEY----- x -----END PRIVATE KEY-----"},
            "transport":{"network":"tcp","path":"/x"}
        }]}"#;
        assert_path(error(tcp_with_path), "inbounds[0].transport");

        let h2_without_tls = r#"{"outbounds":[{
            "tag":"vl","protocol":"vless","server":"example.com:443",
            "uuid":"00000000-0000-0000-0000-000000000001",
            "transport":{"network":"h2"}
        }]}"#;
        assert_path(error(h2_without_tls), "outbounds[0].tls");

        let h2_without_alpn = r#"{"outbounds":[{
            "tag":"vl","protocol":"vless","server":"example.com:443",
            "uuid":"00000000-0000-0000-0000-000000000001",
            "tls":{"sni":"example.com"},
            "transport":{"network":"h2"}
        }]}"#;
        // No alpn list is allowed; only a present list must contain h2.
        let result = parse(h2_without_alpn);
        assert!(result.is_ok(), "unexpected error: {result:?}");

        let bad_ws_subprotocol = r#"{"outbounds":[{
            "tag":"vl","protocol":"vless","server":"example.com:443",
            "uuid":"00000000-0000-0000-0000-000000000001",
            "transport":{"network":"ws","subprotocols":["bad token"]}
        }]}"#;
        assert_path(
            error(bad_ws_subprotocol),
            "outbounds[0].transport.subprotocols[0]",
        );
    }

    #[test]
    fn rejects_reserved_outbound_tags() {
        assert_path(
            error(r#"{"outbounds":[{"tag":"reject","protocol":"direct"}]}"#),
            "outbounds[0].tag",
        );
        assert_path(
            error(
                r#"{"outbounds":[{"tag":"direct","protocol":"http","server":"example.com:80"}]}"#,
            ),
            "outbounds[0].tag",
        );
    }

    #[test]
    fn validates_direct_and_http() {
        assert_path(
            error(r#"{"outbounds":[{"tag":"d","protocol":"direct","server":"example.com:80"}]}"#),
            "outbounds[0]",
        );
        assert_path(
            error(r#"{"outbounds":[{"tag":"h","protocol":"http"}]}"#),
            "outbounds[0].server",
        );
        assert!(
            parse(r#"{"outbounds":[{"tag":"h","protocol":"http","server":"example.com:80"}]}"#)
                .is_ok()
        );
    }

    #[test]
    fn validates_sniffing_options() {
        let all = r#"{"inbounds":[{
            "tag":"s","protocol":"socks5","listen":"127.0.0.1:1080",
            "sniffing":{"enabled":true}
        }]}"#;
        assert!(parse(all).is_ok());

        let none = r#"{"inbounds":[{
            "tag":"s","protocol":"socks5","listen":"127.0.0.1:1080",
            "sniffing":{"enabled":false,"protocols":["tls"]}
        }]}"#;
        assert_path(error(none), "inbounds[0].sniffing.protocols");

        let empty = r#"{"inbounds":[{
            "tag":"s","protocol":"socks5","listen":"127.0.0.1:1080",
            "sniffing":{"enabled":true,"protocols":[]}
        }]}"#;
        assert_path(error(empty), "inbounds[0].sniffing.protocols");

        let duplicate = r#"{"inbounds":[{
            "tag":"s","protocol":"socks5","listen":"127.0.0.1:1080",
            "sniffing":{"enabled":true,"protocols":["tls","tls"]}
        }]}"#;
        assert_path(error(duplicate), "inbounds[0].sniffing.protocols[1]");

        let unknown = r#"{"inbounds":[{
            "tag":"s","protocol":"socks5","listen":"127.0.0.1:1080",
            "sniffing":{"enabled":true,"unknown":true}
        }]}"#;
        assert_json_path(error(unknown), "inbounds[0].sniffing.unknown");
    }

    #[test]
    fn validates_selectors() {
        let unknown = r#"{"outbounds":[
            {"tag":"s","protocol":"selector","nodes":["missing"],"strategy":"manual"}
        ]}"#;
        assert_path(error(unknown), "outbounds[0].nodes[0]");

        let self_ref = r#"{"outbounds":[
            {"tag":"s","protocol":"selector","nodes":["s"],"strategy":"manual"}
        ]}"#;
        assert_path(error(self_ref), "outbounds[0].nodes[0]");

        let nested = r#"{"outbounds":[
            {"tag":"a","protocol":"selector","nodes":["b"],"strategy":"manual"},
            {"tag":"b","protocol":"selector","nodes":["a"],"strategy":"manual"}
        ]}"#;
        assert_path(error(nested), "outbounds[0].nodes[0]");

        let bad_health = r#"{"outbounds":[
            {"tag":"a","protocol":"direct"},
            {"tag":"s","protocol":"selector","nodes":["a"],"strategy":"manual",
             "health_check":{"target":"example.com:443","interval_s":5,"timeout_s":10}}
        ]}"#;
        assert_path(error(bad_health), "outbounds[1].health_check");
    }

    #[test]
    fn restricts_insecure_tls_to_loopback() {
        let loopback = r#"{"outbounds":[{
            "tag":"t","protocol":"trojan","server":"127.0.0.1:443",
            "password":"secret","tls":{"insecure":true}
        }]}"#;
        assert!(parse(loopback).is_ok());

        let public = r#"{"outbounds":[{
            "tag":"t","protocol":"trojan","server":"example.com:443",
            "password":"secret","tls":{"insecure":true}
        }]}"#;
        assert_path(error(public), "outbounds[0].tls.insecure");
    }

    #[test]
    fn validates_tls_and_alpn() {
        let certificate_without_key = r#"{"outbounds":[{
            "tag":"t","protocol":"trojan","server":"example.com:443",
            "password":"secret","tls":{"client_certificate":"-----BEGIN CERTIFICATE----- x -----END CERTIFICATE-----"}
        }]}"#;
        assert_path(
            error(certificate_without_key),
            "outbounds[0].tls.client_certificate",
        );

        let missing_sni = r#"{"outbounds":[{
            "tag":"t","protocol":"trojan","server":"192.0.2.1:443",
            "password":"secret","tls":{}
        }]}"#;
        assert_path(error(missing_sni), "outbounds[0].tls.sni");

        let duplicate_alpn = r#"{"outbounds":[{
            "tag":"t","protocol":"trojan","server":"example.com:443",
            "password":"secret","tls":{"alpn":["h2","h2"]}
        }]}"#;
        assert_path(error(duplicate_alpn), "outbounds[0].tls.alpn[1]");

        let required_missing = r#"{"outbounds":[{
            "tag":"t","protocol":"trojan","server":"example.com:443",
            "password":"secret","tls":{"alpn":["h2"],"required_alpn":"http/1.1"}
        }]}"#;
        assert_path(error(required_missing), "outbounds[0].tls.required_alpn");
    }

    #[test]
    fn validates_process_bounds() {
        assert_path(
            error(r#"{"process":{"cache_ttl_s":3601}}"#),
            "process.cache_ttl_s",
        );
        assert_path(
            error(r#"{"process":{"lookup_timeout_ms":0}}"#),
            "process.lookup_timeout_ms",
        );
        assert_path(
            error(r#"{"process":{"max_inflight":1025}}"#),
            "process.max_inflight",
        );
        assert_path(
            error(r#"{"route":{"rules":[{"process_name":[""],"outbound":"direct"}]}}"#),
            "route.rules[0].process_name[0]",
        );
        assert_path(
            error(r#"{"route":{"rules":[{"process_path":["/a","/a"],"outbound":"direct"}]}}"#),
            "route.rules[0].process_path[1]",
        );
    }

    #[test]
    fn validates_route() {
        assert_path(error(r#"{"route":{"final":"missing"}}"#), "route.final");
        assert_path(
            error(r#"{"route":{"rules":[{"outbound":"missing"}]}}"#),
            "route.rules[0].outbound",
        );
        assert_path(
            error(r#"{"route":{"rules":[{"ip_cidr":["nope"],"outbound":"direct"}]}}"#),
            "route.rules[0].ip_cidr",
        );
        assert_path(
            error(r#"{"route":{"rules":[{"domain":[""],"outbound":"direct"}]}}"#),
            "route.rules[0].domain",
        );
        assert_path(
            error(r#"{"route":{"rules":[{"port":[],"outbound":"direct"}]}}"#),
            "route.rules[0].port",
        );
        assert_path(
            error(r#"{"route":{"rules":[{"domain_keyword":[""],"outbound":"direct"}]}}"#),
            "route.rules[0].domain_keyword[0]",
        );
        assert_path(
            error(r#"{"route":{"rules":[{"domain_set":[],"outbound":"direct"}]}}"#),
            "route.rules[0].domain_set",
        );
        assert_path(
            error(r#"{"route":{"rules":[{"geoip":["a","a"],"outbound":"direct"}]}}"#),
            "route.rules[0].geoip[1]",
        );
        assert_path(
            error(r#"{"route":{"rules":[{"port_range":[[9000,8000]],"outbound":"direct"}]}}"#),
            "route.rules[0].port_range[0]",
        );
        assert_path(
            error(r#"{"route":{"rules":[{"port_range":[],"outbound":"direct"}]}}"#),
            "route.rules[0].port_range",
        );
        let unknown_inbound = r#"{
          "inbounds":[{"tag":"socks","protocol":"socks5","listen":"127.0.0.1:1"}],
          "route":{"rules":[{"inbound":["missing"],"outbound":"direct"}]}
        }"#;
        assert_path(error(unknown_inbound), "route.rules[0].inbound[0]");
        let known_inbound = r#"{
          "inbounds":[{"tag":"socks","protocol":"socks5","listen":"127.0.0.1:1"}],
          "route":{"rules":[{"inbound":["socks"],"outbound":"direct"}]}
        }"#;
        assert!(parse(known_inbound).is_ok());
    }

    #[cfg(feature = "dns")]
    #[test]
    fn accepts_dns_for_builtin_and_injection() {
        assert!(parse(r#"{"dns":{}}"#).is_ok());
        let full = r#"{
          "dns": {
            "servers": [
              { "protocol": "https", "address": "1.1.1.1:443", "path": "/dns-query" },
              { "protocol": "tls", "address": "8.8.8.8:853", "server_name": "dns.google" }
            ],
            "fallback": [{ "protocol": "udp", "address": "1.0.0.1:53" }],
            "tls": { "ca": "pem" }
          }
        }"#;
        assert!(parse(full).is_ok());
    }

    #[cfg(feature = "dns")]
    #[test]
    fn rejects_bad_dns_addresses() {
        assert_path(
            error(r#"{"dns":{"servers":[{"protocol":"udp","address":"dns.example:53"}]}}"#),
            "dns.servers[0].address",
        );
        assert_path(
            error(r#"{"dns":{"servers":[{"protocol":"udp","address":"1.1.1.1:0"}]}}"#),
            "dns.servers[0].address",
        );
    }

    #[cfg(feature = "dns")]
    #[test]
    fn rejects_dns_protocol_fields() {
        assert_path(
            error(
                r#"{"dns":{"servers":[{"protocol":"udp","address":"1.1.1.1:53","server_name":"x"}]}}"#,
            ),
            "dns.servers[0].server_name",
        );
        assert_path(
            error(
                r#"{"dns":{"servers":[{"protocol":"tls","address":"1.1.1.1:853","path":"/x"}]}}"#,
            ),
            "dns.servers[0].path",
        );
        assert_path(
            error(
                r#"{"dns":{"servers":[{"protocol":"https","address":"1.1.1.1:443","path":"x"}]}}"#,
            ),
            "dns.servers[0].path",
        );
    }

    #[cfg(feature = "dns")]
    #[test]
    fn rejects_duplicate_dns_servers() {
        let text = r#"{"dns":{"servers":[
            {"protocol":"udp","address":"1.1.1.1:53"},
            {"protocol":"udp","address":"1.1.1.1:53"}
        ]}}"#;
        assert_path(error(text), "dns.servers[1]");
    }

    #[cfg(feature = "dns")]
    #[test]
    fn rejects_bad_dns_ranges() {
        assert_path(error(r#"{"dns":{"timeout_ms":99}}"#), "dns.timeout_ms");
        assert_path(error(r#"{"dns":{"max_inflight":0}}"#), "dns.max_inflight");
        assert_path(
            error(r#"{"dns":{"min_ttl_s":10,"max_ttl_s":5}}"#),
            "dns.min_ttl_s",
        );
        assert_path(
            error(r#"{"dns":{"negative_ttl_s":3601}}"#),
            "dns.negative_ttl_s",
        );
    }

    #[cfg(feature = "dns")]
    #[test]
    fn rejects_dns_fallback_without_servers() {
        assert_path(
            error(r#"{"dns":{"fallback":[{"protocol":"udp","address":"1.0.0.1:53"}]}}"#),
            "dns.fallback",
        );
    }

    #[cfg(feature = "dns")]
    #[test]
    fn rejects_too_many_dns_servers() {
        let servers = (1..=9)
            .map(|index| format!(r#"{{"protocol":"udp","address":"1.1.1.{index}:53"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let text = format!(r#"{{"dns":{{"servers":[{servers}]}}}}"#);
        assert_path(error(&text), "dns.servers");
    }
}
