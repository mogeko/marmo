//! Outbound, selector, and transport validation.

use super::transport::{validate_alpn, validate_transport_shape};
use super::*;

pub(super) fn validate_outbounds(outbounds: &[RawOutbound]) -> Result<(), ConfigError> {
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
        if outbound.tag == "direct" && outbound.protocol != RawOutboundProtocol::Direct {
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
            RawOutboundProtocol::Direct => validate_direct(outbound, index)?,
            RawOutboundProtocol::Http => validate_http(outbound, index)?,
            RawOutboundProtocol::Shadowsocks => {
                validate_shadowsocks_outbound(outbound, index)?;
            }
            RawOutboundProtocol::Selector => {
                validate_selector(outbound, index, outbounds)?;
            }
            RawOutboundProtocol::Trojan => validate_trojan(outbound, index)?,
            RawOutboundProtocol::Vless => validate_vless(outbound, index)?,
            RawOutboundProtocol::Vmess => validate_vmess(outbound, index)?,
        }
    }
    Ok(())
}

pub(super) fn validate_direct(outbound: &RawOutbound, index: usize) -> Result<(), ConfigError> {
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

pub(super) fn validate_http(outbound: &RawOutbound, index: usize) -> Result<(), ConfigError> {
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

pub(super) fn validate_shadowsocks_outbound(
    outbound: &RawOutbound, index: usize,
) -> Result<(), ConfigError> {
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

pub(super) fn validate_selector(
    outbound: &RawOutbound, index: usize, outbounds: &[RawOutbound],
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
        if candidate.protocol == RawOutboundProtocol::Selector {
            return Err(fail(
                format!("outbounds[{index}].nodes[{node_index}]"),
                "nested selectors are not supported",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_trojan(outbound: &RawOutbound, index: usize) -> Result<(), ConfigError> {
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

pub(super) fn validate_vless(outbound: &RawOutbound, index: usize) -> Result<(), ConfigError> {
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

pub(super) fn validate_vmess(outbound: &RawOutbound, index: usize) -> Result<(), ConfigError> {
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

pub(super) fn validate_outbound_tls(
    tls: &Tls, server: &Endpoint, index: usize,
) -> Result<(), ConfigError> {
    if let Some(sni) = tls.sni.as_deref()
        && sni.is_empty()
    {
        return Err(fail(
            format!("outbounds[{index}].tls.sni"),
            "must not be empty",
        ));
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
    if !(1..=600).contains(&tls.handshake_timeout_s) {
        return Err(fail(
            format!("outbounds[{index}].tls.handshake_timeout_s"),
            "must be 1..600",
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
    if let Some(value) = tls.client_certificate.as_deref()
        && !valid_pem(value)
    {
        return Err(fail(
            format!("outbounds[{index}].tls.client_certificate"),
            "must be inline PEM (ADR-0023); file paths are not accepted",
        ));
    }
    if let Some(value) = tls.client_private_key.as_deref()
        && !valid_pem(value)
    {
        return Err(fail(
            format!("outbounds[{index}].tls.client_private_key"),
            "must be inline PEM (ADR-0023); file paths are not accepted",
        ));
    }
    validate_alpn(
        tls.alpn.as_deref(),
        tls.required_alpn.as_deref(),
        &format!("outbounds[{index}].tls"),
    )
}

pub(super) fn validate_outbound_transport(
    outbound: &RawOutbound, index: usize,
) -> Result<(), ConfigError> {
    let Some(transport) = outbound.transport.as_ref() else {
        return Ok(());
    };
    let base = format!("outbounds[{index}].transport");
    validate_transport_shape(transport, &base)?;

    match transport.network {
        StreamNetwork::Ws => {
            if let Some(tls) = outbound.tls.as_ref()
                && let Some(alpn) = tls.alpn.as_deref()
                && !alpn.is_empty()
                && !contains(alpn, "http/1.1")
            {
                return Err(fail(
                    format!("outbounds[{index}].tls.alpn"),
                    "must contain 'http/1.1' for the ws transport",
                ));
            }
        }
        StreamNetwork::H2 => {
            let tls = outbound.tls.as_ref().ok_or_else(|| {
                fail(
                    format!("outbounds[{index}].tls"),
                    "required for the h2 transport",
                )
            })?;
            if let Some(alpn) = tls.alpn.as_deref()
                && !contains(alpn, "h2")
            {
                return Err(fail(
                    format!("outbounds[{index}].tls.alpn"),
                    "must contain 'h2' for the h2 transport",
                ));
            }
            if let Some(required) = tls.required_alpn.as_deref()
                && required != "h2"
            {
                return Err(fail(
                    format!("outbounds[{index}].tls.required_alpn"),
                    "must be 'h2' for the h2 transport",
                ));
            }
        }
        StreamNetwork::Tcp => {}
    }
    Ok(())
}
