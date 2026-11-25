//! Inbound protocol and transport validation.

use super::transport::{validate_alpn, validate_transport_shape};
use super::*;

pub(super) fn validate_inbounds(inbounds: &[RawInbound]) -> Result<(), ConfigError> {
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
            RawInboundProtocol::Socks5 | RawInboundProtocol::Http => {
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
            RawInboundProtocol::Shadowsocks => validate_shadowsocks_inbound(inbound, index)?,
            RawInboundProtocol::Trojan => validate_trojan_inbound(inbound, index)?,
            RawInboundProtocol::Vless => validate_vless_inbound(inbound, index)?,
            RawInboundProtocol::Vmess => validate_vmess_inbound(inbound, index)?,
        }
    }
    Ok(())
}

pub(super) fn validate_sniffing(
    sniffing: Option<&Sniffing>, index: usize,
) -> Result<(), ConfigError> {
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

pub(super) fn validate_shadowsocks_inbound(
    inbound: &RawInbound, index: usize,
) -> Result<(), ConfigError> {
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

pub(super) fn validate_trojan_inbound(
    inbound: &RawInbound, index: usize,
) -> Result<(), ConfigError> {
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

pub(super) fn validate_vless_inbound(
    inbound: &RawInbound, index: usize,
) -> Result<(), ConfigError> {
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

pub(super) fn validate_vmess_inbound(
    inbound: &RawInbound, index: usize,
) -> Result<(), ConfigError> {
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

pub(super) fn validate_inbound_tls(
    tls: &crate::config::InboundTls, index: usize,
) -> Result<(), ConfigError> {
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
    if !(1..=600).contains(&tls.handshake_timeout_s) {
        return Err(fail(
            format!("inbounds[{index}].tls.handshake_timeout_s"),
            "must be 1..600",
        ));
    }
    Ok(())
}

pub(super) fn validate_inbound_tls_auth(
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

pub(super) fn validate_inbound_transport(
    inbound: &RawInbound, index: usize, tls_required: bool,
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
            if let Some(alpn) = tls.alpn.as_deref()
                && !contains(alpn, "h2")
            {
                return Err(fail(
                    format!("inbounds[{index}].tls.alpn"),
                    "must contain 'h2' for the h2 transport",
                ));
            }
        }
        StreamNetwork::Ws => {
            if let Some(alpn) = tls.alpn.as_deref()
                && !alpn.is_empty()
                && !contains(alpn, "http/1.1")
            {
                return Err(fail(
                    format!("inbounds[{index}].tls.alpn"),
                    "must contain 'http/1.1' for the ws transport",
                ));
            }
        }
        StreamNetwork::Tcp => {}
    }
    Ok(())
}
