//! Shared transport shape and ALPN validation.

use super::*;

pub(super) fn validate_transport_shape(
    transport: &StreamTransport, base: &str,
) -> Result<(), ConfigError> {
    match transport.network {
        StreamNetwork::Tcp => {
            if transport.path != "/"
                || transport.host.is_some()
                || transport.compression
                || transport.subprotocols.is_some()
                || transport.origins.is_some()
            {
                return Err(fail(
                    base.to_string(),
                    "tcp does not take path, host, compression, subprotocols, or origins",
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
            if let Some(host) = transport.host.as_deref()
                && !valid_host(host)
            {
                return Err(fail(format!("{base}.host"), "invalid host"));
            }
            if transport.network == StreamNetwork::H2 {
                if transport.compression
                    || transport.subprotocols.is_some()
                    || transport.origins.is_some()
                {
                    return Err(fail(
                        base.to_string(),
                        "compression, subprotocols, and origins only apply to ws",
                    ));
                }
            } else {
                if let Some(protocols) = transport.subprotocols.as_deref() {
                    validate_subprotocols(protocols, base)?;
                }
                if let Some(origins) = transport.origins.as_deref() {
                    marmo_transport::ws::validate_origins(origins)
                        .map_err(|message| fail(format!("{base}.origins"), message))?;
                }
            }
        }
    }
    Ok(())
}

pub(super) fn validate_subprotocols(protocols: &[String], base: &str) -> Result<(), ConfigError> {
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

pub(super) fn validate_alpn(
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
    if let Some(needed) = required
        && !list.iter().any(|protocol| protocol == needed)
    {
        return Err(fail(format!("{base}.required_alpn"), "not present in alpn"));
    }
    Ok(())
}
