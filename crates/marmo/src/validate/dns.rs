//! DNS policy validation.

use super::*;

pub(super) fn validate_dns(dns: &ConfigDns) -> Result<(), ConfigError> {
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

pub(super) fn validate_dns_server(
    server: &DnsServer, path: &str,
) -> Result<SocketAddr, ConfigError> {
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
