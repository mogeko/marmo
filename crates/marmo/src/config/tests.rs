use super::*;
use marmo_net::Network;

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
          },
          "sniffing": { "enabled": true, "protocols": ["tls", "http2"] }
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
    assert_eq!(config.version(), 2);
    assert_eq!(config.limits().max_connections, 1024);
    assert_eq!(config.process(), &Process::default());
    assert!(config.dns().is_none());
    assert!(config.inbounds().is_empty());
    assert!(config.outbounds().is_empty());
    assert_eq!(config.route().final_outbound, "direct");
}

#[cfg(feature = "dns")]
#[test]
fn parses_dns_config() {
    let text = r#"{
          "dns": {
            "servers": [
              {
                "protocol": "https",
                "address": "1.1.1.1:443",
                "server_name": "cloudflare-dns.com",
                "path": "/dns-query"
              },
              { "protocol": "tls", "address": "8.8.8.8:853" }
            ],
            "fallback": [{ "protocol": "udp", "address": "1.0.0.1:53" }],
            "timeout_ms": 1500,
            "cache_capacity": 0,
            "tls": { "ca": "cert" }
          }
        }"#;
    let config = Config::from_json(text).expect("parse");
    let dns = config.dns().expect("dns");
    assert_eq!(dns.servers.len(), 2);
    assert_eq!(dns.servers[0].protocol, DnsProtocol::Https);
    assert_eq!(dns.servers[0].path.as_deref(), Some("/dns-query"));
    assert_eq!(dns.fallback[0].protocol, DnsProtocol::Udp);
    assert_eq!(dns.timeout_ms, 1500);
    assert_eq!(dns.cache_capacity, 0);
    assert_eq!(
        dns.tls.as_ref().and_then(|tls| tls.ca.as_deref()),
        Some("cert")
    );
}

#[cfg(not(feature = "dns"))]
#[test]
fn rejects_dns_when_feature_is_disabled() {
    let error = Config::from_json(r#"{"dns":{"servers":[]}}"#).expect_err("reject");
    match error {
        ConfigError::Validate { path, message } => {
            assert_eq!(path, "dns");
            assert!(message.contains("dns support is not compiled in"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn parses_full_config() {
    let config = Config::from_json(FULL).expect("parse");
    assert_eq!(config.limits().max_connections, 16);
    assert_eq!(config.limits().idle_timeout, None);

    let Inbound::Vless {
        tag,
        tls,
        transport,
        sniffing,
        ..
    } = &config.inbounds()[0]
    else {
        panic!("expected a VLESS inbound");
    };
    assert_eq!(tag, "in-vless");
    assert_eq!(
        transport.as_ref().expect("transport").network,
        StreamNetwork::Ws
    );
    assert!(transport.as_ref().expect("transport").compression);
    assert_eq!(tls.client_auth, ClientAuth::Required);
    let sniffing = sniffing.as_ref().expect("sniffing");
    assert!(sniffing.enabled);
    assert_eq!(
        sniffing.protocols.as_deref(),
        Some([SniffProtocol::Tls, SniffProtocol::Http2].as_slice())
    );

    let Outbound::Selector {
        strategy,
        health_check,
        ..
    } = &config.outbounds()[1]
    else {
        panic!("expected a selector outbound");
    };
    assert_eq!(*strategy, Strategy::LeastLatency);
    assert_eq!(health_check.as_ref().expect("health").interval_s, 10);
    assert_eq!(health_check.as_ref().expect("health").timeout_s, 5);

    let rule = &config.route().rules[0];
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
    let error =
        Config::from_json(r#"{"inbounds":[{"tag":"x","protocol":"nope","listen":"127.0.0.1:1"}]}"#)
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
    assert_eq!(config.version(), 2);
}

#[test]
fn parses_json_and_typed_accessors_agree() {
    let config = Config::from_json(FULL).expect("parse");
    assert_eq!(config.inbounds().len(), 1);
    assert_eq!(config.outbounds().len(), 2);
    assert_eq!(config.outbounds()[1].tag(), "group");
    assert_eq!(config.inbounds()[0].tag(), "in-vless");
}

#[test]
fn serializes_back_to_the_strict_schema() {
    let config = Config::from_json(FULL).expect("parse");
    let encoded = serde_json::to_string(&config).expect("encode");
    let decoded = Config::from_json(&encoded).expect("decode");
    assert_eq!(decoded, config);
}
