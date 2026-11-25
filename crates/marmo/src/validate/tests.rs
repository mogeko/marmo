use super::*;
use crate::config::Config;

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
        error(r#"{"outbounds":[{"tag":"direct","protocol":"http","server":"example.com:80"}]}"#),
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
        parse(r#"{"outbounds":[{"tag":"h","protocol":"http","server":"example.com:80"}]}"#).is_ok()
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

    let name = r#"{"outbounds":[{
            "tag":"t","protocol":"trojan","server":"localhost:443",
            "password":"secret","tls":{"insecure":true}
        }]}"#;
    assert_path(error(name), "outbounds[0].tls.insecure");
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
        error(r#"{"dns":{"servers":[{"protocol":"tls","address":"1.1.1.1:853","path":"/x"}]}}"#),
        "dns.servers[0].path",
    );
    assert_path(
        error(r#"{"dns":{"servers":[{"protocol":"https","address":"1.1.1.1:443","path":"x"}]}}"#),
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
