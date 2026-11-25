//! Public API construction checks.
//!
//! These tests use only names reachable from the crate root. They check that a
//! complete typed configuration can be built without JSON and that the builder
//! rejects the same invalid documents as `Config::from_json`.

use marmo::{
    Config, Endpoint, Inbound, Limits, Outbound, Route, Router, StreamNetwork, StreamTransport,
    Uuid,
};

#[test]
fn builds_a_config_programmatically() {
    let config = Config::builder()
        .limits(Limits {
            max_connections: 8,
            handshake_timeout_s: 2,
            idle_timeout_s: 10,
            uplink_only_s: 1,
            downlink_only_s: 1,
        })
        .inbound(Inbound::Socks5 {
            tag: "socks".into(),
            listen: Endpoint::parse("127.0.0.1:0").expect("listen"),
            sniffing: None,
        })
        .outbound(Outbound::Direct {
            tag: "direct".into(),
        })
        .route(Route {
            rules: Vec::new(),
            final_outbound: "direct".into(),
        })
        .build()
        .expect("valid config");

    assert_eq!(config.limits().max_connections, 8);
    assert_eq!(config.inbounds()[0].tag(), "socks");
    Router::compile(&config).expect("router");
}

#[test]
fn builder_rejects_semantically_invalid_config() {
    let error = Config::builder()
        .inbound(Inbound::Http {
            tag: String::new(),
            listen: Endpoint::parse("127.0.0.1:0").expect("listen"),
            sniffing: None,
        })
        .build()
        .expect_err("empty tag");
    assert!(error.to_string().contains("inbounds[0].tag"));
}

#[test]
fn builder_rejects_duplicate_tags_and_unknown_targets() {
    let duplicate = Config::builder()
        .outbound(Outbound::Direct {
            tag: "direct".into(),
        })
        .outbound(Outbound::Direct {
            tag: "direct".into(),
        })
        .build()
        .expect_err("duplicate tag");
    assert!(duplicate.to_string().contains("duplicate 'direct'"));

    let unknown = Config::builder()
        .outbound(Outbound::Direct {
            tag: "direct".into(),
        })
        .route(Route {
            rules: vec![marmo::Rule {
                domain: None,
                domain_suffix: None,
                domain_keyword: None,
                domain_set: None,
                ip_cidr: None,
                geoip: None,
                port: None,
                port_range: None,
                network: None,
                inbound: None,
                process_name: None,
                process_path: None,
                outbound: "missing".into(),
            }],
            final_outbound: "direct".into(),
        })
        .build()
        .expect_err("unknown target");
    assert!(unknown.to_string().contains("unknown 'missing'"));
}

#[test]
fn builder_applies_protocol_specific_validation() {
    let listen = Endpoint::parse("127.0.0.1:0").expect("listen");
    let ws = StreamTransport {
        network: StreamNetwork::Ws,
        path: "/".into(),
        ..StreamTransport::default()
    };
    let inbound = Config::builder()
        .inbound(Inbound::Vmess {
            tag: "vmess".into(),
            listen,
            uuid: Uuid::parse("00112233-4455-6677-8899-aabbccddeeff").expect("uuid"),
            tls: None,
            transport: Some(ws),
            sniffing: None,
        })
        .outbound(Outbound::Direct {
            tag: "direct".into(),
        })
        .build()
        .expect_err("ws without TLS");
    assert!(inbound.to_string().contains("inbounds[0].tls"));

    let outbound = Config::builder()
        .outbound(Outbound::Vless {
            tag: "vless".into(),
            server: Endpoint::parse("example.com:443").expect("server"),
            uuid: Uuid::parse("00112233-4455-6677-8899-aabbccddeeff").expect("uuid"),
            tls: None,
            transport: None,
            xudp: true,
            mux: true,
        })
        .build()
        .expect_err("mux and xudp");
    assert!(outbound.to_string().contains("mutually exclusive"));
}

#[test]
fn from_json_and_builder_agree() {
    let json = r#"{
      "inbounds": [
        { "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:0" }
      ],
      "outbounds": [ { "tag": "direct", "protocol": "direct" } ],
      "route": { "final": "direct" }
    }"#;
    let parsed = Config::from_json(json).expect("parse");
    let built = Config::builder()
        .inbound(Inbound::Socks5 {
            tag: "socks".into(),
            listen: Endpoint::parse("127.0.0.1:0").expect("listen"),
            sniffing: None,
        })
        .outbound(Outbound::Direct {
            tag: "direct".into(),
        })
        .route(Route {
            rules: Vec::new(),
            final_outbound: "direct".into(),
        })
        .build()
        .expect("build");
    assert_eq!(parsed.inbounds()[0].tag(), built.inbounds()[0].tag());
    assert_eq!(parsed.outbounds()[0].tag(), built.outbounds()[0].tag());
    assert_eq!(parsed.route(), built.route());
}
