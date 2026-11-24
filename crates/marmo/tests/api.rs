//! Public API construction checks.
//!
//! These tests use only names reachable from the crate root. They check that a
//! complete configuration can be built without JSON and that the builder
//! rejects an invalid document at the same point as `Config::from_json`.

use marmo::{Config, Inbound, InboundProtocol, Limits, Outbound, OutboundProtocol, Route, Router};

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
        .inbound(Inbound {
            tag: "socks".into(),
            protocol: InboundProtocol::Socks5,
            listen: "127.0.0.1:0".into(),
            method: None,
            password: None,
            uuid: None,
            tls: None,
            transport: None,
            fallback: None,
            sniffing: None,
        })
        .outbound(Outbound {
            tag: "direct".into(),
            protocol: OutboundProtocol::Direct,
            server: None,
            method: None,
            password: None,
            uuid: None,
            tls: None,
            transport: None,
            xudp: false,
            mux: false,
            security: None,
            nodes: None,
            strategy: None,
            health_check: None,
        })
        .route(Route {
            rules: Vec::new(),
            final_outbound: "direct".into(),
        })
        .build()
        .expect("valid config");

    assert_eq!(config.limits().max_connections, 8);
    Router::compile(&config).expect("router");
}

#[test]
fn builder_rejects_semantically_invalid_config() {
    let error = Config::builder()
        .inbound(Inbound {
            tag: String::new(),
            protocol: InboundProtocol::Http,
            listen: "127.0.0.1:0".into(),
            method: None,
            password: None,
            uuid: None,
            tls: None,
            transport: None,
            fallback: None,
            sniffing: None,
        })
        .build()
        .expect_err("empty tag");
    assert!(error.to_string().contains("inbounds[0].tag"));
}
