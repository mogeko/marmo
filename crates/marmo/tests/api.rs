//! Public API construction checks.
//!
//! These tests use only names reachable from the crate root. They catch
//! schema types that are public fields of `Config` but not re-exported.

use marmo::{
    Config, ConfigLimits, Inbound, InboundProtocol, Outbound, OutboundProtocol, Route, Router,
};

#[test]
fn builds_a_config_programmatically() {
    let config = Config {
        version: 2,
        limits: ConfigLimits {
            max_connections: 8,
            handshake_timeout_s: 2,
            idle_timeout_s: 10,
            uplink_only_s: 1,
            downlink_only_s: 1,
        },
        process: Default::default(),
        dns: None,
        inbounds: vec![Inbound {
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
        }],
        outbounds: vec![Outbound {
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
        }],
        route: Route {
            rules: Vec::new(),
            final_outbound: "direct".into(),
        },
    };

    config.validate().expect("valid config");
    Router::compile(&config).expect("router");
}
