//! Property tests for parsing boundaries that see untrusted text.

use marmo::{Config, Endpoint, Metadata, Network, Router};
use proptest::prelude::*;

const ROUTES: &str = r#"{
    "outbounds": [{ "tag": "a", "protocol": "direct" }],
    "route": {
        "rules": [{ "domain_suffix": ["a", "example.com"], "outbound": "a" }],
        "final": "direct"
    }
}"#;

proptest! {
    #[test]
    fn config_never_panics(text in "\\PC{0,2048}") {
        let _ = Config::from_json(&text);
    }

    #[test]
    fn endpoint_never_panics(text in "\\PC{0,128}") {
        let _ = Endpoint::parse(&text);
    }

    #[test]
    fn routing_compiles_or_errors(text in "\\PC{0,2048}") {
        if let Ok(config) = Config::from_json(&text) {
            let _ = Router::compile(&config);
        }
    }

    #[test]
    fn routing_never_panics_on_an_inbound_domain(domain in "\\PC{0,253}") {
        let config = Config::from_json(ROUTES).expect("routes");
        let router = Router::compile(&config).expect("router");
        let metadata = Metadata {
            network: Network::Tcp,
            source: Endpoint::from_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 1),
            destination: Endpoint::from_ip(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                443,
            ),
            domain: Some(&domain),
            inbound: None,
            process: None,
        };
        let _ = router.route(&metadata);
    }
}
