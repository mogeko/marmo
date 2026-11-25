//! Regression probe for UTF-8 domain suffix matching.

use marmo::{Action, Metadata, Router};
use marmo_net::{Endpoint, Network};

#[test]
fn unicode_domain_suffix_slicing() {
    let config: marmo::Config = r#"{
        "outbounds": [{ "tag": "a", "protocol": "direct" }],
        "route": { "rules": [ { "domain_suffix": ["a"], "outbound": "a" } ], "final": "direct" }
    }"#
    .parse()
    .expect("config");
    let router = Router::compile(&config).expect("router");
    let destination = Endpoint::from_domain("é", 443).expect("domain");
    let metadata = Metadata {
        network: Network::Tcp,
        source: Endpoint::from_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 1),
        destination,
        domain: None,
        inbound: None,
        process: None,
    };
    assert_eq!(router.route(&metadata), Action::Direct);
}
