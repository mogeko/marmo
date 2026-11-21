//! Rule compilation and allocation-free matching.
//!
//! Rules are compiled once from [`Config`] and evaluated in order; the first
//! match wins. `OutboundId` is the index into `Config::outbounds`, so an
//! `Instance` must build its outbound table in the same order.

use std::collections::HashMap;

use marmo_net::{Cidr, Endpoint, Network};
use thiserror::Error;

use crate::config::Config;

/// Index of an outbound in `Config::outbounds`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OutboundId(u32);

impl OutboundId {
    /// Builds an id from its index in `Config::outbounds`.
    #[must_use]
    pub const fn from_index(index: u32) -> Self {
        Self(index)
    }

    /// Returns the index in `Config::outbounds`.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.0
    }
}

/// Result of routing one connection or UDP session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    /// Dial this outbound.
    Route(OutboundId),
    /// Dial directly, ignoring configured outbounds.
    Direct,
    /// Reject the connection.
    Reject(RejectReason),
}

/// Why a connection was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectReason {
    /// No rule matched and the final action is not a route.
    NoRoute,
    /// An explicit `reject` target matched.
    Rule,
    /// The chosen outbound does not support this network.
    UnsupportedNetwork,
}

/// Immutable routing input for one connection or UDP session.
#[derive(Clone, Debug)]
pub struct Metadata<'a> {
    /// Transport network.
    pub network: Network,
    /// Client endpoint.
    pub source: Endpoint,
    /// Requested destination.
    pub destination: Endpoint,
    /// Domain from the inbound protocol or the sniffer, if known.
    pub domain: Option<&'a str>,
    /// Inbound tag, reserved for the future inbound matcher.
    pub inbound: Option<&'a str>,
}

/// A compiled rule list and its final action.
#[derive(Debug)]
pub struct Router {
    rules: Vec<CompiledRule>,
    final_action: Action,
}

impl Router {
    /// Compiles every rule and resolves outbound tags to ids.
    pub fn compile(config: &Config) -> Result<Self, RoutingError> {
        let mut outbounds = HashMap::with_capacity(config.outbounds.len());
        for (index, outbound) in config.outbounds.iter().enumerate() {
            let index = u32::try_from(index).map_err(|_| RoutingError::TooManyOutbounds)?;
            outbounds.insert(outbound.tag.as_str(), OutboundId::from_index(index));
        }

        let mut rules = Vec::with_capacity(config.route.rules.len());
        for (index, rule) in config.route.rules.iter().enumerate() {
            let path = format!("route.rules[{index}]");
            let cidrs = compile_cidrs(rule.ip_cidr.as_deref(), &path)?;
            rules.push(CompiledRule {
                domains: compile_domains(rule.domain.as_deref()),
                suffixes: compile_domains(rule.domain_suffix.as_deref()),
                cidrs,
                ports: rule.port.clone().unwrap_or_default(),
                network: rule.network,
                action: compile_action(&rule.outbound, format!("{path}.outbound"), &outbounds)?,
            });
        }

        let final_action = compile_action(
            &config.route.final_outbound,
            "route.final".into(),
            &outbounds,
        )?;
        Ok(Self {
            rules,
            final_action,
        })
    }

    /// Returns the first matching action, or the final action.
    #[must_use]
    pub fn route(&self, metadata: &Metadata<'_>) -> Action {
        self.rules
            .iter()
            .find(|rule| rule.matches(metadata))
            .map_or(self.final_action, |rule| rule.action)
    }
}

#[derive(Debug)]
struct CompiledRule {
    domains: Vec<Box<str>>,
    suffixes: Vec<Box<str>>,
    cidrs: Vec<Cidr>,
    ports: Vec<u16>,
    network: Option<Network>,
    action: Action,
}

impl CompiledRule {
    fn matches(&self, metadata: &Metadata<'_>) -> bool {
        if !self.domains.is_empty() {
            let Some(domain) = metadata.domain.or_else(|| metadata.destination.domain()) else {
                return false;
            };
            if !self
                .domains
                .iter()
                .any(|expected| expected.as_ref() == domain)
            {
                return false;
            }
        }

        if !self.suffixes.is_empty() {
            let Some(domain) = metadata.domain.or_else(|| metadata.destination.domain()) else {
                return false;
            };
            if !self
                .suffixes
                .iter()
                .any(|suffix| matches_suffix(domain, suffix))
            {
                return false;
            }
        }

        if !self.cidrs.is_empty() {
            let Some(address) = metadata.destination.ip() else {
                return false;
            };
            if !self.cidrs.iter().any(|cidr| cidr.contains(address)) {
                return false;
            }
        }

        if !self.ports.is_empty() && !self.ports.contains(&metadata.destination.port()) {
            return false;
        }

        if let Some(network) = self.network {
            if network != metadata.network {
                return false;
            }
        }
        true
    }
}

fn compile_domains(values: Option<&[String]>) -> Vec<Box<str>> {
    values
        .unwrap_or(&[])
        .iter()
        .map(|value| Box::<str>::from(value.as_str()))
        .collect()
}

fn compile_cidrs(values: Option<&[String]>, path: &str) -> Result<Vec<Cidr>, RoutingError> {
    let mut cidrs = Vec::with_capacity(values.map_or(0, <[String]>::len));
    for (index, value) in values.unwrap_or(&[]).iter().enumerate() {
        let cidr = Cidr::parse(value).map_err(|_| RoutingError::InvalidCidr {
            path: format!("{path}.ip_cidr[{index}]"),
            value: value.clone(),
        })?;
        cidrs.push(cidr);
    }
    Ok(cidrs)
}

fn compile_action(
    tag: &str, path: String, outbounds: &HashMap<&str, OutboundId>,
) -> Result<Action, RoutingError> {
    match tag {
        "direct" => Ok(Action::Direct),
        "reject" => Ok(Action::Reject(RejectReason::Rule)),
        _ => outbounds
            .get(tag)
            .copied()
            .map(Action::Route)
            .ok_or_else(|| RoutingError::UnknownOutbound {
                path,
                tag: tag.to_string(),
            }),
    }
}

/// Domain suffix match on label boundaries.
///
/// `www.example.com` matches `example.com`, but `notexample.com` does not.
/// A suffix that starts with `.` is matched literally.
fn matches_suffix(domain: &str, suffix: &str) -> bool {
    if domain == suffix {
        return true;
    }
    if domain.len() <= suffix.len() || !domain.ends_with(suffix) {
        return false;
    }
    if suffix.starts_with('.') {
        return true;
    }
    domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.'
}

/// Why a rule set could not be compiled.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RoutingError {
    /// A rule or the final action names a tag that does not exist.
    #[error("route target at {path} is unknown: {tag}")]
    UnknownOutbound {
        /// Field path, for example `route.rules[0].outbound`.
        path: String,
        /// The unresolved tag.
        tag: String,
    },
    /// A CIDR string was invalid.
    #[error("invalid CIDR at {path}: {value}")]
    InvalidCidr {
        /// Field path, for example `route.rules[0].ip_cidr[1]`.
        path: String,
        /// The rejected value.
        value: String,
    },
    /// The outbound table exceeds the `u32` id space.
    #[error("too many outbounds for a u32 id")]
    TooManyOutbounds,
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn router(json: &str) -> Router {
        let config = Config::from_json(json).expect("config");
        Router::compile(&config).expect("router")
    }

    fn metadata(domain: Option<&str>, destination: Endpoint, network: Network) -> Metadata<'_> {
        Metadata {
            network,
            source: Endpoint::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
            destination,
            domain,
            inbound: None,
        }
    }

    fn domain(name: &str, port: u16) -> Endpoint {
        Endpoint::from_domain(name, port).expect("domain")
    }

    fn ip(last: u8, port: u16) -> Endpoint {
        Endpoint::from_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, last)), port)
    }

    const ROUTES: &str = r#"{
      "outbounds": [
        { "tag": "proxy", "protocol": "direct" },
        { "tag": "blocked", "protocol": "direct" },
        { "tag": "group", "protocol": "selector", "nodes": ["proxy"], "strategy": "manual" }
      ],
      "route": {
        "rules": [
          { "domain": ["exact.example"], "outbound": "blocked" },
          { "domain_suffix": ["example.com"], "outbound": "proxy" },
          { "ip_cidr": ["10.0.0.0/8"], "port": [443], "network": "tcp", "outbound": "group" }
        ],
        "final": "direct"
      }
    }"#;

    #[test]
    fn suffix_matches_on_label_boundaries() {
        assert!(matches_suffix("example.com", "example.com"));
        assert!(matches_suffix("www.example.com", "example.com"));
        assert!(matches_suffix("www.example.com", ".example.com"));
        assert!(!matches_suffix("notexample.com", "example.com"));
        assert!(!matches_suffix("example.com.evil", "example.com"));
    }

    #[test]
    fn routes_by_suffix_and_exact_domain() {
        let router = router(ROUTES);
        let suffix = metadata(None, domain("www.example.com", 443), Network::Tcp);
        assert_eq!(
            router.route(&suffix),
            Action::Route(OutboundId::from_index(0))
        );

        let exact = metadata(None, domain("exact.example", 443), Network::Tcp);
        assert_eq!(
            router.route(&exact),
            Action::Route(OutboundId::from_index(1))
        );

        let no_match = metadata(None, domain("notexample.com", 443), Network::Tcp);
        assert_eq!(router.route(&no_match), Action::Direct);
    }

    #[test]
    fn metadata_domain_overrides_ip_destination() {
        let router = router(ROUTES);
        let metadata = metadata(Some("www.example.com"), ip(9, 443), Network::Tcp);
        assert_eq!(
            router.route(&metadata),
            Action::Route(OutboundId::from_index(0))
        );
    }

    #[test]
    fn cidr_port_and_network_are_anded() {
        let router = router(ROUTES);
        let match_all = metadata(None, ip(1, 443), Network::Tcp);
        assert_eq!(
            router.route(&match_all),
            Action::Route(OutboundId::from_index(2))
        );

        let wrong_port = metadata(None, ip(1, 80), Network::Tcp);
        assert_eq!(router.route(&wrong_port), Action::Direct);

        let wrong_network = metadata(None, ip(1, 443), Network::Udp);
        assert_eq!(router.route(&wrong_network), Action::Direct);

        let outside = metadata(
            None,
            Endpoint::from_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443),
            Network::Tcp,
        );
        assert_eq!(router.route(&outside), Action::Direct);
    }

    #[test]
    fn cidr_does_not_match_domains() {
        let router = router(ROUTES);
        let metadata = metadata(None, domain("10.0.0.1", 443), Network::Tcp);
        assert_eq!(router.route(&metadata), Action::Direct);
    }

    #[test]
    fn first_match_wins() {
        let router = router(
            r#"{
              "outbounds": [
                { "tag": "a", "protocol": "direct" },
                { "tag": "b", "protocol": "direct" }
              ],
              "route": {
                "rules": [
                  { "domain_suffix": ["example.com"], "outbound": "a" },
                  { "domain_suffix": ["www.example.com"], "outbound": "b" }
                ],
                "final": "direct"
              }
            }"#,
        );
        let metadata = metadata(None, domain("www.example.com", 443), Network::Tcp);
        assert_eq!(
            router.route(&metadata),
            Action::Route(OutboundId::from_index(0))
        );
    }

    #[test]
    fn empty_rule_matches_everything() {
        let router = router(
            r#"{
              "outbounds": [{ "tag": "a", "protocol": "direct" }],
              "route": {
                "rules": [{ "outbound": "a" }],
                "final": "reject"
              }
            }"#,
        );
        let metadata = metadata(None, ip(1, 80), Network::Udp);
        assert_eq!(
            router.route(&metadata),
            Action::Route(OutboundId::from_index(0))
        );
    }

    #[test]
    fn final_reject_is_reported() {
        let router = router(
            r#"{
              "route": { "final": "reject" }
            }"#,
        );
        let metadata = metadata(None, ip(1, 80), Network::Tcp);
        assert_eq!(router.route(&metadata), Action::Reject(RejectReason::Rule));
    }

    #[test]
    fn rejects_unknown_targets_and_cidrs() {
        let mut config = Config::from_json(ROUTES).expect("config");
        config.route.rules[0].outbound = "missing".into();
        match Router::compile(&config) {
            Err(RoutingError::UnknownOutbound { path, tag }) => {
                assert_eq!(path, "route.rules[0].outbound");
                assert_eq!(tag, "missing");
            }
            other => panic!("unexpected: {other:?}"),
        }

        let mut config = Config::from_json(ROUTES).expect("config");
        config.route.rules[2].ip_cidr = Some(vec!["nope".into()]);
        match Router::compile(&config) {
            Err(RoutingError::InvalidCidr { path, value }) => {
                assert_eq!(path, "route.rules[2].ip_cidr[0]");
                assert_eq!(value, "nope");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
}
