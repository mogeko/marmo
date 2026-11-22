//! Rule compilation and allocation-free matching.
//!
//! Rules are compiled once from [`Config`] and evaluated in order; the first
//! match wins. `OutboundId` is the index into `Config::outbounds`, so an
//! `Instance` must build its outbound table in the same order.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use marmo_net::{Cidr, Endpoint, Network};
use thiserror::Error;

use crate::config::Config;
use crate::process::ProcessInfo;
use crate::ruleset::{DomainSet, IpSet, RuleSets};

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
    /// Local process identity, when a resolver supplied one.
    pub process: Option<ProcessInfo>,
}

/// A compiled rule list and its final action.
pub struct Router {
    rules: Vec<CompiledRule>,
    final_action: Action,
    needs_process: bool,
}

impl fmt::Debug for Router {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Router")
            .field("rules", &self.rules.len())
            .field("final_action", &self.final_action)
            .field("needs_process", &self.needs_process)
            .finish()
    }
}

impl Router {
    /// Compiles every rule and resolves outbound tags to ids.
    ///
    /// Rule sets referenced by `domain_set` or `geoip` are missing from an
    /// empty registry, so configs that use them need
    /// [`Router::compile_with_sets`].
    pub fn compile(config: &Config) -> Result<Self, RoutingError> {
        Self::compile_with_sets(config, &RuleSets::default())
    }

    /// Compiles every rule against the supplied rule-set registry.
    pub fn compile_with_sets(config: &Config, sets: &RuleSets) -> Result<Self, RoutingError> {
        let mut outbounds = HashMap::with_capacity(config.outbounds.len());
        for (index, outbound) in config.outbounds.iter().enumerate() {
            let index = u32::try_from(index).map_err(|_| RoutingError::TooManyOutbounds)?;
            outbounds.insert(outbound.tag.as_str(), OutboundId::from_index(index));
        }

        let mut rules = Vec::with_capacity(config.route.rules.len());
        let mut needs_process = false;
        for (index, rule) in config.route.rules.iter().enumerate() {
            let path = format!("route.rules[{index}]");
            let cidrs = compile_cidrs(rule.ip_cidr.as_deref(), &path)?;
            let process_names = compile_values(rule.process_name.as_deref());
            let process_paths = compile_values(rule.process_path.as_deref());
            needs_process |= !process_names.is_empty() || !process_paths.is_empty();
            rules.push(CompiledRule {
                domains: compile_domains(rule.domain.as_deref()),
                suffixes: compile_domains(rule.domain_suffix.as_deref()),
                keywords: compile_keywords(
                    rule.domain_keyword.as_deref(),
                    &format!("{path}.domain_keyword"),
                )?,
                domain_sets: compile_domain_sets(rule.domain_set.as_deref(), &path, sets)?,
                cidrs,
                ip_sets: compile_ip_sets(rule.geoip.as_deref(), &path, sets)?,
                ports: rule.port.clone().unwrap_or_default(),
                port_ranges: compile_port_ranges(rule.port_range.as_deref()),
                network: rule.network,
                inbounds: compile_values(rule.inbound.as_deref()),
                process_names,
                process_paths,
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
            needs_process,
        })
    }

    /// Returns true when any rule has a process matcher.
    #[must_use]
    pub fn needs_process(&self) -> bool {
        self.needs_process
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

struct CompiledRule {
    domains: Vec<Box<str>>,
    suffixes: Vec<Box<str>>,
    keywords: Option<AhoCorasick>,
    domain_sets: Vec<Arc<dyn DomainSet>>,
    cidrs: Vec<Cidr>,
    ip_sets: Vec<Arc<dyn IpSet>>,
    ports: Vec<u16>,
    port_ranges: Vec<(u16, u16)>,
    network: Option<Network>,
    inbounds: Vec<Box<str>>,
    process_names: Vec<Box<str>>,
    process_paths: Vec<Box<str>>,
    action: Action,
}

impl CompiledRule {
    fn matches(&self, metadata: &Metadata<'_>) -> bool {
        let domain = metadata.domain.or_else(|| metadata.destination.domain());

        if !self.domains.is_empty() {
            let Some(domain) = domain else {
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
            let Some(domain) = domain else {
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

        if let Some(keywords) = self.keywords.as_ref() {
            let Some(domain) = domain else {
                return false;
            };
            if !keywords.is_match(domain) {
                return false;
            }
        }

        if !self.domain_sets.is_empty() {
            let Some(domain) = domain else {
                return false;
            };
            if !self.domain_sets.iter().any(|set| set.contains(domain)) {
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

        if !self.ip_sets.is_empty() {
            let Some(address) = metadata.destination.ip() else {
                return false;
            };
            if !self.ip_sets.iter().any(|set| set.contains(address)) {
                return false;
            }
        }

        if !self.ports.is_empty() && !self.ports.contains(&metadata.destination.port()) {
            return false;
        }

        if !self.port_ranges.is_empty()
            && !port_in_ranges(metadata.destination.port(), &self.port_ranges)
        {
            return false;
        }

        if let Some(network) = self.network {
            if network != metadata.network {
                return false;
            }
        }

        if !self.inbounds.is_empty() {
            let Some(inbound) = metadata.inbound else {
                return false;
            };
            if !self
                .inbounds
                .iter()
                .any(|expected| expected.as_ref() == inbound)
            {
                return false;
            }
        }

        if !self.process_names.is_empty() || !self.process_paths.is_empty() {
            let Some(process) = metadata.process.as_ref() else {
                return false;
            };
            if !self.process_names.is_empty() {
                let Some(name) = process.name() else {
                    return false;
                };
                if !self
                    .process_names
                    .iter()
                    .any(|expected| expected.as_ref() == name)
                {
                    return false;
                }
            }
            if !self.process_paths.is_empty() {
                let Some(path) = process.path() else {
                    return false;
                };
                if !self
                    .process_paths
                    .iter()
                    .any(|expected| expected.as_ref() == path)
                {
                    return false;
                }
            }
        }
        true
    }
}

fn compile_domains(values: Option<&[String]>) -> Vec<Box<str>> {
    values
        .unwrap_or(&[])
        .iter()
        .map(|value| Box::<str>::from(value.to_ascii_lowercase()))
        .collect()
}

fn compile_keywords(
    values: Option<&[String]>, path: &str,
) -> Result<Option<AhoCorasick>, RoutingError> {
    let Some(values) = values.filter(|values| !values.is_empty()) else {
        return Ok(None);
    };
    AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .build(values.iter().map(String::as_str))
        .map(Some)
        .map_err(|error| RoutingError::Keyword {
            path: path.to_owned(),
            reason: error.to_string(),
        })
}

fn compile_domain_sets(
    values: Option<&[String]>, path: &str, sets: &RuleSets,
) -> Result<Vec<Arc<dyn DomainSet>>, RoutingError> {
    let mut compiled = Vec::with_capacity(values.map_or(0, <[String]>::len));
    for (index, tag) in values.unwrap_or(&[]).iter().enumerate() {
        let set = sets
            .domain(tag)
            .cloned()
            .ok_or_else(|| RoutingError::UnknownDomainSet {
                path: format!("{path}.domain_set[{index}]"),
                tag: tag.clone(),
            })?;
        compiled.push(set);
    }
    Ok(compiled)
}

fn compile_ip_sets(
    values: Option<&[String]>, path: &str, sets: &RuleSets,
) -> Result<Vec<Arc<dyn IpSet>>, RoutingError> {
    let mut compiled = Vec::with_capacity(values.map_or(0, <[String]>::len));
    for (index, tag) in values.unwrap_or(&[]).iter().enumerate() {
        let set = sets
            .ip(tag)
            .cloned()
            .ok_or_else(|| RoutingError::UnknownIpSet {
                path: format!("{path}.geoip[{index}]"),
                tag: tag.clone(),
            })?;
        compiled.push(set);
    }
    Ok(compiled)
}

fn compile_port_ranges(values: Option<&[[u16; 2]]>) -> Vec<(u16, u16)> {
    let mut ranges: Vec<(u16, u16)> = values
        .unwrap_or(&[])
        .iter()
        .map(|&[start, end]| (start, end))
        .collect();
    ranges.sort_unstable();
    let mut merged: Vec<(u16, u16)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut() {
            if start <= last.1.saturating_add(1) {
                last.1 = last.1.max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    merged
}

fn compile_values(values: Option<&[String]>) -> Vec<Box<str>> {
    values
        .unwrap_or(&[])
        .iter()
        .map(|value| Box::<str>::from(value.as_str()))
        .collect()
}

fn port_in_ranges(port: u16, ranges: &[(u16, u16)]) -> bool {
    let index = ranges.partition_point(|&(start, _)| start <= port);
    index > 0 && ranges[index - 1].1 >= port
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
    /// A `domain_set` tag was not registered.
    #[error("unknown domain set at {path}: {tag}")]
    UnknownDomainSet {
        /// Field path, for example `route.rules[0].domain_set[1]`.
        path: String,
        /// The unresolved tag.
        tag: String,
    },
    /// A `geoip` tag was not registered.
    #[error("unknown IP set at {path}: {tag}")]
    UnknownIpSet {
        /// Field path, for example `route.rules[0].geoip[0]`.
        path: String,
        /// The unresolved tag.
        tag: String,
    },
    /// A keyword automaton could not be built.
    #[error("invalid keyword rule at {path}: {reason}")]
    Keyword {
        /// Field path, for example `route.rules[0].domain_keyword`.
        path: String,
        /// Why the automaton was rejected.
        reason: String,
    },
    /// The outbound table exceeds the `u32` id space.
    #[error("too many outbounds for a u32 id")]
    TooManyOutbounds,
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, RwLock};

    use super::*;

    struct TestDomainSet(Vec<&'static str>);

    impl DomainSet for TestDomainSet {
        fn contains(&self, domain: &str) -> bool {
            self.0.contains(&domain)
        }
    }

    struct TestIpSet(Vec<Cidr>);

    impl IpSet for TestIpSet {
        fn contains(&self, address: IpAddr) -> bool {
            self.0.iter().any(|cidr| cidr.contains(address))
        }
    }

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
            process: None,
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

    #[test]
    fn matches_keyword_port_range_inbound_and_sets() {
        let config = Config::from_json(
            r#"{
              "inbounds": [
                { "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:1" }
              ],
              "outbounds": [
                { "tag": "keyword", "protocol": "direct" },
                { "tag": "range", "protocol": "direct" },
                { "tag": "inbound", "protocol": "direct" },
                { "tag": "sites", "protocol": "direct" },
                { "tag": "geo", "protocol": "direct" }
              ],
              "route": {
                "rules": [
                  { "domain_keyword": ["tracker"], "outbound": "keyword" },
                  { "port_range": [[8000, 9000]], "outbound": "range" },
                  { "inbound": ["socks"], "outbound": "inbound" },
                  { "domain_set": ["sites"], "outbound": "sites" },
                  { "geoip": ["geo"], "outbound": "geo" }
                ],
                "final": "direct"
              }
            }"#,
        )
        .expect("config");

        let mut sets = RuleSets::new();
        sets.add_domain("sites", Arc::new(TestDomainSet(vec!["set.example"])))
            .expect("domain set");
        sets.add_ip(
            "geo",
            Arc::new(TestIpSet(vec![Cidr::parse("10.0.0.0/8").expect("cidr")])),
        )
        .expect("ip set");
        let router = Router::compile_with_sets(&config, &sets).expect("router");

        let keyword = metadata(None, domain("ads.tracker.example", 443), Network::Tcp);
        assert_eq!(
            router.route(&keyword),
            Action::Route(OutboundId::from_index(0))
        );

        let range = metadata(None, ip(1, 8500), Network::Tcp);
        assert_eq!(
            router.route(&range),
            Action::Route(OutboundId::from_index(1))
        );

        let mut inbound = metadata(None, ip(1, 443), Network::Tcp);
        inbound.inbound = Some("socks");
        assert_eq!(
            router.route(&inbound),
            Action::Route(OutboundId::from_index(2))
        );

        let sites = metadata(None, domain("set.example", 443), Network::Tcp);
        assert_eq!(
            router.route(&sites),
            Action::Route(OutboundId::from_index(3))
        );

        let geo = metadata(None, ip(5, 443), Network::Tcp);
        assert_eq!(router.route(&geo), Action::Route(OutboundId::from_index(4)));

        let missed = metadata(
            None,
            Endpoint::from_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443),
            Network::Tcp,
        );
        assert_eq!(router.route(&missed), Action::Direct);
    }

    #[test]
    fn keyword_range_and_inbound_are_anded() {
        let router = router(
            r#"{
              "inbounds": [
                { "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:1" }
              ],
              "outbounds": [{ "tag": "a", "protocol": "direct" }],
              "route": {
                "rules": [{
                  "domain_keyword": ["example"],
                  "port_range": [[443, 443]],
                  "inbound": ["socks"],
                  "outbound": "a"
                }],
                "final": "direct"
              }
            }"#,
        );
        let mut matched = metadata(None, domain("www.example.com", 443), Network::Tcp);
        matched.inbound = Some("socks");
        assert_eq!(
            router.route(&matched),
            Action::Route(OutboundId::from_index(0))
        );

        let mut wrong_inbound = metadata(None, domain("www.example.com", 443), Network::Tcp);
        wrong_inbound.inbound = Some("other");
        assert_eq!(router.route(&wrong_inbound), Action::Direct);

        let wrong_port = metadata(None, domain("www.example.com", 80), Network::Tcp);
        assert_eq!(router.route(&wrong_port), Action::Direct);
    }

    #[test]
    fn unknown_rule_sets_are_reported_with_paths() {
        let config = Config::from_json(
            r#"{
              "outbounds": [{ "tag": "a", "protocol": "direct" }],
              "route": {
                "rules": [
                  { "domain_set": ["missing"], "outbound": "a" },
                  { "geoip": ["missing"], "outbound": "a" }
                ],
                "final": "direct"
              }
            }"#,
        )
        .expect("config");

        match Router::compile(&config) {
            Err(RoutingError::UnknownDomainSet { path, tag }) => {
                assert_eq!(path, "route.rules[0].domain_set[0]");
                assert_eq!(tag, "missing");
            }
            other => panic!("unexpected: {other:?}"),
        }

        let mut sets = RuleSets::new();
        sets.add_domain("missing", Arc::new(TestDomainSet(Vec::new())))
            .expect("domain set");
        match Router::compile_with_sets(&config, &sets) {
            Err(RoutingError::UnknownIpSet { path, tag }) => {
                assert_eq!(path, "route.rules[1].geoip[0]");
                assert_eq!(tag, "missing");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    struct SwappableDomainSet(RwLock<&'static str>);

    impl DomainSet for SwappableDomainSet {
        fn contains(&self, domain: &str) -> bool {
            *self.0.read().expect("set lock") == domain
        }
    }

    #[test]
    fn provider_data_can_change_without_recompiling() {
        let config = Config::from_json(
            r#"{
              "outbounds": [{ "tag": "a", "protocol": "direct" }],
              "route": {
                "rules": [{ "domain_set": ["sites"], "outbound": "a" }],
                "final": "direct"
              }
            }"#,
        )
        .expect("config");
        let set = Arc::new(SwappableDomainSet(RwLock::new("one.example")));
        let mut sets = RuleSets::new();
        sets.add_domain("sites", set.clone()).expect("domain set");
        let router = Router::compile_with_sets(&config, &sets).expect("router");

        let first = metadata(None, domain("one.example", 443), Network::Tcp);
        assert_eq!(
            router.route(&first),
            Action::Route(OutboundId::from_index(0))
        );

        *set.0.write().expect("set lock") = "two.example";
        assert_eq!(router.route(&first), Action::Direct);
        let second = metadata(None, domain("two.example", 443), Network::Tcp);
        assert_eq!(
            router.route(&second),
            Action::Route(OutboundId::from_index(0))
        );
    }

    #[test]
    fn matches_process_name_and_path() {
        let router = router(
            r#"{
              "outbounds": [
                { "tag": "name", "protocol": "direct" },
                { "tag": "path", "protocol": "direct" }
              ],
              "route": {
                "rules": [
                  { "process_name": ["curl"], "outbound": "name" },
                  { "process_path": ["/usr/bin/git"], "outbound": "path" }
                ],
                "final": "direct"
              }
            }"#,
        );
        assert!(router.needs_process());

        let mut by_name = metadata(None, ip(1, 443), Network::Tcp);
        by_name.process = Some(ProcessInfo::new(Some(Arc::from("curl")), None));
        assert_eq!(
            router.route(&by_name),
            Action::Route(OutboundId::from_index(0))
        );

        let mut by_path = metadata(None, ip(1, 443), Network::Tcp);
        by_path.process = Some(ProcessInfo::new(
            Some(Arc::from("git")),
            Some(Arc::from("/usr/bin/git")),
        ));
        assert_eq!(
            router.route(&by_path),
            Action::Route(OutboundId::from_index(1))
        );

        let unknown = metadata(None, ip(1, 443), Network::Tcp);
        assert_eq!(router.route(&unknown), Action::Direct);
    }

    #[test]
    fn domains_are_compared_case_insensitively() {
        let router = router(
            r#"{
              "outbounds": [{ "tag": "a", "protocol": "direct" }],
              "route": {
                "rules": [{ "domain_suffix": ["EXAMPLE.COM"], "outbound": "a" }],
                "final": "direct"
              }
            }"#,
        );
        let metadata = metadata(None, domain("WWW.Example.COM", 443), Network::Tcp);
        assert_eq!(
            router.route(&metadata),
            Action::Route(OutboundId::from_index(0))
        );
    }
}
