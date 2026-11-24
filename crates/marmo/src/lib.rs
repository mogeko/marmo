//! Public facade for marmo.
//!
//! `Config` is the strict version 2 schema and `Instance` is the composition
//! root: build, bind, serve, and shut down. R4 adds the `Outbound` and `Layer`
//! boundaries, selectors and health probes, metrics, and inline TLS
//! credentials.
#![forbid(unsafe_code)]

mod config;
mod deadline;
mod direct;
pub mod dns;
mod inbound;
mod instance;
mod limits;
mod metrics;
mod mux;
mod outbound;
pub mod process;
mod routing;
pub mod ruleset;
mod shadowsocks;
mod sniff;
mod supervisor;
mod trojan;
mod validate;
mod vless;
mod vmess;

pub use config::{
    ClientAuth, Config, ConfigError, Dns, DnsProtocol, DnsServer, DnsTls, HealthCheck, Inbound,
    InboundProtocol, InboundTls, Limits as ConfigLimits, MAX_CONFIG_BYTES, Outbound,
    OutboundProtocol, Process, Route, Rule, SniffProtocol, Sniffing, Strategy, StreamNetwork,
    StreamTransport, Tls, VmessSecurity,
};
pub use instance::{
    BindError, BoundAddr, BoundInstance, BuildError, Instance, InstanceBuilder, InstanceHandle,
    ServeError,
};
pub use limits::Limits;
pub use marmo_net::{Cidr, Endpoint, Network};
pub use metrics::{MetricEvent, MetricsSink, MetricsSnapshot};
pub use process::{ProcessInfo, ProcessRequest, ProcessResolver};
pub use routing::{Action, Metadata, OutboundId, RejectReason, Router, RoutingError};
pub use ruleset::{DomainSet, IpSet, RuleSetError, RuleSets};
