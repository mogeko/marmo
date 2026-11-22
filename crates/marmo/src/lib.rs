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
mod inbound;
mod instance;
mod limits;
mod metrics;
mod mux;
mod outbound;
mod routing;
pub mod ruleset;
mod shadowsocks;
mod sniff;
mod supervisor;
mod trojan;
mod validate;
mod vless;
mod vmess;

pub use config::{Config, ConfigError};
pub use instance::{
    BindError, BoundAddr, BoundInstance, BuildError, Instance, InstanceBuilder, InstanceHandle,
    ServeError,
};
pub use limits::Limits;
pub use marmo_net::{Cidr, Endpoint, Network};
pub use metrics::{MetricEvent, MetricsSink, MetricsSnapshot};
pub use routing::{Action, Metadata, OutboundId, RejectReason, Router, RoutingError};
pub use ruleset::{DomainSet, IpSet, RuleSetError, RuleSets};
