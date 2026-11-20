//! Public facade for marmo.
//!
//! `Config` is the strict v1 schema and `Instance` is the composition root:
//! build, bind, serve, and shut down. R2d supports direct outbounds and the
//! SOCKS5 CONNECT inbound; later phases add the remaining protocols.
#![forbid(unsafe_code)]

mod config;
mod direct;
mod inbound;
mod instance;
mod limits;
mod outbound;
mod routing;
mod shadowsocks;
mod supervisor;
mod trojan;
mod validate;

pub use config::{Config, ConfigError};
pub use instance::{
    BindError, BoundAddr, BoundInstance, BuildError, Instance, InstanceBuilder, InstanceHandle,
    ServeError,
};
pub use limits::Limits;
pub use marmo_net::{Cidr, Endpoint, Network};
pub use routing::{Action, Metadata, OutboundId, RejectReason, Router, RoutingError};
