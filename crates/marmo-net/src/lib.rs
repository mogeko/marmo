//! Network primitives: endpoints, CIDR, socket options, and resolver policy.
//!
//! This crate must not depend on proxy protocols, tokio, or the facade. See
//! `docs/architecture.md` §6.
#![forbid(unsafe_code)]

mod cidr;
mod endpoint;
mod network;

pub use cidr::{Cidr, CidrError};
pub use endpoint::{DomainName, Endpoint, EndpointError, Host};
pub use network::Network;
