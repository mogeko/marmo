//! Network primitives: endpoints, CIDR, socket options, and resolver policy.
//!
//! This crate must not depend on proxy protocols, tokio, or the facade. See
//! `docs/architecture.md` §6.
#![forbid(unsafe_code)]
