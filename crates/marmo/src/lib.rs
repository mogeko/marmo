//! Public facade for marmo.
//!
//! R1 provides the `Limits` policy and the internal TCP engine (admission,
//! direct connect, relay, cancellation). The public `Instance`/`Config`
//! lifecycle lands with the R2 configuration schema; see
//! `docs/architecture.md` §14.
#![forbid(unsafe_code)]

mod direct;
mod limits;
mod supervisor;
// The engine is exercised by its tests until R2 wires it into `Instance`.
#[allow(dead_code)]
mod tcp_forward;

pub use limits::Limits;
