//! DNS resolution, cache, and the public resolver override.
//!
//! The subsystem is compiled only with the `dns` Cargo feature. Without it a
//! zero-sized stub keeps the instance and dialer types unchanged while the
//! configuration validator rejects any `dns` block.

#[cfg(not(feature = "dns"))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct DnsRuntime;

#[cfg(feature = "dns")]
mod imp;

#[cfg(feature = "dns")]
pub use imp::{DnsAnswer, DnsError, DnsFuture, DnsResolver};
#[cfg(feature = "dns")]
pub(crate) use imp::{DnsBuildError, DnsRuntime};
