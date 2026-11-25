//! Build, bind, and serve failures.

use std::io;

use thiserror::Error;

use crate::routing::RoutingError;

/// Why an instance could not be built.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BuildError {
    /// The routing rules could not be compiled.
    #[error(transparent)]
    Routing(#[from] RoutingError),
    /// The configuration has process matchers but no resolver was injected.
    #[error("process rules require .process_resolver(...)")]
    MissingProcessResolver,
    /// The DNS runtime could not be built.
    #[error("invalid dns configuration: {reason}")]
    Dns {
        /// Why the resolver was rejected.
        reason: String,
    },
    /// An injected DNS resolver conflicts with built-in server fields.
    #[error("dns_resolver conflicts with dns.servers, dns.fallback, or dns.tls")]
    DnsResolverConflict,
    /// A rule-set tag could not be registered.
    #[error("rule set '{tag}' registration failed: {reason}")]
    RuleSet {
        /// The rejected tag.
        tag: String,
        /// Why registration failed.
        reason: String,
    },
    /// No tokio runtime was supplied and none is current.
    #[error("no tokio runtime; call .runtime(handle) or build inside a runtime")]
    NoRuntime,
    /// The listen endpoint is not an IP literal.
    #[error("inbound '{tag}' listen is not an IP endpoint: {listen}")]
    InboundListen {
        /// Inbound tag.
        tag: String,
        /// Configured listen string.
        listen: String,
    },
    /// The outbound server endpoint is missing or invalid.
    #[error("outbound '{tag}' has an invalid server: {value}")]
    OutboundEndpoint {
        /// Outbound tag.
        tag: String,
        /// Configured server string.
        value: String,
    },
    /// An inbound option could not be used.
    #[error("inbound '{tag}' has an invalid option: {reason}")]
    InboundOption {
        /// Inbound tag.
        tag: String,
        /// Why the option was rejected.
        reason: String,
    },
    /// An outbound option could not be used.
    #[error("outbound '{tag}' has an invalid option: {reason}")]
    OutboundOption {
        /// Outbound tag.
        tag: String,
        /// Why the option was rejected.
        reason: String,
    },
    /// The configured credentials could not be used.
    #[error("'{tag}' has invalid credentials: {reason}")]
    Credentials {
        /// Inbound or outbound tag.
        tag: String,
        /// Why the credentials were rejected.
        reason: String,
    },
}

/// Why binding failed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BindError {
    /// A selector graph was rejected while binding.
    #[error("selector '{tag}' failed: {reason}")]
    Selector {
        /// Selector tag.
        tag: String,
        /// Why the selector was rejected.
        reason: String,
    },
    /// A TLS configuration was rejected while binding.
    #[error("'{tag}' TLS setup failed: {reason}")]
    Tls {
        /// Inbound or outbound tag.
        tag: String,
        /// Why the TLS configuration was rejected.
        reason: String,
    },
    /// One inbound could not bind.
    #[error("inbound '{inbound}' failed to bind {address}: {source}")]
    Inbound {
        /// Inbound tag.
        inbound: String,
        /// Configured address.
        address: String,
        /// Underlying socket error.
        #[source]
        source: io::Error,
    },
}

/// Why serving stopped with an error.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ServeError {
    /// Binding failed before serving started.
    #[error(transparent)]
    Bind(#[from] BindError),
    /// A listener could not accept.
    #[error("inbound '{inbound}' accept failed: {source}")]
    Accept {
        /// Inbound tag.
        inbound: String,
        /// Underlying socket error.
        #[source]
        source: io::Error,
    },
    /// An inbound task panicked.
    #[error("inbound task failed: {0}")]
    Task(String),
}
