//! Strict JSON configuration.
//!
//! This module is the data model and parser: unknown fields, duplicate fields,
//! bad enum tags, and oversized documents are rejected here. Semantic
//! validation (tag references, selector graphs, credential shapes) lives in
//! `validate`.

use std::fmt;
use std::str::FromStr;

use serde::Serialize;
use thiserror::Error;

mod raw;
mod schema;
mod secret;
mod typed;

pub(crate) use raw::{RawConfig, RawInbound, RawInboundProtocol, RawOutbound, RawOutboundProtocol};
pub use schema::{
    ClientAuth, Dns, DnsProtocol, DnsServer, DnsTls, HealthCheck, InboundTls, Limits, Process,
    Route, Rule, SniffProtocol, Sniffing, Strategy, StreamNetwork, StreamTransport, Tls,
    VmessSecurity,
};
pub use secret::SecretString;
pub use typed::{Inbound, Outbound};

/// Upper bound for a configuration document (4 MiB).
pub const MAX_CONFIG_BYTES: usize = 4 * 1024 * 1024;

/// The whole configuration document, after validation (ADR-0032).
///
/// The fields are private. Construct one with [`Config::from_json`] or
/// [`ConfigBuilder`], both of which reject invalid documents before returning.
#[derive(Clone, PartialEq)]
pub struct Config {
    pub(crate) inner: ConfigInner,
}

/// Validated configuration state.
#[derive(Clone, PartialEq)]
pub(crate) struct ConfigInner {
    pub(crate) version: u8,
    pub(crate) limits: Limits,
    pub(crate) process: Process,
    pub(crate) dns: Option<Dns>,
    pub(crate) inbounds: Vec<Inbound>,
    pub(crate) outbounds: Vec<Outbound>,
    pub(crate) route: Route,
}

impl Config {
    /// Parses strict JSON.
    ///
    /// The document is rejected before parsing when it exceeds
    /// [`MAX_CONFIG_BYTES`]. Unknown fields, duplicate fields, bad enum tags,
    /// and trailing data are errors carrying a JSON path. A parsed value is
    /// semantically valid.
    pub fn from_json(text: &str) -> Result<Self, ConfigError> {
        let raw = RawConfig::from_json(text)?;
        raw.validate()?;
        Ok(Self {
            inner: ConfigInner::from_raw(&raw)?,
        })
    }

    /// Starts a programmatic configuration.
    #[must_use]
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::new()
    }

    /// Schema version; only `2` is defined today.
    #[must_use]
    pub fn version(&self) -> u8 {
        self.inner.version
    }

    /// Returns the runtime limits derived from this configuration.
    #[must_use]
    pub fn limits(&self) -> crate::limits::RuntimeLimits {
        crate::limits::RuntimeLimits::from_config(&self.inner.limits)
    }

    /// Process-identity lookup bounds.
    #[must_use]
    pub fn process(&self) -> &Process {
        &self.inner.process
    }

    /// Optional DNS resolver policy.
    #[must_use]
    pub fn dns(&self) -> Option<&Dns> {
        self.inner.dns.as_ref()
    }

    /// Configured inbounds.
    #[must_use]
    pub fn inbounds(&self) -> &[Inbound] {
        &self.inner.inbounds
    }

    /// Configured outbounds.
    #[must_use]
    pub fn outbounds(&self) -> &[Outbound] {
        &self.inner.outbounds
    }

    /// Rule list and default action.
    #[must_use]
    pub fn route(&self) -> &Route {
        &self.inner.route
    }
}

/// Builds a validated [`Config`] without JSON.
///
/// Each call replaces or appends one section. [`ConfigBuilder::build`] runs the
/// same semantic validation as [`Config::from_json`].
#[derive(Clone)]
pub struct ConfigBuilder {
    limits: Limits,
    process: Process,
    dns: Option<Dns>,
    inbounds: Vec<Inbound>,
    outbounds: Vec<Outbound>,
    route: Route,
}

impl ConfigBuilder {
    /// Starts from schema defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            limits: Limits::default(),
            process: Process::default(),
            dns: None,
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            route: Route::default(),
        }
    }

    /// Replaces global connection and timeout limits.
    #[must_use]
    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Replaces process-identity lookup bounds.
    #[must_use]
    pub fn process(mut self, process: Process) -> Self {
        self.process = process;
        self
    }

    /// Replaces the optional DNS policy.
    #[must_use]
    pub fn dns(mut self, dns: Option<Dns>) -> Self {
        self.dns = dns;
        self
    }

    /// Appends one inbound.
    #[must_use]
    pub fn inbound(mut self, inbound: Inbound) -> Self {
        self.inbounds.push(inbound);
        self
    }

    /// Appends one outbound.
    #[must_use]
    pub fn outbound(mut self, outbound: Outbound) -> Self {
        self.outbounds.push(outbound);
        self
    }

    /// Replaces the rule list and default action.
    #[must_use]
    pub fn route(mut self, route: Route) -> Self {
        self.route = route;
        self
    }

    /// Validates the assembled configuration.
    pub fn build(self) -> Result<Config, ConfigError> {
        let raw = RawConfig {
            version: 2,
            limits: self.limits.clone(),
            process: self.process.clone(),
            dns: self.dns.clone(),
            inbounds: self.inbounds.iter().map(Inbound::to_raw).collect(),
            outbounds: self.outbounds.iter().map(Outbound::to_raw).collect(),
            route: self.route.clone(),
        };
        raw.validate()?;
        Ok(Config {
            inner: ConfigInner {
                version: 2,
                limits: self.limits,
                process: self.process,
                dns: self.dns,
                inbounds: self.inbounds,
                outbounds: self.outbounds,
                route: self.route,
            },
        })
    }
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for RawConfig {
    fn default() -> Self {
        Self {
            version: 2,
            limits: Limits::default(),
            process: Process::default(),
            dns: None,
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            route: Route::default(),
        }
    }
}

impl Serialize for Config {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let raw = RawConfig {
            version: self.inner.version,
            limits: self.inner.limits.clone(),
            process: self.inner.process.clone(),
            dns: self.inner.dns.clone(),
            inbounds: self.inner.inbounds.iter().map(Inbound::to_raw).collect(),
            outbounds: self.inner.outbounds.iter().map(Outbound::to_raw).collect(),
            route: self.inner.route.clone(),
        };
        raw.serialize(serializer)
    }
}

impl FromStr for Config {
    type Err = ConfigError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::from_json(text)
    }
}

/// Why a configuration document was rejected.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The document exceeded [`MAX_CONFIG_BYTES`].
    #[error("configuration exceeds {} bytes", MAX_CONFIG_BYTES)]
    TooLarge,
    /// The JSON was malformed, had unknown or duplicate fields, or bad values.
    #[error("invalid configuration JSON at {path}: {source}")]
    Json {
        /// JSON path reported by `serde_path_to_error`; `.` is the root.
        path: String,
        /// The underlying serde error.
        #[source]
        source: serde_json::Error,
    },
    /// The document parsed but violates a cross-field constraint.
    #[error("invalid configuration at {path}: {message}")]
    Validate {
        /// JSON-like field path, for example `inbounds[0].tag`.
        path: String,
        /// What is wrong.
        message: String,
    },
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print credentials: the config carries passwords and UUIDs.
        f.debug_struct("Config")
            .field("version", &self.inner.version)
            .field("limits", &self.inner.limits)
            .field(
                "dns",
                &self
                    .inner
                    .dns
                    .as_ref()
                    .map(|dns| (dns.servers.len(), dns.fallback.len())),
            )
            .field("inbounds", &self.inner.inbounds.len())
            .field("outbounds", &self.inner.outbounds.len())
            .field("route", &self.inner.route)
            .finish()
    }
}

#[cfg(test)]
mod tests;
