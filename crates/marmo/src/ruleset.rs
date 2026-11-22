//! Injected domain and IP sets.
//!
//! The library defines the routing matchers; the embedder supplies the data.
//! A set implementation may be backed by a trie, a sorted array, a database
//! snapshot, or any other store. The contract is that [`DomainSet::contains`]
//! and [`IpSet::contains`] are non-blocking, allocation-free, bounded, and
//! panic-free. Set data is owned by the embedder and may be swapped behind the
//! handle; the router never reloads or inspects it.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use thiserror::Error;

/// Maximum number of tags in each registry (domain and IP).
pub const MAX_RULE_SETS: usize = 256;

/// A domain membership predicate supplied by the embedder.
///
/// `domain` is ASCII-lowercased and has no trailing dot. A suffix, keyword, or
/// exact-set implementation all fit this interface. Returning `false` on an
/// internal error is required: a failed lookup is a non-match, never a
/// connection failure.
pub trait DomainSet: Send + Sync {
    /// Returns true when `domain` belongs to this set.
    fn contains(&self, domain: &str) -> bool;
}

/// An IP membership predicate supplied by the embedder.
///
/// Returning `false` on an internal error is required: a failed lookup is a
/// non-match, never a connection failure.
pub trait IpSet: Send + Sync {
    /// Returns true when `address` belongs to this set.
    fn contains(&self, address: IpAddr) -> bool;
}

/// Why a rule-set tag could not be registered.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RuleSetError {
    /// The tag was empty.
    #[error("rule-set tag must not be empty")]
    EmptyTag,
    /// The same tag was registered twice in one registry.
    #[error("rule-set tag '{tag}' is registered twice")]
    Duplicate {
        /// The duplicated tag.
        tag: String,
    },
    /// A registry reached [`MAX_RULE_SETS`].
    #[error("at most {MAX_RULE_SETS} rule sets are allowed per registry")]
    TooMany,
}

/// Registered domain and IP sets, resolved by tag during routing compilation.
#[derive(Default)]
pub struct RuleSets {
    domains: HashMap<Box<str>, Arc<dyn DomainSet>>,
    ips: HashMap<Box<str>, Arc<dyn IpSet>>,
}

impl RuleSets {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a domain set under `tag`.
    pub fn add_domain(&mut self, tag: &str, set: Arc<dyn DomainSet>) -> Result<(), RuleSetError> {
        if tag.is_empty() {
            return Err(RuleSetError::EmptyTag);
        }
        if self.domains.contains_key(tag) {
            return Err(RuleSetError::Duplicate {
                tag: tag.to_owned(),
            });
        }
        if self.domains.len() >= MAX_RULE_SETS {
            return Err(RuleSetError::TooMany);
        }
        self.domains.insert(tag.into(), set);
        Ok(())
    }

    /// Registers an IP set under `tag`.
    pub fn add_ip(&mut self, tag: &str, set: Arc<dyn IpSet>) -> Result<(), RuleSetError> {
        if tag.is_empty() {
            return Err(RuleSetError::EmptyTag);
        }
        if self.ips.contains_key(tag) {
            return Err(RuleSetError::Duplicate {
                tag: tag.to_owned(),
            });
        }
        if self.ips.len() >= MAX_RULE_SETS {
            return Err(RuleSetError::TooMany);
        }
        self.ips.insert(tag.into(), set);
        Ok(())
    }

    pub(crate) fn domain(&self, tag: &str) -> Option<&Arc<dyn DomainSet>> {
        self.domains.get(tag)
    }

    pub(crate) fn ip(&self, tag: &str) -> Option<&Arc<dyn IpSet>> {
        self.ips.get(tag)
    }
}

impl fmt::Debug for RuleSets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuleSets")
            .field("domains", &self.domains.len())
            .field("ips", &self.ips.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Empty;

    impl DomainSet for Empty {
        fn contains(&self, _domain: &str) -> bool {
            false
        }
    }

    impl IpSet for Empty {
        fn contains(&self, _address: IpAddr) -> bool {
            false
        }
    }

    #[test]
    fn registers_and_resolves_sets() {
        let mut sets = RuleSets::new();
        sets.add_domain("domains", Arc::new(Empty)).expect("domain");
        sets.add_ip("ips", Arc::new(Empty)).expect("ip");
        assert!(sets.domain("domains").is_some());
        assert!(sets.ip("ips").is_some());
        assert!(sets.domain("missing").is_none());
    }

    #[test]
    fn rejects_empty_and_duplicate_tags() {
        let mut sets = RuleSets::new();
        assert!(matches!(
            sets.add_domain("", Arc::new(Empty)),
            Err(RuleSetError::EmptyTag)
        ));
        sets.add_domain("same", Arc::new(Empty)).expect("first");
        assert!(matches!(
            sets.add_domain("same", Arc::new(Empty)),
            Err(RuleSetError::Duplicate { .. })
        ));
    }

    #[test]
    fn caps_each_registry() {
        let mut sets = RuleSets::new();
        for index in 0..MAX_RULE_SETS {
            sets.add_domain(&format!("d{index}"), Arc::new(Empty))
                .expect("under cap");
        }
        assert!(matches!(
            sets.add_domain("last", Arc::new(Empty)),
            Err(RuleSetError::TooMany)
        ));
    }
}
