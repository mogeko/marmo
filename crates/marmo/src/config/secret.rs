//! A zeroizing secret wrapper for configuration values.

use std::fmt;

use zeroize::Zeroizing;

/// A secret configuration value.
///
/// The value is zeroized on drop and never printed by `Debug`.
#[derive(Clone, PartialEq)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Wraps an owned secret.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// Exposes the secret to the library.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}
