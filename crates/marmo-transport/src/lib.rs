//! Transport traits, adapters, and the bidirectional relay.
//!
//! The `AsyncStream`/`Datagram` bounds and the `Layer` composition are specified
//! in `docs/architecture.md` §8.2–§8.3. Adapters wrap upstream crates
//! (`rustls`, `tokio-tungstenite`, `h2`, `quinn`); this crate owns no protocol
//! parser it did not write itself.
#![deny(unsafe_code)]
