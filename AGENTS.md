# AGENTS.md

marmo is an embeddable Rust library for TCP/UDP proxying: L4/L7 inbounds,
multiple proxy protocols, rule-based routing, and latency-aware outbound
selection.

## Design gate

- Read `docs/architecture.md` and `docs/decisions/` before changing a boundary.
  A `Proposed` ADR is not approved: do not implement it.
- Accepted ADRs are immutable; supersede them with a new ADR instead of editing
  history.
- Keep `docs/architecture.md`, the ADR index, and this file in sync.
- `Instance` is the composition root; do not add a CLI, daemon, application
  layer, or process-level signal handling.

## Repo state

- The workspace is `crates/` with five crates: `marmo`, `marmo-proto`,
  `marmo-net`, `marmo-transport`, and `marmo-testkit`.
- The Rust implementation is the only implementation. The release line is
  `master`; unreleased changes may land on short-lived topic branches.
- Config schema is version 2; TLS credentials are inline PEM (ADR-0023).
- Runnable examples live in `crates/marmo/examples/`; fuzz targets in `fuzz/`.
- `docs/protocols/` records wire formats and interop; `docs/security/audit.md`
  records the threat model and open obligations.

## Toolchain

- Edition 2024, MSRV 1.87. Raise it only with a commit message naming the
  dependency that forced the change.
- tokio is the runtime. The library never creates or shuts down a runtime; the
  builder uses `Handle::try_current()` and may be given an explicit handle.
- `marmo-proto` and `marmo` are `#![forbid(unsafe_code)]`.
  `marmo-transport` denies unsafe by default; an unsafe block needs a written
  justification and a safety comment.
- No feature flag selects a backend or transport implementation.

## Style

- Safety first, then performance, then developer experience. Prefer explicit,
  boring code; fix known flaws instead of leaving debt.
- Untrusted bytes never cause a panic, undefined behavior, an unbounded read,
  or unbounded allocation. Return typed errors.
- Assertions prove programmer invariants; input validation uses errors.
  `assert` is removed in release builds; never rely on it for security.
- Functions should stay under 70 lines and lines under 100 columns; `cargo
  fmt` decides layout. Use four-space indentation.
- Files `snake_case.rs`; types `CamelCase`; functions, variables, and fields
  `snake_case`. Avoid abbreviations except common I/O and protocol terms.
- Public items need documentation. Errors are `thiserror` enums,
  `#[non_exhaustive]`; `anyhow` stays in examples and tests.
- No recursion on untrusted input. Bound every loop, queue, buffer, cache, and
  session table at initialization.
- Use fixed-width wire types and explicit endian conversion. Never pointer-cast
  network data; check before `as` casts.
- Zeroize secrets with `zeroize`; compare passwords, tokens, and tags in
  constant time. Never log payloads, credentials, UUIDs, keys, or SNI.
- Every bug fix adds a regression test; every decoder has a fuzz target.
- Codecs and routing stay free of I/O and tokio. TLS, HTTP/2, and WebSocket are
  upstream crates behind `marmo-transport` adapters; do not fork them.

## Commands

```sh
cargo test --workspace --locked
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo +1.87.0 test --workspace --locked
cargo audit
cargo tree --workspace --format '{l}'   # license review
cargo +nightly fuzz build
```

Run one test with `cargo test -p marmo --test <name>` or
`cargo test -p marmo-proto <filter>`. Loopback tests use port 0; never use
live third-party servers in tests.

CI runs the first four checks on Linux, macOS, and Windows. The copyleft check
and `cargo audit` run in the `Dependencies` workflow; the PR-only fuzz smoke
runs all decoder targets.

## Review checklist

- Bounds on every loop, queue, buffer, and session table.
- No allocation or panic on the packet path.
- Input validation uses errors; invariants use assertions.
- Endianness and casts explicit; secrets zeroized and constant-time compared.
- Cancellation leaves no half-authenticated session reachable.
- `cargo fmt`, `cargo test`, and `cargo clippy -D warnings` are clean.
