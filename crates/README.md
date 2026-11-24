# Rust workspace

Four crates, one dependency direction, no optional transport backends.

| Crate | Purpose | Published |
| --- | --- | --- |
| `marmo` | `Instance`, config, routing, inbounds, outbounds, metrics, public API | yes |
| `marmo-proto` | HTTP/1, SOCKS5, SS2022, Trojan, VLESS, VMess, Mux.Cool codecs; no I/O, no tokio | yes |
| `marmo-net` | `Endpoint`, CIDR, `Network`; no protocols | yes |
| `marmo-transport` | stream traits, `Layer` adapters (TLS/WS/H2), relay | yes |

Dependency direction: `marmo` → all; `marmo-proto` → `marmo-net` (address
parsing only); `marmo-net` → nothing. `marmo-transport` depends only on
upstream crates.

Every crate carries its own `README.md`, declared as `readme` in its manifest,
so the crates.io page documents that crate instead of the whole workspace. Keep
the crate README in step with its public API; cross-crate links must be absolute
URLs because crates.io renders only the package tarball.

## Commands

```sh
cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo audit
cargo tree --workspace --format '{l}'   # license review
```

CI runs the first three on Linux, macOS, and Windows, and the doc check on Linux.
The copyleft check and `cargo audit` run in a separate `Dependencies` workflow,
only when a manifest or `Cargo.lock` changes; Dependabot alerts cover advisories
for unchanged dependencies. `cargo-fuzz` runs on nightly only. Pushing a `vX.Y.Z`
tag runs the `Release` workflow.

## Rules

- Edition 2024, MSRV 1.88 in `Cargo.toml`. CI tests 1.88.0 and the current
  stable; raise the MSRV only with a commit message that names the dependency
  that forced it.
- `marmo-proto` and `marmo` are `#![forbid(unsafe_code)]`. `marmo-transport`
  denies unsafe by default; any block needs a written justification and a
  safety comment.
- No feature flag selects a backend or a transport implementation. The `dns`
  feature is a capability gate for the optional DNS subsystem (ADR-0030); it is
  off by default, and the default workspace suite runs without it. Other
  features are limited to test/bench support.
- Errors are `thiserror` enums, `#[non_exhaustive]`; `anyhow` stays in examples
  and tests. Config is schema version 2; TLS credentials are inline PEM
  (ADR-0023).
- Every `marmo-proto` decoder has a fuzz target and a fixture, including the
  HTTP/1 request and CONNECT response parser and Mux.Cool metadata. Every bug
  fix adds a regression test.
- Public items need documentation. `missing_docs` is denied by CI.
- License is MIT OR Apache-2.0. Dependency changes record a
  `cargo tree --format '{l}'` review; CI rejects GPL/AGPL/MPL. Apache-2.0-only
  crates are accepted; `cargo-audit` covers advisories.

See [`../docs/architecture.md`](../docs/architecture.md) and
[`../docs/decisions/`](../docs/decisions/) before changing a boundary.
