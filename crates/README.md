# Rust workspace

Four crates, one dependency direction, no optional transport backends.

| Crate | Purpose | Published |
| --- | --- | --- |
| `marmo` | `Instance`, config, routing, inbounds, outbounds, metrics, public API | yes |
| `marmo-proto` | HTTP/1, SOCKS5, SS2022, Trojan, VLESS, XUDP codecs; no I/O, no tokio | yes |
| `marmo-net` | `Endpoint`, CIDR, `Network`; no protocols | yes |
| `marmo-transport` | stream traits, `Layer` adapters (TLS/WS/H2), relay | yes |

Dependency direction: `marmo` → all; `marmo-proto` → `marmo-net` (address
parsing only); `marmo-net` → nothing. `marmo-transport` depends only on
upstream crates.

## Commands

```sh
cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo audit
cargo tree --workspace --format '{l}'   # license review
```

CI runs the first three on Linux, macOS, and Windows. The copyleft check and
`cargo audit` run in a separate `Dependencies` workflow, only when a manifest or
`Cargo.lock` changes; Dependabot alerts cover advisories for unchanged
dependencies. `cargo-fuzz` runs on nightly only. Pushing a `vX.Y.Z` tag runs the
`Release` workflow, which publishes the four published crates through
`crates-io-auth-action`; configure crates.io trusted publishing for
`.github/workflows/release.yml`, the `publish` job, and the `release`
environment first.

## Rules

- Edition 2024, MSRV 1.87 in `Cargo.toml`. CI tests 1.87.0 and the current
  stable; raise the MSRV only with a commit message that names the dependency
  that forced it.
- `marmo-proto` and `marmo` are `#![forbid(unsafe_code)]`. `marmo-transport`
  denies unsafe by default; any block needs a written justification and a
  safety comment.
- No feature flag selects a backend or a transport implementation. Features
  are limited to test/bench support.
- Errors are `thiserror` enums, `#[non_exhaustive]`; `anyhow` stays in examples
  and tests. Config is schema version 2; TLS credentials are inline PEM
  (ADR-0023).
- Every `marmo-proto` decoder has a fuzz target and a synthetic fixture,
  including the HTTP/1 request and CONNECT response parser. Every bug fix adds
  a regression test.
- Public items need documentation. `missing_docs` is denied by CI.
- License is MIT OR Apache-2.0. Dependency changes record a
  `cargo tree --format '{l}'` review; CI rejects GPL/AGPL/MPL. Apache-2.0-only
  crates are accepted; `cargo-audit` covers advisories.

See [`../docs/architecture.md`](../docs/architecture.md) and
[`../docs/decisions/`](../docs/decisions/) before changing a boundary.
