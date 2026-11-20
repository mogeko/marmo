# Rust workspace

Five crates, one dependency direction, no optional transport backends.

| Crate | Purpose | Published |
| --- | --- | --- |
| `marmo` | `Instance`, config, routing, inbounds, outbounds, public API | yes |
| `marmo-proto` | SOCKS5, HTTP/1, SS2022, Trojan, VLESS, XUDP codecs; no I/O, no tokio | yes |
| `marmo-net` | `Endpoint`, CIDR, socket options, resolver policy | yes |
| `marmo-transport` | stream/datagram traits, TLS/WS/H2/QUIC adapters, relay | yes |
| `marmo-testkit` | fake streams, fixture loaders, loopback helpers | no |

Dependency direction: `marmo` → all; `marmo-transport` → `marmo-net`;
`marmo-proto` → `marmo-net` (address parsing only); `marmo-net` → nothing.

## Commands

```sh
cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo audit
cargo tree --workspace --format '{l}'   # license review
```

CI runs the first three on Linux, macOS, and Windows; the copyleft check and
`cargo audit` run on Linux. `cargo-fuzz` runs on nightly only.

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
  and tests.
- Every decoder has a fuzz target and a fixture; every bug fix adds a
  regression test.
- Public items need documentation. `missing_docs` is denied by CI.
- License is MIT OR Apache-2.0. Dependency changes record a
  `cargo tree --format '{l}'` review; CI rejects GPL/AGPL/MPL. Apache-2.0-only
  crates are accepted; `cargo-audit` covers advisories.

See [`../docs/architecture.md`](../docs/architecture.md) and
[`../docs/decisions/`](../docs/decisions/) before changing a boundary.
