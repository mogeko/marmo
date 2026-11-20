# ADR-0018: Dependencies and crypto backend

- Status: Accepted (2026-11-21)
- Date: 2026-11-21
- Deciders: @mogeko
- Related: ADR-0007, ADR-0009, ADR-0017, ADR-0020

## Context

ADR-0007 made the project std-only with no C toolchain and no optional
backends, which forced TLS 1.3, HTTP/2, and WebSocket into this repository
(15,465 lines) and would force QUIC as well. The decider has accepted a C
toolchain for the crypto backend and allowed the dependency policy to change.
The replacement must still keep protocol logic clean-room, keep the dependency
surface reviewable, and avoid two behavior surfaces.

## Decision (recommended)

Delete the in-tree transport implementations and depend on maintained crates.

- **TLS 1.3**: `rustls` + `tokio-rustls`, TLS 1.3 only, ALPN, mTLS,
  ECDSA/Ed25519/RSA server certificates, platform trust store through
  `rustls-platform-verifier`.
- **HTTP/2**: `h2` (framing, HPACK, flow control, 1xx, trailers).
- **WebSocket**: `tokio-tungstenite` (permessage-deflate, subprotocols).
- **HTTP/1.1**: `httparse` for the minimal inbound; `hyper` only if a
  concrete need appears.
- **QUIC**: `quinn` when R5 starts (streams, datagrams, custom congestion
  control).
- **DNS**: `hickory-resolver` when R5 starts (system, DoH, DoT, cache).
- **Crypto provider**: `aws-lc-rs`, the `rustls` default, is the only
  supported provider. It requires a C toolchain and assembly. `ring` is not a
  second backend; if a supported platform cannot build `aws-lc-rs`, that is a
  bug to fix or a new ADR, not a silent fallback.
- **SS2022 primitives**: `aes-gcm`, `chacha20poly1305`, `blake3` from
  RustCrypto/BLAKE3. No primitive is implemented by hand.
- **Policy**: `Cargo.lock` is committed and CI uses `--locked`; `cargo-deny`
  enforces the license allowlist and denies GPL/AGPL/MPL; `cargo-audit` runs
  in CI; every new crate with `unsafe`, a build script, or a proc macro needs a
  recorded review.
- **No forks.** If a capability is missing, pin a newer upstream version; do
  not copy a transport into this repository and do not add a feature flag that
  selects a backend.
- **Config validation** rejects a transport or protocol that is not
  implemented yet, as before.

## Alternatives

1. **Keep the in-tree transports.** Preserves zero dependencies, but keeps the
   15.5k-line security surface, blocks Phase 3 on QUIC, and is the work this
   migration exists to remove. Rejected.
2. **BoringSSL or OpenSSL through FFI.** Mature, but a large C surface, unsafe
   bindings, and a heavier build than `rustls`. Rejected.
3. **`s2n-quic` for QUIC.** Viable, but `quinn` is the ecosystem default, has
   the controller trait needed for Brutal, and integrates with `rustls`
   directly. Rejected.
4. **`ring` as the crypto provider.** Smaller build, but `aws-lc-rs` is the
   `rustls` default, better maintained, and has the broader platform story.
   Rejected as a second backend; may be reconsidered only as a replacement.
5. **Multiple TLS providers behind features.** Recreates the optional-backend
   problem ADR-0007 rejected: two behavior surfaces and an untested
   configuration. Rejected.

## Consequences

- A C toolchain (compiler, CMake, NASM/Perl as the provider requires) is a
  documented build prerequisite on Linux, macOS, and Windows.
- The dependency graph becomes a supply-chain surface. Mitigated by the
  pinned lockfile, `cargo-deny`, `cargo-audit`, and review of build scripts.
- Audit findings against the in-tree TLS, HTTP/2, and WebSocket parsers are
  closed by deletion. The audit is re-scoped to protocol code, configuration,
  and dependency review.
- Build time and binary size increase; the workspace and release profile are
  tuned in R0, and `criterion` measures the data plane.
- TLS 1.3 remains the only TLS version, matching the current scope.
- Clean-room rules are unchanged: specs and fixtures, never ported GPL/AGPL/MPL
  code, even when a dependency's license would allow reading it.

## Approval

- [x] Accept the recommendation (`rustls` + `aws-lc-rs`; `h2`,
      `tokio-tungstenite`, `quinn`, `hickory-resolver`).
- [ ] Choose a different crypto provider: ...

Accepted 2026-11-21 as recommended.
