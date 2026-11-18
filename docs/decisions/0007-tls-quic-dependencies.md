# ADR-0007: TLS, QUIC, and crypto dependencies

- Status: Accepted (2026-11-18)
- Amended: 2026-11-18 (std-first)
- Date: 2026-11-18
- Deciders: @mogeko
- Related: ADR-0002, ADR-0004, ADR-0009

## Context

Verified against Zig 0.17.1, `std` provides:

- `std.crypto.tls.Client` (TLS 1.3 client, with SNI and certificate
  verification) but **no TLS server**.
- No QUIC, no HTTP/2 client, and no WebSocket client (only an HTTP/1.1
  server-side upgrade helper).
- Crypto primitives: AES-GCM, ChaCha20-Poly1305, BLAKE2/BLAKE3, SHA-1/2/3,
  HMAC, HKDF, X25519, Ed25519, and MD5 (legacy).

Protocols in scope need all of these: Trojan and Hysteria2 require TLS
termination for inbounds; TUIC and Hysteria2 require QUIC; VLESS/VMess over
WebSocket or gRPC require those transports; Hysteria2's Brutal congestion
control needs a configurable QUIC sender.

The library must stay std-only: no C toolchain, no optional binary backends, and
no dependency that complicates LGPL distribution. Missing transports are
therefore implementation work in this repository, not configuration choices.

## Decision

Implement every missing transport in-tree. There are no optional backends and no
build flags that select a transport implementation.

- **std-first**: prefer `std` over in-tree code. When a future Zig version
  pinned by this project provides a missing primitive or transport, switch to
  the `std` implementation, delete the in-tree one, and re-run the interop and
  fuzz suites. An in-tree transport is a stopgap, not a permanent fork.
- **Crypto**: use `std.crypto` exclusively. Never implement primitives in-tree.
  MD5 is allowed only for legacy VMess compatibility, which is not planned.
- **TLS client**: `std.crypto.tls.Client` in Phase 1/2.
- **TLS 1.3 server**: in-tree, Phase 2, built on `std.crypto`. Scope: TLS 1.3
  only, ALPN and SNI, caller-provided certificate/key and client-auth policy,
  no renegotiation, no weak ciphers, no resumption until the base state machine
  is audited.
- **QUIC**: in-tree, Phase 3. Scope: QUIC v1 with a TLS 1.3 handshake, stream
  multiplexing, datagrams, connection close, and pluggable congestion control
  (NewReno and Brutal; BBR only if needed). No 0-RTT in v1.
- **WebSocket / HTTP/2 / gRPC**: in-tree over `std.Io` and `std.crypto`, Phase
  2/3. HTTP/2 is limited to what the transports need (framing, HPACK, SETTINGS,
  GOAWAY), not a general client.
- **Config validation**: a config that selects a transport or protocol not yet
  implemented is rejected at validation time. There is no silent fallback.
- **Security gates**: test vectors and transcript fixtures for every handshake
  state machine, fuzz targets for every parser, and an external review before
  any production-readiness claim. Until reviewed, the README states the
  transport status explicitly.
- CI builds and tests the single default configuration; no backend matrix.

## Alternatives

1. **Vendor BoringSSL/quiche.** Fast path to all protocols, but a heavy C
   surface, build complexity, and LGPL/static-linking review. Rejected by the
   user.
2. **Optional in-tree/C backends behind build flags.** Maintains a std-only
   default, but creates two behavior surfaces and an untested configuration.
   Rejected by the user.
3. **Drop inbound TLS and QUIC protocols.** Simple, but contradicts the
   requested protocol set.
4. **Depend on an existing Zig TLS/QUIC package.** Rejected: it is still an
   external backend, adds an unvetted dependency, and conflicts with the
   decision to implement transports in-tree.

## Consequences

- The in-tree surface is large: TLS 1.3 server, QUIC, HTTP/2, WebSocket, and
  gRPC. Phase 2/3 are gated on this work.
- Security review and fuzzing are mandatory; a hand-written TLS/QUIC stack is a
  high-value target. Do not merge a partial stack with verification disabled.
- The library remains embeddable in projects that forbid C dependencies and
  avoids a C toolchain entirely.
- Build and CI stay simple: one configuration, no feature matrix.
- TUIC and Hysteria2 cannot ship before the QUIC stack is complete and tested.
- Missing transports are rejected at config validation, which makes the
  roadmap visible to users instead of failing at runtime.
- Zig upgrades trigger a std-vs-in-tree review; deleting an in-tree transport
  in favor of `std` is expected work, not a regression.

## Amendment

2026-11-18: the decider added the std-first rule above. In-tree transports are
temporary: replace them with `std` implementations as soon as the pinned Zig
version provides the same primitive or protocol.

## Approval

- [x] Accepted 2026-11-18 with: no optional backends, no C dependencies; all
      missing transports implemented in-tree, std-first.
