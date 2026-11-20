# Changelog

All notable changes to marmo are recorded here. The project is pre-1.0; APIs
and behavior may change between minor releases.

> **Scope:** this file records embedder-visible changes to the root `marmo`
> library (`src/`, `Instance`, config, adapters, examples). The first-party
> packages under `packages/` are independently consumable and keep their own
> changelogs; root entries mention package changes only when they affect the
> root API, defaults, or integration.

## Unreleased

> Version not bumped yet. When releasing, replace "Unreleased" with the
> version and date, update `build.zig.zon` and the README status, and keep
> the known limitations below in the release notes.

### Security

- Global connection limits/timeouts (ADR-0015): 1024 TCP connections, 10 s
  handshake deadline, 300 s idle timeout, and 1 s half-close grace, enforced by
  one reaper per `Instance` over a bounded guard registry. Metrics expose
  rejected connections, handshake timeouts, and idle timeouts; UDP is excluded
  from `max_connections`.
- Relay teardown clears the peer reference, aborts with the non-blocking
  `.both` path, and removes the guard before closing the stream, so a timeout
  cannot leave a dangling peer or stall the reaper on a writer lock.
- TLS, HTTP/2, and WebSocket received seven hardening rounds. Root-visible
  effects: stricter certificate validation (malformed DER, SAN, legacy OIDs,
  v1/unique-ID, RSA-PSS, expired anchors), HTTP/2 half-close/flow-control and
  padding/trailer handling, and WebSocket 1 MiB reads, continuation writes,
  Close 1009, and a bounded frame budget. Package details are in
  [packages/tls13/CHANGELOG.md](packages/tls13/CHANGELOG.md),
  [packages/http2/CHANGELOG.md](packages/http2/CHANGELOG.md), and
  [packages/ws/CHANGELOG.md](packages/ws/CHANGELOG.md); audit history is in
  [docs/archive/security-audit-zig.md](docs/archive/security-audit-zig.md).

### Added

- VLESS stream transports (ADR-0016): `transport: { network: tcp|ws|h2,
  path, host, compression, subprotocols }` on inbounds and outbounds.
  WebSocket uses RFC 6455 path/Host, optional permessage-deflate, and
  subprotocols; HTTP/2 uses a POST stream with ALPN `h2` and a configured
  path/Host. TLS ALPN defaults are transport-aware, and non-VLESS protocols
  reject the object.
- Loopback integration coverage for VLESS over WebSocket (compressed and with
  a subprotocol) and VLESS over HTTP/2, plus config validation tests for the
  new transport object.
- TLS 1.3 transport (ADR-0012): ALPN, mTLS with `none`/`optional`/`required`
  policy, `TLS_AES_128_GCM_SHA256`/`TLS_AES_256_GCM_SHA384`/
  `TLS_CHACHA20_POLY1305_SHA256`, X25519 and P-256 ECDHE, and KeyUpdate. The
  TLS client is the in-tree implementation and verifies ECDSA, Ed25519, and
  RSA server certificates. Root config adds `tls.client_certificate`,
  `tls.client_private_key`, `tls.client_ca`, and `tls.client_auth`.
- First-party `packages/http2`: HTTP/2 framing, HPACK with Huffman decoding,
  SETTINGS, flow control, bounded 16-stream multiplexing, and 1xx/trailers for
  gRPC-style callers (ADR-0013). Root adapters expose `H2Stream` and
  `H2Dialer`.
- First-party `packages/ws`: RFC 6455 client/server opening handshake, masked
  framing, continuation, ping/pong, close, permessage-deflate (RFC 7692), and
  subprotocol negotiation (ADR-0014). Root adapters expose `WsStream` and
  `WsDialer`.
- Loopback integration coverage for WebSocket over TLS and HTTP/2 over TLS,
  including ALPN assertions.
- Trojan inbound and outbound over TLS: TCP `CONNECT`, UDP `ASSOCIATE` with
  per-packet destinations, SHA-224 password authentication, and an optional
  explicit `fallback` endpoint routed through the router (ADR-0011).
- Trojan config validation, protocol unit tests, loopback TCP/UDP integration
  tests, a fallback integration test, and `trojan_auth`, `trojan_request`, and
  `trojan_udp_frame` fuzz targets.
- Standalone `examples/trojan` server/client, including an optional routed
  fallback and local certificate setup.
- Local interop checks against self-hosted Xray-core 26.11.9 and trojan-gfw
  1.16.0 cover TCP and UDP in both directions; the harness is not committed.

### Changed

- The next release is dual-licensed MIT OR Apache-2.0 (ADR-0020); 0.0.2 and
  earlier remain LGPL-2.1. The Rust migration is recorded in ADR-0017..0019.
- The HTTP/2 and WebSocket adapters now use a running/done/fired handshake
  state, so a platform sleep that is not canceled promptly cannot abort a
  connection after a successful handshake. `Instance` disables the adapter
  timers and lets the ADR-0015 reaper own the deadline.
- The TLS client is now the in-tree TLS 1.3 implementation. TLS 1.2-only
  servers are rejected; a missing `close_notify` is a truncation error unless
  `allow_truncation_attacks` is enabled. Client and server negotiate three
  AEAD suites, X25519 or P-256, optional client certificates, and KeyUpdate.
- The global `limits` policy is enforced by default: 1024 TCP connections,
  10 s handshake deadline, 300 s idle timeout, and 1 s uplink/downlink grace.
  UDP is omitted from `max_connections`.
- The WebSocket server adapter defaults to no internal handshake timer so the
  ADR-0015 reaper owns the deadline. Standalone users must set
  `handshake_timeout_ns` explicitly.
- Per-connection peer failures are logged at debug level instead of warn, so
  normal protocol violations, resets, and truncation cannot flood embedder
  logs. `accept failed` and `spawn failed` remain warn-level.
- WebSocket audit follow-ups: pings queue instead of dropping when a data
  writer holds the lock, valid close codes are echoed, non-minimal frame
  lengths/BFINAL/malformed extensions/duplicate subprotocols are rejected, and
  `ws_deflate` plus compressed-connection fuzz targets were added.
- WebSocket reads accept standard-client single frames up to 1 MiB; writes
  still fragment at 64 KiB.

### Known limitations

- TLS: no PSK/session tickets/0-RTT, TLS 1.2, ECH, record padding, or
  CRL/OCSP; credentials are ECDSA P-256 only; HelloRetryRequest is rejected
  because both supported key shares are offered. Certificate policy still
  falls back to CN and does not check leaf `keyUsage`. See
  [packages/tls13/CHANGELOG.md](packages/tls13/CHANGELOG.md).
- HTTP/2: VLESS can select `transport.network = "h2"`, but `Instance` serves
  one VLESS stream per H2 connection; the package's 16-stream multiplexer and
  connection pooling are not yet used by the root library. The package accepts
  1xx/trailers but cannot send 1xx; no server push/PRIORITY, h2c upgrade,
  HTTP/2 WebSocket, or gRPC message framing; HPACK encoding has no
  Huffman/dynamic-table insertion. The 8 KiB stream receive window is a
  throughput trade-off. See
  [packages/http2/CHANGELOG.md](packages/http2/CHANGELOG.md).
- WebSocket: VLESS wires `path`, `host`, `compression`, and `subprotocols`
  through `transport`; the full `DeflateOptions`/close-code surface is
  package-only. No arbitrary WS headers, early data (`?ed=`), heartbeat,
  Origin/auth handling, redirects/proxy auth, true half-close, or HTTP/2
  WebSocket. A connection reserves 1 MiB before the handshake and compression
  state when negotiated. See [packages/ws/CHANGELOG.md](packages/ws/CHANGELOG.md).
- VMess is not implemented. VLESS over WebSocket/HTTP/2 does not support
  early data, h2c, HTTP/2 multiplexing at the `Instance` layer, or gRPC. QUIC,
  TUIC, and Hysteria2 remain Phase 3.
- The library remains not production-ready, has no external cryptographic or
  transport audit, and its public API is unstable.

### Tests

- 271 tests: 63 root unit, 4 public API, 32 integration, 48 tls13, 44 http2,
  66 ws, and 14 fuzz corpus tests, passing in Debug and ReleaseSafe.
- Local interoperability checks pass for Shadowsocks 2022 (AES-128/256,
  TCP/UDP), VLESS (TCP, simple UoT, XUDP, TCP+UDP) and Trojan (TCP/UDP), in
  both directions against shadowsocks-rust 1.25.0 and Xray-core 26.11.9.
  TLS interop covers OpenSSL 4.1 for three suites, X25519/P-256, mTLS, and
  KeyUpdate; WebSocket covers Python `websockets` 17.4 and Node `ws` with
  compression and subprotocols. The harnesses are not committed and are not
  part of CI.

## 0.0.2 - 2026-11-19

### Added

- Outbound selectors: `manual`, `round_robin`, `random`, `fallback`, and
  `least_latency`, with optional active TCP health probes and passive latency
  samples.
- VLESS outbound over TCP or TLS, with UUID authentication, IPv4/domain/IPv6
  targets, TCP command `1`, simple UDP command `2`, and opt-in XUDP command
  `3` (`"xudp": true`).
- VLESS inbound over TLS, with UUID authentication, routing, TCP, simple UDP,
  XUDP (Xray-compatible), and PEM/DER ECDSA P-256 TLS credential loading.
- In-tree TLS 1.3 server in the first-party `packages/tls13` package, exposed
  through a thin `Stream` adapter. The package also owns the std-backed TLS
  client and CA handling.
- Bounded TLS handshakes for both directions: `handshake_timeout_s` defaults
  to 10 seconds and is rejected when zero.
- Standalone `examples/vless` server/client, including local Xray interop notes.
- Workspace commands: `zig build test` aggregates package tests,
  `zig build check` adds formatting, and `zig build examples` builds examples.
- `packages/README.md` package contract and `examples/README.md` index.

### Changed

- TLS moved out of root `src/transport` into `packages/tls13` (ADR-0010).
  Root keeps only `Stream`/`Dialer` adapters.
- Root CI runs formatting, Debug tests, and a ReleaseSafe test pass.
- `AGENTS.md` consolidates the enforceable Zig style and workspace rules.

### Fixed

- `Stream.write` no longer passes a const slice array to
  `Writer.writeVecAll`. The old `@constCast` path mutated read-only slice
  descriptors and crashed ReleaseSafe on Linux; writes now use a small mutable
  stack copy. Added a regression test.

### Known limitations

- VLESS UDP supports simple UoT (`[2B length][payload]`) and XUDP
  (`[2B metadata][2B length][payload]`). XUDP is opt-in on the outbound and
  supported on the inbound for Xray clients. XUDP cone NAT/GlobalID is not
  implemented, and one stream is fixed to one destination; per-packet target
  changes are rejected.
- The in-tree TLS 1.3 server supports X25519, AES-128-GCM/SHA-256, and ECDSA
  P-256 certificates. It has no client authentication, PSK, session tickets,
  ALPN selection, 0-RTT, or KeyUpdate. TLS handshakes are bounded by the root
  adapters' `handshake_timeout_s`; the package API itself is synchronous. It
  has not been externally audited; see `docs/archive/security-audit-zig.md`.
- The std-backed TLS client can negotiate TLS 1.2. A server-initiated TLS 1.3
  KeyUpdate is not synchronized with a concurrent write; this is documented and
  will be removed with the in-tree record layer.
- The library remains not production-ready; API and configuration may change.

### Tests

- 77 tests (38 root unit, 4 public API, 18 integration, 10 fuzz, 7 TLS
  package), passing in Debug and ReleaseSafe.
- Examples build with `zig build examples`.
- Reference interop was checked locally against Xray-core 26.11.9 for VLESS TCP
  in both directions and XUDP UDP in both directions. The harness is not
  committed and is not part of CI.

## 0.0.1 - 2026-11-19

- Initial Phase 1 MVP: strict JSON config, `Instance` lifecycle, TCP/UDP relay,
  SOCKS5 CONNECT and UDP ASSOCIATE, HTTP CONNECT and forward proxying,
  Shadowsocks 2022 TCP/UDP, direct outbound, rule-based routing, and metrics.
