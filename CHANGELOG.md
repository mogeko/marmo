# Changelog

All notable changes to marmo are recorded here. The project is pre-1.0; APIs
and behavior may change between minor releases.

## Unreleased

### Security

- TLS client certificate paths now require issuer `basicConstraints CA:TRUE`
  and `keyUsage keyCertSign`; a CA:FALSE intermediate is rejected. Host-name
  verification is independent of chain verification. Post-handshake plaintext
  alerts are rejected, and missing `close_notify` is a truncation error by
  default. ALPN extension length arithmetic is bounded.
- HTTP/2 accepts client `ENABLE_PUSH`, treats `END_STREAM` as a half-close,
  rejects HEADERS for other streams, reports RST/truncating GOAWAY as resets,
  limits CONTINUATION frames, and sizes the HPACK dynamic table by bytes.
- WebSocket preserves frames coalesced with the opening handshake and checks
  close state under the write lock.
- Stream adapters track in-flight operations so `close` unblocks I/O and waits
  before freeing connection state.

### Added

- TLS ALPN negotiation on both sides (ADR-0012). The TLS client is now the
  in-tree TLS 1.3 implementation, replacing `std.crypto.tls.Client`, so it can
  send the ALPN extension. It verifies ECDSA, Ed25519, and RSA server
  certificates through the system CA bundle.
- First-party `packages/http2`: HTTP/2 framing, HPACK with Huffman decoding,
  SETTINGS, flow control, and a one-stream client/server transport
  (ADR-0013). Root adapters expose `H2Stream` and `H2Dialer`.
- First-party `packages/ws`: RFC 6455 client/server opening handshake, masked
  framing, continuation, ping/pong, and close (ADR-0014). Root adapters expose
  `WsStream` and `WsDialer`.
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

### Fixed

- The TLS client reader now waits for a complete record instead of reporting a
  partial record as EOF. The bug lost split replies and was found during
  trojan-gfw UDP interop; `packages/tls13/src/reader.zig` has a regression
  test.

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
  has not been externally audited; see `docs/security/audit.md`.
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
