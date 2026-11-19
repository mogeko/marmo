# Changelog

All notable changes to marmo are recorded here. The project is pre-1.0; APIs
and behavior may change between minor releases.

## 0.0.2 - 2026-11-19

### Added

- Outbound selectors: `manual`, `round_robin`, `random`, `fallback`, and
  `least_latency`, with optional active TCP health probes and passive latency
  samples.
- VLESS outbound over TCP or TLS, with UUID authentication, IPv4/domain/IPv6
  targets, TCP command `1`, and simple UDP command `2`.
- VLESS inbound over TLS, with UUID authentication, routing, TCP, simple UDP,
  and PEM/DER ECDSA P-256 TLS credential loading.
- In-tree TLS 1.3 server in the first-party `packages/tls13` package, exposed
  through a thin `Stream` adapter. The package also owns the std-backed TLS
  client and CA handling.
- Standalone `examples/vless` server/client, including local Xray interop notes.
- Workspace commands: `zig build test` aggregates package tests,
  `zig build check` adds formatting, and `zig build examples` builds examples.
- `packages/README.md` package contract and `examples/README.md` index.

### Changed

- TLS moved out of root `src/transport` into `packages/tls13` (ADR-0010).
  Root keeps only `Stream`/`Dialer` adapters.
- Root CI runs formatting, Debug tests, and a ReleaseSafe test pass.
- `AGENTS.md` consolidates the enforceable Zig style and workspace rules.

### Known limitations

- VLESS UDP implements simple UoT (`[2B length][payload]`) only. XUDP command
  `3`, cone NAT, and per-packet destinations are not implemented; Xray v26 UDP
  clients use XUDP by default and are not interoperable with the VLESS inbound.
- One VLESS UDP stream is fixed to one destination. A SOCKS5 UDP association
  that switches targets has later datagrams rejected.
- The in-tree TLS 1.3 server supports X25519, AES-128-GCM/SHA-256, and ECDSA
  P-256 certificates. It has no client authentication, PSK, session tickets,
  ALPN selection, 0-RTT, KeyUpdate, or handshake timeout. It is not audited for
  production use.
- The std-backed TLS client can negotiate TLS 1.2. A server-initiated TLS 1.3
  KeyUpdate is not synchronized with a concurrent write; this is documented and
  will be removed with the in-tree record layer.
- TLS and VLESS decoders do not yet have committed fuzz targets or reference
  transcript fixtures.
- The library remains not production-ready; API and configuration may change.

### Tests

- 51 root tests (32 unit, 4 public API, 15 integration) and 4 TLS package
  tests, passing in Debug and ReleaseSafe.
- Examples build with `zig build examples`.
- Reference interop was checked locally against Xray-core 26.11.9 for VLESS TCP
  in both directions and marmo UDP client -> Xray server. The harness is not
  committed and is not part of CI.

## 0.0.1 - 2026-11-19

- Initial Phase 1 MVP: strict JSON config, `Instance` lifecycle, TCP/UDP relay,
  SOCKS5 CONNECT and UDP ASSOCIATE, HTTP CONNECT and forward proxying,
  Shadowsocks 2022 TCP/UDP, direct outbound, rule-based routing, and metrics.
