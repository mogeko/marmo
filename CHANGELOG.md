# Changelog

All notable changes to marmo are recorded here. The project is pre-1.0; APIs
and behavior may change between minor releases.

## 0.0.3 - 2026-11-21

- Rust workspace: `marmo`, `marmo-proto`, `marmo-net`, `marmo-transport`, and
  `marmo-testkit` (ADR-0019).
- Inbounds: SOCKS5 TCP/UDP, HTTP CONNECT/forward, Shadowsocks 2022 TCP/UDP,
  Trojan TCP/UDP with routed fallback, and VLESS TCP/UoT/XUDP over TLS, WS,
  and HTTP/2.
- Outbounds: direct, HTTP CONNECT, Shadowsocks 2022, Trojan, VLESS, and
  selectors (manual, round-robin, random, fallback, least-latency) with
  optional TCP health probes.
- TLS 1.3 through `rustls` with ALPN, mTLS, and the platform verifier;
  WebSocket through `ws-net`; HTTP/2 through `h2` (ADR-0018, ADR-0021).
- Global limits and timeouts, shared idle and absolute handshake deadlines,
  and connection/byte/timeout/UDP-session/health metrics with an optional
  `MetricsSink`.
- Strict JSON schema version 2; TLS credentials are inline PEM (ADR-0023).
- Decoder fuzz targets: SS2022 TCP/UDP, SOCKS5, Trojan, VLESS, XUDP, and HTTP.

## 0.0.2 - 2026-11-19

### Added

- Outbound selectors: manual, round-robin, random, fallback, and
  least-latency, with optional active TCP health probes and passive latency
  samples.
- VLESS outbound and inbound over TLS: UUID authentication, TCP, simple UoT,
  and Xray-compatible XUDP.
- TLS 1.3 server and client with ALPN, mTLS, ECDSA credentials, bounded
  handshakes, and transport-aware defaults.
- HTTP/2 and WebSocket transports, including compression, subprotocols,
  multiplexing, trailers, and bounded frames.
- Trojan inbound/outbound over TLS with TCP, UDP ASSOCIATE, and optional
  routed fallback.
- Standalone Shadowsocks 2022, Trojan, and VLESS examples.
- Local interop against Xray and trojan-gfw for TCP and UDP.

### Changed

- Global limits: 1024 TCP connections, 10 s handshake, 300 s idle, 1 s
  half-close grace; UDP remains outside `max_connections`.
- TLS, HTTP/2, and WebSocket were hardened and bounded; TLS 1.2-only peers are
  rejected by the TLS 1.3 client.
- Per-connection protocol failures are debug-level so they cannot flood
  embedder logs.
- License changed to MIT OR Apache-2.0 for the next release (ADR-0020).

### Fixed

- Relay writes use a mutable stack copy instead of mutating read-only slice
  descriptors.
- HTTP/2 and WebSocket handshake timers can no longer abort a live connection
  after a successful handshake.
- WebSocket close, ping, continuation, and compressed-frame handling follow
  RFC 6455/7692 more strictly.

## 0.0.1 - 2026-11-19

- Initial MVP: strict JSON config, `Instance` lifecycle, TCP/UDP relay,
  SOCKS5 CONNECT and UDP ASSOCIATE, HTTP CONNECT and forward proxying,
  Shadowsocks 2022 TCP/UDP, direct outbound, rule-based routing, and metrics.

## Known limitations

- VMess, QUIC/TUIC/Hysteria2, gRPC/XHTTP, DNS cache/DoH, sniffing, rule sets,
  process rules, HTTP/2 root multiplexing/pooling, `http_head` health checks,
  jitter, and exponential backoff are not implemented.
- `Instance` serves one VLESS stream per HTTP/2 connection.
- The library is not production-ready and has not had an external audit.
