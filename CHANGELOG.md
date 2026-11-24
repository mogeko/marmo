# Changelog

All notable changes to marmo are recorded here. The project is pre-1.0; APIs
and behavior may change between minor releases.

## Unreleased

- Security hardening from the internal audit: Shadowsocks 2022 UDP
  timestamps are validated in both directions, TCP request salts are rejected
  for 60 seconds, and SS UDP sessions last at least 60 seconds.
- Direct UDP replies are filtered against a bounded set of destinations the
  association actually contacted, closing a wildcard-socket injection path.
- Inbound Mux.Cool sessions now take a per-instance session permit, run under
  the handshake deadline, and count downlink traffic against the physical idle
  timer.
- Domain names drop a trailing DNS root dot before routing; exact and suffix
  matching are ASCII-case-insensitive.
- HTTP forward requests strip fields nominated by `Connection:` and redact
  parsed header values in `Debug`.
- `Config` now re-exports every schema type (`ConfigLimits`, `Inbound`,
  `Outbound`, `Route`, `Rule`, TLS/transport/sniffing types), so a config can
  be built programmatically.
- Shadowsocks request/response state has redacted `Debug` output and zeroizes
  retained subkeys; VMess body ciphers keep a zeroized raw-key copy.
- The fuzz smoke job now runs the Mux.Cool target; the docs/CI matrix covers
  handshake deadlines and a multi-thread runtime.
- Added an opt-in DNS subsystem behind the non-default `dns` feature
  (ADR-0030): bounded TTL cache, UDP/TCP/DoT/DoH upstreams, two-tier fallback,
  a total lookup deadline, an in-flight limit, and a public `DnsResolver`
  override. Direct TCP/UDP and proxy-server dials use it; routing-time IP
  rules still see literal addresses only.
- MSRV is now Rust 1.88, raised for `hickory-resolver` 0.26.3. The dependency
  is optional and compiled only with `dns`.
- DNS query/cache-hit/fallback/failure metrics and a redacted config `Debug`.
- Injected domain and IP sets through `DomainSet`/`IpSet`, plus
  `domain_keyword`, `port_range`, `inbound`, `domain_set`, and `geoip`
  matchers; the library never reads rule-set files or requests data at runtime
  (ADR-0028).
- Injected process identity through `ProcessResolver`, `process_name` and
  `process_path` matchers, a bounded cache, lookup timeout, in-flight limit,
  and fail-open unknown handling (ADR-0029).
- Domain names are canonicalized to ASCII lowercase at parse time; routing
  comparisons are case-insensitive.
- `aho-corasick` is a new `marmo` dependency for inline keyword matching.
- VMess AEAD inbound and outbound: TCP, direct UDP, inbound Mux.Cool
  termination, AES-128-GCM and ChaCha20-Poly1305, bounded auth-ID replay
  filter, and TLS/WebSocket/HTTP2 transports (ADR-0025).
- `marmo-proto` adds the `vmess` and `mux` codecs and a `vmess` fuzz target.
- VLESS inbound terminates full Mux.Cool for TCP and UDP sessions, sharing the
  VMess dispatcher (ADR-0026). The VLESS outbound keeps UoT/XUDP.
- Client-side Mux.Cool pooling for VMess and VLESS with `"mux": true`:
  bounded connection/session tables, TCP and UDP, per-datagram UDP targets,
  keep-alive, and idle close (ADR-0027).
- Removed the duplicate `xudp` codecs and fuzz target; the `xudp: true` mode
  now uses the shared Mux.Cool codec (ADR-0027).
- Root-level HTTP/2 multiplexing and pooling (ADR-0031): VLESS and VMess
  inbounds serve every stream on one connection under a separate stream budget,
  and their outbounds reuse up to four connections with 16 streams each and 64
  streams in flight. New `h2_streams_*` metrics cover accepted, active,
  rejected, and closed streams.
- `marmo-transport` no longer implements `Layer` for `H2Client` and
  `H2Server`; `Instance` uses `H2ClientConnection` and `H2ServerConnection`
  instead. The one-shot `connect`/`accept` methods remain, and `LayerError::H2`
  is removed.
- Fixture parity for every codec: golden wire images under
  `crates/marmo-proto/tests/fixtures/`, a dedicated Mux.Cool fuzz target,
  corpus provenance in `fuzz/corpus/README.md`, HTTP/SOCKS5 protocol notes, and
  a differential interop matrix in `docs/protocols/interop.md`. Phase 2 is
  complete; P2-13 is closed.

## 0.0.3 - 2026-11-21

- Rust workspace: `marmo`, `marmo-proto`, `marmo-net`, and `marmo-transport`
  (ADR-0019, ADR-0024).
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

- QUIC/TUIC/Hysteria2, gRPC/XHTTP, DNS cache/DoH, sniffing, rule sets,
  process rules, `http_head` health checks, jitter, and exponential backoff are
  not implemented.
- The VMess authenticated-length option is not implemented; legacy VMess CFB
  is not planned. Client-side Mux.Cool pooling is available with `mux: true`.
- The library is not production-ready and has not had an external audit.
