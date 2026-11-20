# marmo

A TCP/UDP proxy library written in Zig: L4/L7 inbounds, multiple proxy
protocols, rule-based routing, and latency-aware node selection.

**Version:** 0.0.2 (Not production-ready; API is unstable and may change without notice.)

**Status:** Phase 1 MVP implemented; Phase 2 has started with outbound selectors
(manual, round-robin, random, fallback, least-latency), active TCP health
probes, VLESS outbound and inbound over TCP/TLS/WebSocket/HTTP/2 (TCP/UDP,
simple UoT and XUDP), Trojan inbound and outbound over TLS (TCP/UDP, optional
routed fallback), and a TLS 1.3 server. Includes strict JSON config, direct TCP/UDP and HTTP
CONNECT outbounds, SOCKS5 inbound (CONNECT + UDP ASSOCIATE), HTTP CONNECT and
forward proxying, Shadowsocks 2022 TCP/UDP (AES-128/256-GCM),
domain/IP-CIDR/port routing, relay, metrics, TLS ALPN, HTTP/2 and WebSocket
transport packages, and global connection limits/timeouts (ADR-0015).

**Transport status:** plaintext TCP, TCP/TLS, TLS+WebSocket, and TLS+HTTP/2 are
wired in for VLESS; the in-tree TLS 1.3 client/server is shared. TLS, HTTP/2,
and WebSocket live in independent packages (ADR-0010, ADR-0013, ADR-0014). TLS supports X25519/P-256 ECDHE,
AES-128-GCM/AES-256-GCM/ChaCha20-Poly1305, ALPN, mTLS, KeyUpdate, and
ECDSA/Ed25519/RSA server certificates. The
HTTP/2 transport multiplexes up to 16 streams per connection and exposes
1xx/trailers for gRPC-style callers; WebSocket implements RFC 6455 with
permessage-deflate and subprotocol negotiation. VLESS selects its L7 transport
with `transport.network` (ADR-0016); `Instance` currently serves one VLESS
stream per HTTP/2 connection. QUIC and gRPC are not implemented (ADR-0007).

- [Architecture](docs/architecture.md)
- [Architecture decisions](docs/decisions/)
- [Packages](packages/)
- [Examples](examples/)
- [Changelog](CHANGELOG.md)
- [Agent instructions and Zig style](AGENTS.md)

## Workspace

This is a small monorepo: root library, `packages/`, and `examples/`.

```sh
zig build test       # root and package tests
zig build check      # formatting check plus tests
zig build examples   # build every example
```

Package rules and the workspace contract are in
[`packages/README.md`](packages/README.md).

## Design highlights

- `std.Io`-based runtime; the library never owns threads or an event loop.
- Layered: inbound → routing → outbound, over composable transports.
- Rule-based routing on domain, IP/CIDR, GEOIP/GEOSITE, port, process, and
  sniffed protocol.
- Outbound groups with manual, round-robin, random, fallback, and least-latency
  selection.
- Phased protocol support; see the matrix in the architecture document.

## License

LGPL-2.1. See [LICENSE](LICENSE).
