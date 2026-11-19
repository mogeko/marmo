# marmo

A TCP/UDP proxy library written in Zig: L4/L7 inbounds, multiple proxy
protocols, rule-based routing, and latency-aware node selection.

**Version:** 0.0.2 (Not production-ready; API is unstable and may change without notice.)

**Status:** Phase 1 MVP implemented; Phase 2 has started with outbound selectors
(manual, round-robin, random, fallback, least-latency), active TCP health
probes, VLESS outbound and inbound over TLS (TCP/UDP, simple UoT and XUDP),
and a TLS 1.3 server. Includes strict JSON config, direct TCP/UDP and HTTP
CONNECT outbounds, SOCKS5 inbound (CONNECT + UDP ASSOCIATE), HTTP CONNECT and
forward proxying, Shadowsocks 2022 TCP/UDP (AES-128/256-GCM),
domain/IP-CIDR/port routing, relay, and metrics.

**Transport status:** plaintext TCP, the TLS client, and an in-tree TLS 1.3
server are wired in. The TLS code lives in the independent
[`packages/tls13`](packages/tls13/) package (ADR-0010); the server supports
X25519, AES-128-GCM/SHA-256, and ECDSA P-256 certificates. QUIC, HTTP/2,
WebSocket, and gRPC are not implemented (ADR-0007).

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
