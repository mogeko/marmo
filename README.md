# marmo

A TCP/UDP proxy library written in Zig: L4/L7 inbounds, multiple proxy
protocols, rule-based routing, and latency-aware node selection.

**Version:** 0.0.1 (Not production-ready; API is unstable and may change without notice.)

**Status:** Phase 1 MVP implemented; Phase 2 has started with outbound selectors
(manual, round-robin, random, fallback, least-latency), active TCP health
probes, and a VLESS outbound over TCP or TLS. Includes strict JSON config, direct
TCP/UDP and HTTP CONNECT outbounds, SOCKS5 inbound (CONNECT + UDP ASSOCIATE),
HTTP CONNECT and forward proxying, Shadowsocks 2022 TCP/UDP
(AES-128/256-GCM), domain/IP-CIDR/port routing, relay, and metrics.

**Transport status:** plaintext TCP and the TLS client are wired in; TLS
verification uses the system CA bundle, with an explicit insecure option for
testing. The in-tree TLS 1.3 server, QUIC, HTTP/2, WebSocket, and gRPC are not
implemented (ADR-0007).

- [Architecture](docs/architecture.md)
- [Architecture decisions](docs/decisions/)
- [Shadowsocks 2022 example](examples/shadowsocks2022/)
- [Agent instructions and Zig style](AGENTS.md)

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
