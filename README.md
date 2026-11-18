# marmo

A TCP/UDP proxy library written in Zig: L4/L7 inbounds, multiple proxy
protocols, rule-based routing, and latency-aware node selection.

**Status: Phase 1 design.** ADR-0001–0009 are accepted; no code or build
scaffold exists yet.

**Transport status:** only the design exists. TLS client comes from `std`; the
in-tree TLS 1.3 server, QUIC, HTTP/2, WebSocket, and gRPC are not implemented
yet (ADR-0007).

- [Architecture](docs/architecture.md)
- [Architecture decisions](docs/decisions/)
- [Zig code style](.agents/instructions/zig-style.md)
- [Agent instructions](AGENTS.md)

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
