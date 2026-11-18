# ADR-0002: Scope and delivery phases

- Status: Accepted (2026-11-18)
- Date: 2026-11-18
- Deciders: @mogeko
- Related: ADR-0004, ADR-0006, ADR-0007

## Context

The target feature set (L4/L7 proxying, six proxy protocols, rule-based routing,
latency-aware selection) is larger than sing-box or Xray v1. Trying to ship all
of it at once would delay every layer and hide interface mistakes until late.
The repository contains only docs, and the Zig standard library lacks a TLS
server, QUIC, HTTP/2, and a WebSocket client. ADR-0007 commits to implementing
those in-tree rather than adding optional backends, which puts transport work on
the critical path.

## Decision

Ship a library-first core in Phase 0 plus four delivery phases, designing
interfaces for the full set but implementing only Phase 1 first.

- **Phase 0**: architecture, ADRs, build scaffold, CI, core interfaces, public
  facade.
- **Phase 1 (MVP)**: `std.Io` core; TCP/UDP relay; SOCKS5 (CONNECT + UDP
  ASSOCIATE); HTTP/1.1 proxy (CONNECT + forward); HTTP CONNECT outbound; direct
  outbound; Shadowsocks 2022; domain/IP-CIDR/port rules; manual outbound group;
  strict JSON config; counters and logs.
- **Phase 2**: VLESS, Trojan, VMess; in-tree TLS 1.3 server and
  WebSocket/HTTP/2 transports; sniffing; compiled rule sets (GEOIP/GEOSITE);
  process rules; selectors and health checks; DNS cache and DoH.
- **Phase 3**: in-tree QUIC; TUIC; Hysteria2; gRPC transport.
- **Phase 4**: optional TUN inbound and transparent proxying; Windows support;
  security hardening and external audit of the in-tree transports.

Explicit exclusions:

- **Snell**: deferred for now; not part of the current roadmap. No official
  specification, TCP-only, and high interop risk for little gain.
- **WireGuard**: explicitly abandoned. It is an L3 VPN, not a stream proxy, and
  would require TUN or a userspace TCP/IP stack.

Out of scope for v1: TLS MITM, fake-IP, subscription formats, GUI, HTTP
caching, and a userspace TCP/IP stack.

Hysteria2 is the target, not Hysteria v1 (legacy protocol, different transport).

## Alternatives

1. **Protocol-complete v1.** Implement all protocols before release. Rejected:
   in-tree TLS server and QUIC make this a multi-quarter effort, and early
   interface mistakes would be costly.
2. **L4-only library.** Skip L7 and protocol adaptation. Rejected: the user
   requirement explicitly includes L7 and the protocol set.
3. **Config-compatible clone** of an existing proxy. Rejected: license risk
   (ADR-0009) and a large compatibility surface unrelated to the core design.
4. **Keep Snell and WireGuard in scope.** Rejected by the user: Snell adds
   reverse-engineering cost without UDP, and WireGuard does not fit a stream
   proxy library.

## Consequences

- Interfaces must be designed for Phase 3 (QUIC streams). The optional Phase 4
  TUN work may add a packet-level view but must not reshape stream interfaces.
- Each phase has a usable artifact; Phase 1 is a legitimate minimal proxy.
- In-tree TLS/QUIC work (ADR-0007) is on the critical path; Phase 2/3 estimates
  must include it, not treat it as a footnote.
- Dropping Snell and WireGuard removes two fragile integrations and keeps the
  core focused on stream/datagram proxying.
- Documentation must state the phase and excluded protocols so users are not
  misled.

## Approval

- [x] Accepted 2026-11-18 with: Snell deferred, WireGuard abandoned, all other
      protocols and phases accepted as listed.
