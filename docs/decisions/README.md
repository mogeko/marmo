# Architecture Decision Records

One file per decision. ADRs are immutable once accepted: change a decision by
superseding it with a new ADR, never by editing history. A decider-requested
clarification may be appended as an explicit `## Amendment` section with the
date.

## Process

1. Copy `0000-template.md` (or run `.agents/skills/adr/scripts/new-adr.sh <slug>`).
2. Set `Status: Proposed`, name the options, and state a recommendation.
3. Add a row to the index below and link the ADR from
   [`docs/architecture.md`](../architecture.md) when it affects the design.
4. The user decides. Proposed is not approved: do not implement it.
5. On approval, set `Status: Accepted`, keep the chosen option, and reconcile
   `docs/architecture.md`. On rejection, set `Status: Rejected` and record why.

Statuses: `Proposed` → `Accepted` | `Rejected` | `Superseded by ADR-NNNN`.

## Index

| ADR | Topic | Status | Outcome |
| --- | --- | --- | --- |
| [0001](0001-io-runtime.md) | I/O and concurrency runtime | Accepted | `std.Io`; no owned runtime |
| [0002](0002-scope-and-phasing.md) | Scope and delivery phases | Accepted | Snell deferred; WireGuard abandoned; phases as listed |
| [0003](0003-core-abstractions.md) | Core interfaces and dispatch | Accepted | vtable interfaces; internal concrete types |
| [0004](0004-transport-composition.md) | Transport composition | Accepted | nested dialers |
| [0005](0005-routing-engine.md) | Routing engine | Accepted | first-match rules; no regex in v1 |
| [0006](0006-outbound-selection.md) | Outbound groups and selection | Accepted | five strategies; probes opt-in |
| [0007](0007-tls-quic-dependencies.md) | TLS, QUIC, crypto dependencies | Accepted | std-first; in-tree transports; no optional backends |
| [0008](0008-api-and-config.md) | Public API, config, errors | Accepted | lifecycle facade; strict JSON; typed errors |
| [0009](0009-licensing-and-interop.md) | Licensing and interop hygiene | Accepted | LGPL-2.1; clean-room protocol work |
| [0010](0010-tls-module-package.md) | TLS module as a replaceable package | Accepted | `packages/tls13`; std-only API; path dependency |
| [0011](0011-trojan-inbound-fallback.md) | Trojan inbound fallback | Accepted | optional explicit fallback; routed through `Dispatch`; no default |
| [0012](0012-tls-alpn.md) | TLS ALPN negotiation | Accepted | ALPN on client and server; in-tree TLS 1.3 client |
| [0013](0013-http2-package.md) | HTTP/2 transport package | Accepted | `packages/http2`; one stream; framing/HPACK/flow control |
| [0014](0014-websocket-package.md) | WebSocket transport package | Accepted | `packages/ws`; RFC 6455 handshake and framing |
| [0015](0015-connection-limits-and-timeouts.md) | Connection limits and idle timeouts | Accepted | global limits 1024/10/300/1/1; per-connection watchdog; UDP excluded |

## Accepted decisions

ADR-0001–0010 were accepted on 2026-11-18 (ADR-0010 on 2026-11-19); ADR-0011
was accepted on 2026-11-19. ADR-0012–0014 were accepted on 2026-11-19 on the
direct implementation request. ADR-0015 was accepted on 2026-11-20 after
reference-implementation research.

- **ADR-0002**: Snell deferred, WireGuard abandoned; all other protocols and
  phases accepted.
- **ADR-0007**: no optional backends or C dependencies; TLS 1.3 server, QUIC,
  HTTP/2, WebSocket, and gRPC are implemented in-tree, with a std-first rule
  that replaces them as soon as Zig's `std` provides the same primitive.
- **ADR-0011**: Trojan inbound `fallback` is optional and explicit; it is
  routed through `Dispatch` and has no default endpoint.
- **ADR-0012–0014**: TLS ALPN is negotiated on both sides by an in-tree TLS
  1.3 client/server; HTTP/2 and WebSocket are std-only first-party packages
  with one active stream (H2) and bounded RFC 6455 framing (WS).
- **ADR-0015**: a global `limits` policy caps TCP connections and applies
  handshake, idle, and half-close grace timeouts, enforced by one reaper per
  `Instance`.
- **ADR-0001, 0003–0006, 0008, 0009**: accepted as recommended.
