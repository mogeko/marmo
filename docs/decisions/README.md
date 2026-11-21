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
| [0001](0001-io-runtime.md) | I/O and concurrency runtime | Superseded by ADR-0017 | `std.Io`; no owned runtime |
| [0002](0002-scope-and-phasing.md) | Scope and delivery phases | Accepted | Snell deferred; WireGuard abandoned; phases as listed |
| [0003](0003-core-abstractions.md) | Core interfaces and dispatch | Superseded by ADR-0017 | vtable interfaces; internal concrete types |
| [0004](0004-transport-composition.md) | Transport composition | Accepted (in-tree clause superseded by ADR-0018) | nested dialers |
| [0005](0005-routing-engine.md) | Routing engine | Accepted | first-match rules; no regex in v1 |
| [0006](0006-outbound-selection.md) | Outbound groups and selection | Accepted | five strategies; probes opt-in |
| [0007](0007-tls-quic-dependencies.md) | TLS, QUIC, crypto dependencies | Superseded by ADR-0018 | std-first; in-tree transports; no optional backends |
| [0008](0008-api-and-config.md) | Public API, config, errors | Accepted (re-expressed in Rust) | lifecycle facade; strict JSON; typed errors |
| [0009](0009-licensing-and-interop.md) | Licensing and interop hygiene | Superseded in part by ADR-0020 | LGPL-2.1; clean-room protocol work |
| [0010](0010-tls-module-package.md) | TLS module as a replaceable package | Superseded by ADR-0019 | `packages/tls13`; std-only API; path dependency |
| [0011](0011-trojan-inbound-fallback.md) | Trojan inbound fallback | Accepted | optional explicit fallback; routed through `Dispatch`; no default |
| [0012](0012-tls-alpn.md) | TLS ALPN negotiation | Accepted | ALPN, mTLS, AES-128/256-GCM and ChaCha20-Poly1305, X25519/P-256, KeyUpdate |
| [0013](0013-http2-package.md) | HTTP/2 transport package | Superseded by ADR-0019 | `packages/http2`; 16-stream multiplexing; framing/HPACK/flow control; 1xx/trailers |
| [0014](0014-websocket-package.md) | WebSocket transport package | Superseded by ADR-0019 | `packages/ws`; RFC 6455, permessage-deflate, subprotocols |
| [0015](0015-connection-limits-and-timeouts.md) | Connection limits and idle timeouts | Accepted | global limits 1024/10/300/1/1; per-Instance reaper; UDP excluded |
| [0016](0016-protocol-transport-wiring.md) | Protocol transport composition wiring | Accepted | VLESS `transport` tcp/ws/h2; TLS ALPN defaults; WS compression/subprotocols; H2 one stream per Instance connection |
| [0017](0017-language-and-runtime.md) | Language, runtime, and interface model | Accepted (2026-11-21) | Rust + tokio |
| [0018](0018-dependencies-and-crypto.md) | Dependencies and crypto backend | Accepted (2026-11-21; amended) | in-tree transports deleted; `rustls` + `aws-lc-rs`; WebSocket crate superseded by ADR-0021; `cargo tree` copyleft check |
| [0019](0019-workspace-and-packaging.md) | Workspace layout and packaging | Accepted (2026-11-21) | five crates |
| [0020](0020-license.md) | License change | Accepted (2026-11-21; amended) | MIT OR Apache-2.0; `cargo tree` license review |
| [0021](0021-websocket-backend.md) | WebSocket backend and permessage-deflate | Accepted (2026-11-21) | `ws-net` + tokio pump; compression enabled |
| [0022](0022-vless-http2-method.md) | VLESS HTTP/2 transport method | Accepted (2026-11-21) | `PUT` client, no content type; `POST`/`PUT` server |
| [0023](0023-tls-credentials-inline.md) | TLS credentials as inline configuration | Accepted (2026-11-21) | inline PEM; no filesystem I/O in build/bind; schema v2 |

## Eras

- **Zig era (0001-0016)**: ended on 2026-11-21. Its decisions remain as
  history; the conflicting ones are marked superseded in the index, and their
  bodies are unchanged.
- **Rust era (0017-)**: accepted on 2026-11-21. `docs/architecture.md` is the
  canonical design; implementation starts at G1.

The Zig-era architecture is archived at
[`docs/archive/architecture-zig.md`](../archive/architecture-zig.md). The
index above is the only place where the effective status of each ADR is
recorded; ADR bodies are never edited.


## Accepted decisions

ADR-0001–0010 were accepted on 2026-11-18 (ADR-0010 on 2026-11-19); ADR-0011
was accepted on 2026-11-19. ADR-0012–0014 were accepted on 2026-11-19 on the
direct implementation request. ADR-0015 was accepted on 2026-11-20 after
reference-implementation research; ADR-0016 was accepted on 2026-11-20 on the
direct implementation request.

- **ADR-0002**: Snell deferred, WireGuard abandoned; all other protocols and
  phases accepted.
- **ADR-0007**: no optional backends or C dependencies; TLS 1.3 server, QUIC,
  HTTP/2, WebSocket, and gRPC are implemented in-tree, with a std-first rule
  that replaces them as soon as Zig's `std` provides the same primitive.
- **ADR-0011**: Trojan inbound `fallback` is optional and explicit; it is
  routed through `Dispatch` and has no default endpoint.
- **ADR-0012–0014**: TLS ALPN is negotiated on both sides by an in-tree TLS
  1.3 client/server; HTTP/2 and WebSocket are std-only first-party packages
  with bounded 16-stream H2 multiplexing and RFC 6455 framing (WS).
- **ADR-0016**: VLESS inbounds/outbounds accept a strict `transport` object
  (`tcp`, `ws`, `h2`) with transport-aware ALPN defaults and WebSocket
  compression/subprotocol options; other protocols reject it.
- **ADR-0015**: a global `limits` policy caps TCP connections and applies
  handshake, idle, and half-close grace timeouts, enforced by one reaper per
  `Instance`.
- **ADR-0001, 0003-0006, 0008, 0009**: accepted as recommended.

### Rust era

ADR-0017–0020 were accepted on 2026-11-21:

- **ADR-0017**: Rust, edition 2024, with tokio as the only supported runtime;
  traits and futures replace the vtable/`close` interface model.
- **ADR-0018**: the in-tree TLS, HTTP/2, and WebSocket implementations are
  deleted in favour of `rustls`, `h2`, and (originally) `tokio-tungstenite`;
  the crypto provider is `aws-lc-rs`, and a C toolchain is an accepted build
  prerequisite. The WebSocket crate was superseded by ADR-0021.
- **ADR-0019**: a five-crate workspace (`marmo`, `marmo-proto`, `marmo-net`,
  `marmo-transport`, `marmo-testkit`).
- **ADR-0020**: relicensed to MIT OR Apache-2.0.
- **ADR-0021**: WebSocket runs on `ws-net` with a tokio pump, enabling RFC 7692
  permessage-deflate; it supersedes ADR-0018's WebSocket crate choice.
- **ADR-0022**: HTTP/2 uses `PUT` without a content type on the client and
  accepts `POST`/`PUT` on the server; it supersedes ADR-0016's method clause.

ADR-0001, 0003, 0007, 0010, 0013, and 0014 are superseded. ADR-0009 is
superseded only in its license half; its clean-room protocol rule remains in
force.
