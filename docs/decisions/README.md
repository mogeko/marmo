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
ADR-0001 through ADR-0016 are retained as historical records from the initial
implementation. Their bodies are unchanged; the current Rust decisions are
ADR-0017 onward.

## Index

| ADR | Topic | Status | Outcome |
| --- | --- | --- | --- |
| [0001](0001-io-runtime.md) | I/O and concurrency runtime | Historical; superseded by ADR-0017 | initial runtime |
| [0002](0002-scope-and-phasing.md) | Scope and delivery phases | Historical; carried over | Snell deferred; WireGuard abandoned |
| [0003](0003-core-abstractions.md) | Core interfaces and dispatch | Historical; superseded by ADR-0017 | initial vtable interfaces |
| [0004](0004-transport-composition.md) | Transport composition | Accepted; in-tree clause superseded | nested dialers |
| [0005](0005-routing-engine.md) | Routing engine | Accepted | first-match rules |
| [0006](0006-outbound-selection.md) | Outbound selection | Accepted | five strategies; probes opt-in |
| [0007](0007-tls-quic-dependencies.md) | TLS, QUIC, crypto dependencies | Historical; superseded by ADR-0018 | initial in-tree policy |
| [0008](0008-api-and-config.md) | Public API, config, errors | Accepted; re-expressed in Rust | lifecycle facade; strict JSON |
| [0009](0009-licensing-and-interop.md) | Licensing and interop hygiene | License half superseded by ADR-0020 | clean-room rule remains |
| [0010](0010-tls-module-package.md) | TLS module package | Historical; superseded by ADR-0019 | initial TLS package |
| [0011](0011-trojan-inbound-fallback.md) | Trojan inbound fallback | Accepted | optional routed fallback |
| [0012](0012-tls-alpn.md) | TLS ALPN negotiation | Accepted; implementation replaced | ALPN, mTLS, KeyUpdate |
| [0013](0013-http2-package.md) | HTTP/2 transport package | Historical; superseded by ADR-0019 | initial H2 package |
| [0014](0014-websocket-package.md) | WebSocket transport package | Historical; superseded by ADR-0019 | initial WS package |
| [0015](0015-connection-limits-and-timeouts.md) | Connection limits and timeouts | Accepted | global limits and deadlines |
| [0016](0016-protocol-transport-wiring.md) | Protocol transport wiring | Accepted; H2 method superseded by ADR-0022 | VLESS transport object |
| [0017](0017-language-and-runtime.md) | Language, runtime, and interface model | Accepted | Rust + tokio |
| [0018](0018-dependencies-and-crypto.md) | Dependencies and crypto backend | Accepted; amended | `rustls` + `aws-lc-rs` |
| [0019](0019-workspace-and-packaging.md) | Workspace layout and packaging | Accepted; fifth crate superseded by ADR-0024 | four published crates |
| [0020](0020-license.md) | License change | Accepted; amended | MIT OR Apache-2.0 |
| [0021](0021-websocket-backend.md) | WebSocket backend and permessage-deflate | Accepted | `ws-net` + tokio pump |
| [0022](0022-vless-http2-method.md) | VLESS HTTP/2 transport method | Accepted | `PUT` client, no content type |
| [0023](0023-tls-credentials-inline.md) | TLS credentials as inline configuration | Accepted | inline PEM; schema v2 |
| [0024](0024-drop-testkit.md) | Drop the unused testkit crate | Accepted (2026-11-21) | four published crates |
| [0025](0025-vmess-aead.md) | VMess AEAD, UDP, and Mux.Cool | Accepted (2026-11-22) | AEAD inbound/outbound; Mux.Cool inbound |
| [0026](0026-vless-mux.md) | VLESS inbound Mux.Cool | Accepted (2026-11-22) | shared Mux.Cool dispatcher |

ADR-0001, 0003, 0007, 0010, 0013, and 0014 are superseded. ADR-0009 is
superseded only in its license half; its clean-room protocol rule remains in
force. ADR-0002, 0005, 0006, 0008, 0011, 0012, 0015, and 0016 carry over; their
current Rust expression is in `docs/architecture.md`.
