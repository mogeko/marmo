# Roadmap

- Status: current release `0.0.3`.
- Source: ADR-0002 (scope and phases), re-expressed for the Rust tree by
  ADR-0017 through ADR-0023.
- This document is the dependency-ordered work list. ADRs remain the decision
  record; `docs/architecture.md` remains the design.

## Phase summary

| Phase | Goal | Status |
| --- | --- | --- |
| 0 | Decisions, workspace, CI, baseline | Complete |
| 1 | Minimal usable proxy | Complete |
| 2 | Full protocol/transport set, routing depth, selectors, DNS | In progress |
| 3 | QUIC, TUIC, Hysteria2, gRPC | Not started |
| 4 | TUN/transparent, platform hardening, external audit | Not started |

Phase 2 is not fully closed, so Phase 3 should not be treated as the only
remaining work. The original Phase 3 "in-tree QUIC" clause is superseded by
ADR-0018: the Rust tree uses `quinn` rather than writing a QUIC stack.

## Phase 0 — decisions and baseline

**Status: complete.** No remaining work.

| ID | Item | Status | Depends on | Exit criteria |
| --- | --- | --- | --- | --- |
| P0-1 | Scope, license, runtime, dependencies, workspace decisions | Done | — | ADR-0017..ADR-0023 accepted |
| P0-2 | Five-crate workspace and MSRV | Done | P0-1 | `cargo test --workspace --locked` on Linux/macOS/Windows |
| P0-3 | CI: fmt, clippy, tests, MSRV, audit, copyleft | Done | P0-2 | All jobs green on `master` |
| P0-4 | Fuzz harness and corpus baseline | Done | P0-2 | `cargo +nightly fuzz build` and decoder smoke pass |
| P0-5 | Docs, ADR index, protocol notes | Done | P0-1 | `docs/architecture.md`, `docs/decisions/`, `docs/protocols/` current |

## Phase 1 — minimal usable proxy

**Status: complete.** No remaining work.

| ID | Item | Status | Depends on | Exit criteria |
| --- | --- | --- | --- | --- |
| P1-1 | `Endpoint`, CIDR, `Network`, config, limits | Done | P0 | Unit tests and strict config validation |
| P1-2 | TCP/UDP engine, relay, cancellation, admission control | Done | P1-1 | Loopback relay, deadline, limit tests |
| P1-3 | SOCKS5 CONNECT + UDP ASSOCIATE inbound | Done | P1-2 | TCP/UDP loopback and interop |
| P1-4 | HTTP CONNECT + forward inbound; HTTP CONNECT outbound | Done | P1-2 | Loopback tests and interop |
| P1-5 | Shadowsocks 2022 TCP/UDP | Done | P1-1, P1-2 | Vectors, loopback, `shadowsocks-rust` interop |
| P1-6 | Direct outbound and rule routing | Done | P1-2 | Domain/suffix/CIDR/port/network tests |
| P1-7 | Metrics counters and redaction | Done | P1-2 | Snapshot and sink tests |

## Phase 2 — full protocol/transport set and routing depth

**Status: in progress.** Core protocol transports, TLS, selectors, health, and
limits are complete. The remaining items are independent enough to be taken in
any order after their dependencies.

### Completed

| ID | Item | Status | Depends on | Exit criteria |
| --- | --- | --- | --- | --- |
| P2-1 | VLESS inbound/outbound: TCP, simple UoT, XUDP | Done | P1 | TCP/UDP/XUDP tests and reference interop |
| P2-2 | Trojan inbound/outbound: TCP, UDP, routed fallback | Done | P1 | Loopback TCP/UDP and fallback tests |
| P2-3 | TLS 1.3: ALPN, mTLS, platform verifier | Done | P1 | `rustls` tests and TLS interop |
| P2-4 | WebSocket and HTTP/2 transports | Done | P1 | WS/H2 loopback, interop, VLESS over both |
| P2-5 | Selectors and health probes | Done | P1-6 | Five strategies, EWMA, TCP probes, unit tests |
| P2-6 | Connection limits and deadlines | Done | P1-2 | Absolute handshake, shared idle, half-close tests |

### Remaining

| ID | Item | Status | Depends on | Exit criteria | Estimate |
| --- | --- | --- | --- | --- | --- |
| P2-7 | VMess codec and inbound/outbound | Deferred | P2-3, P2-4 | Vectors, loopback, reference interop, fuzz | TBD; not scheduled |
| P2-8 | Sniffing: TLS SNI, HTTP Host, HTTP/2 `:authority` | Planned | P1-4, P2-1, P2-3 | Buffered replay, routing on sniffed domain, tests | 2–3 d |
| P2-9 | Compiled rule sets: GEOIP/GEOSITE, keyword, port ranges, inbound | Planned | P1-6, P2-8 | Versioned compiled format, bounded load, routing tests | 3–5 d |
| P2-10 | Process rules (`sysinfo`, opt-in) | Planned | P1-6 | Fail-open "unknown", per-platform tests | included in P2-9 |
| P2-11 | DNS cache + DoH/DoT resolver | Planned | P1-1 | TTL cache, bounded entries, DoH policy, fallback tests | 2–3 d |
| P2-12 | Root-level HTTP/2 multiplexing and pooling | Planned | P2-4 | Multiple streams per connection, pool bounds, tests | 1–2 d |
| P2-13 | Fixture parity for all codecs | Planned | P1-5, P2-1..P2-4 | Corpus/unit vectors, differential interop records | 1 d |

**Phase 2 gate:** every remaining item either complete or explicitly moved out
of Phase 2 by an ADR. VMess is currently deferred by the architecture; if it
stays deferred, record that decision rather than leaving Phase 2 ambiguous.

## Phase 3 — QUIC, TUIC, Hysteria2, gRPC

**Status: not started.** Phase 3 depends on Phase 2 closeout for release
sequencing, but the QUIC adapter can be developed in parallel once the
datagram/endpoint boundary is settled.

| ID | Item | Status | Depends on | Exit criteria | Estimate |
| --- | --- | --- | --- | --- | --- |
| P3-1 | Datagram/QUIC endpoint boundary | Planned | P1-2 | `Datagram`/endpoint abstraction, bounded queues, cancellation tests | 1–2 d |
| P3-2 | QUIC transport adapter (`quinn`) | Planned | P3-1 | Stream and datagram adapters, ALPN, idle/close, loopback tests | 2–3 d |
| P3-3 | TUIC inbound/outbound | Planned | P3-2 | Auth, stream/datagram relay, congestion config, reference interop | 2–3 d |
| P3-4 | Hysteria2 inbound/outbound | Planned | P3-2 | TLS-over-QUIC, UDP relay, Brutal/congestion policy, reference interop | 2–4 d |
| P3-5 | gRPC transport | Planned | P2-4 | `tonic`/H2 framing, `application/grpc`, trailers, VLESS/VMess interop | 1–2 d |

**Phase 3 gate:** QUIC adapter bounded and cancellable; TUIC and Hysteria2
interop against self-hosted reference implementations; gRPC framing/trailer
tests; fuzz/decoder coverage where a new codec exists; docs updated.

Open question: Hysteria2's Brutal congestion controller must fit `quinn`'s
controller trait, or the design needs an ADR before implementation.

## Phase 4 — TUN, platforms, production readiness

**Status: not started.** Windows is already a CI target; this phase is about
packet-level ingress, platform behavior, and the external audit.

| ID | Item | Status | Depends on | Exit criteria | Estimate |
| --- | --- | --- | --- | --- | --- |
| P4-1 | TUN inbound | Planned | P1-2, P2-9 | Bounded packet queues, Linux/macOS loopback, no stream reshaping | 5–8 d |
| P4-2 | Transparent proxying (`iptables`/TPROXY) | Planned | P4-1 | Linux-only, documented privileges, routing tests | 3–5 d |
| P4-3 | Platform hardening | Planned | P2-10, P4-1 | Windows/macOS/Linux behavior documented and tested | 2–3 d |
| P4-4 | External security audit | Planned | P2, P3, P4-1 | Independent review of codecs, config, relay, cancellation | External |
| P4-5 | Production-readiness claim | Planned | P4-4 | Audit findings closed; no open critical/high risks | — |

## Dependency graph

```text
P0 decisions/workspace/CI
  |
  v
P1 core (net, config, relay, limits)
  |-- P1 SOCKS5/HTTP/SS2022/direct/routing
  |
  +--> P2-1 VLESS --+
  +--> P2-2 Trojan --+
  +--> P2-3 TLS -----+--> P2-4 WS/H2 --+--> P2-12 H2 pooling
  |                                    +--> P3-5 gRPC
  +--> P2-5 selectors/health
  +--> P1-6 routing --+--> P2-9 rule sets --> P4-1 TUN
                      +--> P2-10 process rules
  +--> P2-8 sniffing
  +--> P2-11 DNS resolver
  |
  +--> P3-1 datagram/QUIC boundary --> P3-2 QUIC --> P3-3 TUIC
                                                   --> P3-4 Hysteria2
  |
  +--> P4-1 TUN --> P4-2 transparent --> P4-3 platform hardening
  |
  +--> P4-4 external audit --> P4-5 production readiness
```

## Critical path

1. Close Phase 2: P2-8 sniffing, P2-9/P2-10 rule sets and process rules,
   P2-11 DNS, P2-12 H2 pooling; record VMess as deferred or schedule it.
2. Settle P3-1 datagram/endpoint boundary.
3. Build P3-2 QUIC, then P3-3 TUIC and P3-4 Hysteria2.
4. P3-5 gRPC can run in parallel once H2 is stable.
5. Phase 4 TUN/transparent depends on routing and platform work; external audit
   is last.

## Out of scope

- Snell (deferred; no official specification).
- WireGuard (L3 VPN, not a stream proxy).
- TLS MITM, fake-IP, subscription formats, GUI, HTTP caching, userspace TCP/IP.
- VMess legacy CFB is not planned.

## Tracking

- Update the status column in the same change that closes an item.
- A Phase 2/3 item is not done without its tests, interop/fuzz evidence, and
  docs.
- New capabilities that change scope need an ADR before implementation.
