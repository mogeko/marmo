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
| 2 | Full protocol/transport set, routing depth, selectors, DNS | Complete |
| 3 | QUIC, TUIC, Hysteria2, gRPC, XHTTP | Not started |
| 4 | TUN/transparent, platform hardening, external audit | Not started |

Phase 2 is closed; Phase 3 is the only remaining implementation phase before
platform hardening and audit. The original Phase 3 "in-tree QUIC" clause is
superseded by ADR-0018: the Rust tree uses `quinn` rather than writing a QUIC
stack.

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

**Status: complete.** Core protocol transports, TLS, selectors, health, limits,
rule sets, process identity, DNS, root-level HTTP/2 pooling, and fixture parity
are complete.

### Completed

| ID | Item | Status | Depends on | Exit criteria |
| --- | --- | --- | --- | --- |
| P2-1 | VLESS inbound/outbound: TCP, simple UoT, XUDP, inbound Mux.Cool | Done | P1 | TCP/UDP/XUDP/mux tests and reference interop |
| P2-2 | Trojan inbound/outbound: TCP, UDP, routed fallback | Done | P1 | Loopback TCP/UDP and fallback tests |
| P2-3 | TLS 1.3: ALPN, mTLS, platform verifier | Done | P1 | `rustls` tests and TLS interop |
| P2-4 | WebSocket and HTTP/2 transports | Done | P1 | WS/H2 loopback, interop, VLESS over both |
| P2-5 | Selectors and health probes | Done | P1-6 | Five strategies, EWMA, TCP probes, unit tests |
| P2-6 | Connection limits and deadlines | Done | P1-2 | Absolute handshake, shared idle, half-close tests |
| P2-7 | VMess AEAD inbound/outbound: TCP, direct UDP, Mux.Cool | Done | P2-3, P2-4 | Vectors, loopback, Xray interop, fuzz |
| P2-8 | Sniffing: TLS SNI, HTTP Host, HTTP/2 `:authority` | Done | P1-4, P2-1, P2-3 | Buffered replay, routing on sniffed domain, tests |
| P2-9 | Injected domain/IP sets: GEOIP/GEOSITE, keyword, port ranges, inbound | Done | P1-6, P2-8 | `DomainSet`/`IpSet` injection, bounded refs, hot-swappable data, routing tests (ADR-0028) |
| P2-10 | Process rules via injected resolver (`process_name`/`process_path`) | Done | P1-6 | Resolver injection, bounded cache/timeout, fail-open, tests (ADR-0029) |
| P2-11 | DNS cache + DoH/DoT resolver | Done | P1-1 | TTL cache, bounded entries, DoH policy, fallback tests (ADR-0030) |
| P2-12 | Root-level HTTP/2 multiplexing and pooling | Done | P2-4 | Multiple streams per connection, 4/16/64 pool bounds, inbound stream budget, tests (ADR-0031) |
| P2-13 | Fixture parity for all codecs | Done | P1-5, P2-1..P2-4 | Golden fixtures per codec, Mux fuzz target, provenance, differential interop records |
| P2-14 | Client-side Mux.Cool pooling (VMess/VLESS) | Done | P2-1, P2-7 | Pool bounds, TCP/UDP/mixed, Xray interop |

**Phase 2 gate:** every item is complete. VMess landed under ADR-0025, DNS
under ADR-0030, and root HTTP/2 multiplexing/pooling under ADR-0031.

## Phase 3 — QUIC, TUIC, Hysteria2, gRPC, XHTTP

**Status: not started.** Phase 2 is closed; Phase 3 can start with the
datagram/endpoint boundary.

| ID | Item | Status | Depends on | Exit criteria | Estimate |
| --- | --- | --- | --- | --- | --- |
| P3-1 | Datagram/QUIC endpoint boundary | Planned | P1-2 | `Datagram`/endpoint abstraction, bounded queues, cancellation tests | 1–2 d |
| P3-2 | QUIC transport adapter (`quinn`) | Planned | P3-1 | Stream and datagram adapters, ALPN, idle/close, loopback tests | 2–3 d |
| P3-3 | TUIC inbound/outbound | Planned | P3-2 | Auth, stream/datagram relay, congestion config, reference interop | 2–3 d |
| P3-4 | Hysteria2 inbound/outbound | Planned | P3-2 | TLS-over-QUIC, UDP relay, Brutal/congestion policy, reference interop | 2–4 d |
| P3-5 | gRPC transport | Planned | P2-4 | `tonic`/H2 framing, `application/grpc`, trailers, VLESS/VMess interop | 1–2 d |
| P3-6 | XHTTP transport | Planned (needs ADR) | P2-4; P3-2 for `h3` | `transport.network = "xhttp"`, stream-one first, reference interop, bounded bodies | 2–4 d |

XHTTP is newer than ADR-0002: current Xray releases removed HTTP/2 in favour
of XHTTP, so it is the compatibility transport to add after the H2 work. It
needs its own ADR before implementation; `h3` depends on the QUIC adapter.

**Phase 3 gate:** QUIC adapter bounded and cancellable; TUIC and Hysteria2
interop against self-hosted reference implementations; gRPC framing/trailer
tests; XHTTP ADR and stream-one interop; fuzz/decoder coverage where a new
codec exists; docs updated.

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
  +--> P2-7 VMess --+--> P2-14 client mux
  +--> P2-3 TLS -----+--> P2-4 WS/H2 --+--> P2-12 H2 pooling
  |                                    +--> P3-5 gRPC
  |                                    +--> P3-6 XHTTP (h3 after P3-2)
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

1. Settle P3-1 datagram/endpoint boundary.
2. Build P3-2 QUIC, then P3-3 TUIC and P3-4 Hysteria2.
3. P3-5 gRPC and P3-6 XHTTP can run in parallel once H2 is stable; XHTTP `h3`
   follows P3-2.
4. Phase 4 TUN/transparent depends on routing and platform work; external audit
   is last.

## Post-1.0 backlog

These are documented capabilities that are not part of the Phase 0-4 exit
criteria. They are tracked here so they do not disappear from the docs.

| ID | Item | Status | Notes |
| --- | --- | --- | --- |
| P5-1 | SOCKS5 outbound | Planned | architecture §2 marks it later work |
| P5-2 | `http_head` health checks, jitter, exponential backoff | Planned | selection/health follow-up |
| P5-3 | Config reload (`ArcSwap`) | Planned | architecture §5 |
| P5-4 | `tracing` spans, structured logs, and complete metrics | Planned | architecture §17; add rule-hit, dropped-datagram, failure, and per-node health counters |
| P5-5 | XUDP per-packet targets, GlobalID/cone NAT | Deferred | one fixed destination per stream today |
| P5-6 | Shadowsocks 2022 ChaCha20, anti-probing, non-direct UDP, padding policies | Deferred | direct-only UDP today |
| P5-7 | TLS resumption/0-RTT/ECH/OCSP/CRL | Deferred | depends on `rustls` capability |
| P5-8 | Trojan-Go WebSocket/Mux/XTLS | Deferred | not part of standard Trojan |
| P5-9 | WS early data/heartbeat; VLESS `flow`/XTLS Vision | Deferred | compatibility extensions |
| P5-10 | Windows-specific process matching in the embedder resolver | Planned | with P2-10, best-effort |
| P5-12 | VMess authenticated-length option | Deferred | only if a reference client enables Opt A |

## Release packaging order

All four crates take their version from `[workspace.package]`, and path
dependencies pin that version exactly (`=0.0.3`). Bump the workspace version
once, then publish in dependency order, because a crate must be visible in the
crates.io index before anything that depends on it.

| Step | Crate | Depends on |
| --- | --- | --- |
| 1 | `marmo-net` | nothing |
| 2 | `marmo-proto` | `marmo-net` |
| 3 | `marmo-transport` | upstream crates only |
| 4 | `marmo` | the three crates above |

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
