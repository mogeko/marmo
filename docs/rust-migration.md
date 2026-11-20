# Rust migration: feasibility and roadmap

- Status: Research. Not a decision, not approved for implementation.
- Date: 2026-11-21
- Scope: the whole repository (library, packages, examples, tests).
- Related: ADR-0001, ADR-0003, ADR-0004, ADR-0007, ADR-0009, ADR-0010,
  ADR-0013, ADR-0014, ADR-0016.

## 0. Recommendation

Rewrite the project in Rust, in this repository, as a second workspace
(`crates/`) while the Zig tree stays frozen but buildable. Implementation
starts only after ADR-0017..ADR-0020 are accepted and the architecture and
roadmap are approved.

The case is not "Rust is nicer". It is that this repository already spends
**15,465 of its ~35,000 lines (44%) re-implementing transports that the Rust
ecosystem ships and audits** — TLS 1.3 client/server, HTTP/2, WebSocket — and
that the next phase needs QUIC, which is the largest and riskiest of those
re-implementations. Rust removes that work and replaces it with `rustls`,
`h2`, `quinn`, and `tokio-tungstenite`; the proxy-specific code that remains
(protocols, routing, inbounds/outbounds, config) is roughly 9,000 lines and is
the part worth owning.

The migration is affordable *because of the timing*: the repository is four
days old (first commit 2026-11-18, 65 commits), so there is no installed base,
no released API to preserve, and the reusable assets — protocol notes,
fixtures, ADRs, interop knowledge — are language-neutral.

Estimated effort to reach parity with today's implemented scope: **18-35
engineer-days, most likely ~25**, where one engineer-day is six productive
hours. That is 4-7 weeks full time or 7-14 weeks at three hours a day.
Estimates are ±40%; the uncertainty is in protocol edge cases, not line count.

## 1. What the Zig stack costs today

The cost is documented in the repository itself.

| Constraint | Concrete cost in this repo |
| --- | --- |
| `std` has no TLS server | `packages/tls13`, 7,097 lines: handshake, record layer, certificate path, signature, credentials, interop tests |
| `std` has no HTTP/2 | `packages/http2`, 4,279 lines: framing, HPACK + Huffman, flow control, multiplexing |
| `std` has no WebSocket | `packages/ws`, 4,089 lines: handshake, framing, permessage-deflate, subprotocols |
| `std` has no QUIC | Phase 3 is blocked on the largest in-tree state machine in the plan; TUIC and Hysteria2 cannot start |
| `std.Io` is pre-1.0 | Toolchain pinned to 0.17.x; `Io.Evented` exists on three architectures only; `Io.Threaded` starvation forced a design note in `src/core/connection_guard.zig` |
| No `Semaphore` / `TaskTracker` / cancel token | `connection_guard.zig` (355 lines) plus one reaper task per `Instance` to police handshake/idle/half-close deadlines |
| No `async`/`await` | Manual `io.concurrent` fan-out, `close`-unblocks-I/O contract in the `Stream` vtable, guard/peer pointers for abort |
| No serde | `src/config/config.zig`, 1,879 lines of hand-written strict JSON parsing and path-aware validation |
| No DoH/DoT resolver, no gRPC, no process-info crate | Phase 2/3 items that are library calls elsewhere |
| No first-class test/fuzz tooling | bespoke `tests/fuzz.zig` + fixtures under `tests/fixtures/` |

None of this is a criticism of the implementation; the code is careful and the
ADRs are explicit about the trade. It is a statement about where the next 10k
lines would go if the project stays on Zig: into TLS/QUIC infrastructure rather
than into proxying.

### 1.1 Cost of *not* migrating

- Phase 3 (QUIC, TUIC, Hysteria2) becomes a multi-week hand-written protocol
  effort with an external-audit obligation before any production claim.
- Every Zig upgrade re-opens `std.Io` and `std.json` churn; the pinned version
  is a permanent tax.
- Windows support stays deferred: `Io.Evented` does not cover it and the
  `Io.Threaded` fallback is the design constraint that shaped the reaper.
- The in-tree crypto-adjacent surface (15,465 lines of TLS/H2/WS parsers)
  remains the highest-risk part of the codebase and must be fuzzed, audited,
  and maintained by this project alone.

## 2. Why the timing is favourable

| Factor | Today | After Phase 3 |
| --- | --- | --- |
| Hand-written transport lines to discard | 15,465 | ~25,000+ with QUIC |
| Released API to preserve | none (0.0.2, unstable) | unknown |
| Protocol fixtures and notes | already written | more to rewrite |
| Downstream embedders | none known | unknown |
| Rewrite cost | weeks | months |

The assets that survive are exactly the expensive-to-recreate ones:
`docs/protocols/*.md` (spec sources, ambiguities, interop notes),
`tests/fixtures/*` (byte-level, language-neutral), the ADR history, the
security audit and threat model, and the protocol behaviour itself.

## 3. Target ecosystem (verified 2026-11-21 against crates.io)

Every crate below was checked for its SPDX license. Under the accepted
MIT OR Apache-2.0 license (ADR-0020), all of them are usable, including
Apache-2.0-only crates. Under the old LGPL-2.1 they would have been usable only
by taking the MIT/ISC option. The two exceptions are noted below the table.

| Capability | Crate | Version | License | Replaces |
| --- | --- | --- | --- | --- |
| Runtime, TCP/UDP, timers, sync | `tokio` | 1.54.1 | MIT | `std.Io`, `Io.Group` |
| Cancellation, `TaskTracker`, codecs | `tokio-util` | 0.7.20 | MIT | `connection_guard`, group cancel |
| TLS 1.3 client/server, ALPN, mTLS | `rustls` + `tokio-rustls` | 0.23.46 / 0.26.6 | Apache-2.0 OR ISC OR MIT | `packages/tls13` (7,097) |
| Platform trust store | `rustls-platform-verifier` | 0.7.1 | MIT OR Apache-2.0 | `cert_path.zig` (part of `tls13`) |
| QUIC v1, streams, datagrams, pluggable CC | `quinn` | 0.11.12 | MIT OR Apache-2.0 | Phase 3 QUIC |
| HTTP/2 framing, HPACK, flow control | `h2` | 0.4.20 | MIT | `packages/http2` (4,279) |
| HTTP/1.1 client/server, CONNECT | `hyper` + `http`, or `httparse` | 1.12.0 / 1.5.0 / 1.10.1 | MIT | `src/inbound/http.zig` |
| WebSocket, permessage-deflate | `tokio-tungstenite` | 0.30.0 | MIT | `packages/ws` (4,089) |
| gRPC (Phase 3) | `tonic` | 0.14.9 | MIT | — |
| DNS, DoH, DoT, cache | `hickory-resolver` | 0.26.3 | MIT OR Apache-2.0 | `src/net` resolver |
| Config, strict JSON, path errors | `serde`, `serde_json`, `serde_path_to_error` | 1.0.229 / 1.0.154 / 0.1.20 | MIT OR Apache-2.0 | `config.zig` (1,879) |
| Structured logging/tracing | `tracing` | 0.1.44 | MIT | `std.log` + `Diagnostic` |
| Config reload | `arc-swap` | 1.9.5 | MIT OR Apache-2.0 | manual atomic swap |
| Byte buffers | `bytes` | 1.12.2 | MIT | arena + slices |
| Typed errors | `thiserror` | 2.0.21 | MIT OR Apache-2.0 | error sets |
| Secret redaction/zeroization | `secrecy`, `zeroize` | 0.10.3 / 1.9.2 | Apache-2.0 OR MIT | manual `secureZero` |
| IP/CIDR | `ipnet` | 2.12.2 | MIT OR Apache-2.0 | `net/cidr.zig` |
| Domain keyword/suffix sets | `aho-corasick` | 1.1.5 | Unlicense OR MIT | `routing/rules.zig` |
| SS2022 AEAD | `aes-gcm`, `chacha20poly1305`, `blake3` | 0.11.1 / 0.11.0 / 1.8.7 | Apache-2.0 OR MIT / CC0 OR Apache-2.0 | `protocol/shadowsocks2022.zig` |
| Socket options | `socket2` | 0.6.5 | MIT OR Apache-2.0 | `transport/tcp.zig` |
| Process rules | `sysinfo` | 0.40.4 | MIT | `routing` process matcher |
| Property tests, fuzz, bench, snapshots | `proptest`, `cargo-fuzz`, `criterion`, `insta` | 1.12.0 / 0.13.2 / 0.8.2 | MIT OR Apache-2.0 | `tests/fuzz.zig` |

Two notes:

- **License history.** `s2n-quic` is Apache-2.0 **only**, which was
  incompatible with the old LGPL-2.1 under the FSF reading (LGPL-2.1 is built
  on GPL-2.0). ADR-0020 removes that constraint by moving to MIT OR
  Apache-2.0, but `quinn` is still preferred for its congestion-controller
  trait and ecosystem fit. `webpki-roots` is CDLA-Permissive-2.0: a permissive
  *data* license, not code; record it in `NOTICE` or prefer the platform
  verifier. `insta` is Apache-2.0-only and stays a dev-dependency.
- **C toolchain returns.** `rustls` ships `aws-lc-rs` (Apache-2.0 OR ISC) or
  `ring` (ISC); both compile C and assembly. ADR-0007's "no C toolchain" is not
  survivable. There is no production-grade pure-Rust TLS stack, and writing one
  is the thing this migration exists to stop doing. This must be an explicit,
  user-approved consequence.

## 4. Architecture for the Rust version

The abstractions that exist in Zig because of `std.Io`'s shape should not be
ported. The rewrite should delete them, not translate them.

### 4.1 Workspace layout

```
crates/
  marmo-proto/       wire codecs only: socks5, http1, ss2022, trojan, vless, xudp
  marmo-net/         Endpoint, CIDR, socket options, resolver policy
  marmo-transport/   Stream/Datagram traits, TLS/WS/H2/QUIC adapters, relay
  marmo/             facade: Instance, config, routing, inbounds, outbounds,
                     metrics, public API
  marmo-testkit/     fake streams, fixture loaders, loopback helpers (dev-only)
```

Five crates, not ten. Rationale: crate boundaries are a compile-time and
ownership tool, not a documentation device. `inbound`, `outbound`, `routing`,
and `config` live inside `marmo` because they are cyclic in practice
(`Instance` wires all of them) and splitting them buys nothing but
re-export churn. `marmo-proto` is separate because it must stay I/O-free and
fuzzable in isolation; `marmo-transport` because it wraps the external
TLS/QUIC/H2/WS implementations and needs its own fuzz and bench targets.

Dependency direction stays the same as §6 of `docs/architecture.md`:
`marmo` → everything, `marmo-transport` → `marmo-net`, `marmo-proto` →
`marmo-net` (address parsing only); `marmo-net` → nothing.

### 4.2 Concurrency and lifetime model

- **Runtime**: `tokio`, multi-threaded or current-thread. The embedder owns the
  `Runtime`; the builder defaults to `Handle::try_current()` and accepts an
  explicit handle through `.runtime()`. This replaces ADR-0001's "never own the
  runtime" with "never own the runtime unless asked".
- **Cancellation**: one `CancellationToken` per `Instance`, child tokens per
  listener and per connection. Every `select!` waits on `cancelled()`; dropping
  a connection task is the abort path. No `close`-unblocks-I/O contract, no
  peer pointers.
- **Structured shutdown**: `JoinSet` per listener, `TaskTracker` for UDP
  sessions. `InstanceHandle::shutdown()` cancels the root token; `serve` and
  `BoundInstance::serve` drain with `timeout(grace)`.
- **Limits**: `Arc<Semaphore>` with `try_acquire_owned()` for TCP, and a second
  bounded semaphore for UDP sessions (ADR-0015 keeps them separate). This
  deletes `connection_guard.zig` and the reaper: admission control is the
  permit, deadlines are `tokio::time::timeout` / `Sleep` inside `select!`.
- **Backpressure**: bounded `mpsc` per UDP session; no unbounded channels, no
  unbounded `spawn`.
- **Config reload**: `ArcSwap<CompiledConfig>`; readers clone an `Arc` per
  connection, so the data plane never locks.
- **Per-connection state**: a struct owned by the connection task. The arena
  disappears: `Metadata` holds `Bytes`/`Arc<str>` for the domain, and everything
  dies with the task.

This is the largest structural simplification. Roughly 700 lines of Zig
(guard registry, reaper, abort paths, manual group fan-out) become permit +
token + `select!`.

### 4.3 Interfaces

Rust changes what an interface must be. The Zig `Stream` vtable exists because
Zig has no trait objects with async methods; Rust has both traits and
`tokio::io::AsyncRead/AsyncWrite`. Do not port `Stream`/`PacketConn` as vtables.

```rust
// A stream is a bound, not a bespoke trait.
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> AsyncStream for T {}

pub trait Outbound: Send + Sync {
    fn connect<'a>(
        &'a self,
        target: &'a Endpoint,
        opts: &'a ConnectOptions,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncStream>, ConnectError>>;

    fn connect_datagram<'a>(
        &'a self,
        target: &'a Endpoint,
        opts: &'a ConnectOptions,
    ) -> BoxFuture<'a, Result<Box<dyn Datagram>, ConnectError>>;
}
```

- Use `async fn` in traits + `dynosaur` (or `async-trait`) only at the two
  boundaries that are chosen at runtime: outbound and transport adapter.
  Everything else stays static/generic.
- `Dialer`/`Transport` becomes a *builder* that wraps one stream in another
  (`TlsDialer<WsDialer<TcpDialer>>` is not needed; use a `Vec<Layer>` compiled
  at startup and `Box<dyn AsyncStream>` per layer).
- Codecs remain plain functions over `&mut Bytes`/`&[u8]` returning
  `Result<T, ProtoError>`; they do not know about tokio and are shared by
  inbound and outbound exactly as today.
- `PacketConn` is replaced by `tokio::net::UdpSocket` for the direct case and a
  small `Datagram` trait only for protocol-owned datagram channels
  (VLESS UoT, Trojan UDP, TUIC).
- `Router::match(&Metadata) -> Action` stays synchronous and allocation-free;
  rules live in `Arc<CompiledRules>`.

### 4.4 Data plane

- Relay: `tokio::io::copy_bidirectional_with_sizes(32 KiB)` wrapped in
  `CountingStream` (bytes per direction, metrics) and `IdleTimeout` adapters
  (activity-based deadline). Half-close is handled by `copy_bidirectional`.
  This replaces the hand-written relay and its guard integration.
- UDP: session table keyed by `(client, target, inbound, assoc_id)`, capacity
  bounded at init, LRU eviction, one task per session holding a permit, idle
  expiry via `select!`. Same policy as §9.2 of the architecture, less code.
- Fixed relay buffers stay fixed (32 KiB default) and are reused, not allocated
  per read.

### 4.5 Config, errors, secrets

- `serde` with `#[serde(deny_unknown_fields)]` and `serde_path_to_error` gives
  path-aware diagnostics (`inbounds[0].port`) without the hand-written parser.
  Keep the JSON schema compatible with v1 so existing configs still load; the
  Rust API itself is a new major surface.
- One `thiserror` enum per layer; `anyhow` only in examples/tests. No
  `Box<dyn Error>` across the public API.
- `secrecy::SecretString` for passwords/UUIDs; `zeroize` on drop; custom
  `Debug` or no `Debug` on secret-bearing structs. Keep the "never log
  payloads, passwords, UUIDs, or SNI" rule.
- Add a `#[non_exhaustive]` policy so enum growth is not a breaking change.

### 4.6 Observability and testing

- `tracing` spans per connection (`inbound`, `outbound`, `network`, hashed SNI)
  replace `std.log` + `Diagnostic`; redaction is a span-field policy.
- Metrics: keep a concrete `Metrics` struct of atomics behind an optional
  `MetricsSink`; do not pull a full OpenTelemetry stack into the library.
- Tests: `#[tokio::test(flavor = "multi_thread")]` and
  `flavor = "current_thread"` replace the Threaded/Evented matrix;
  `tokio::io::duplex` for codec/relay tests without sockets; loopback port 0
  for integration; `insta` for config-error snapshots; `proptest` + `cargo-fuzz`
  for decoders (the existing fixtures are bytes and move unchanged);
  `tokio::time::pause()` for deterministic timeout and half-close tests.
  `cargo-fuzz` runs on nightly; the library itself stays on stable.
- Interop: `shadowsocks-rust` is an MIT crate and `sing-box` a GPL-3.0 binary;
  running either as an external reference server in CI is permitted by
  ADR-0009 because no code is linked, ported, or distributed. This replaces the
  hand-run local interop check. `sodium`/`libcrypto` bindings are not needed:
  SS2022 uses the RustCrypto crates listed above.
- Optional `loom` for the session table and permit logic; `miri` on the codec
  crates; `criterion` benches gated behind a non-default feature.

## 5. Port inventory

Line counts are from the current tree (excluding `.zig-cache`).

| Area | Zig lines | Action | Rust estimate | Risk |
| --- | --- | --- | --- | --- |
| `packages/tls13` | 7,097 | **delete** | ~150 adapter | low (rustls) |
| `packages/http2` | 4,279 | **delete** | ~250 adapter | low (`h2`) |
| `packages/ws` | 4,089 | **delete** | ~200 adapter | low |
| `src/transport` (adapters, tcp, udp, relay glue) | 3,343 | rewrite | ~1,200 | medium (composition order) |
| `src/protocol` (ss2022, trojan, vless, xudp) | 3,050 | port semantics | ~2,400 | **high** (wire edge cases) |
| `src/inbound` (socks5, http, ss, vless, trojan, udp) | 2,164 | rewrite | ~1,600 | medium |
| `src/outbound` (direct, http, ss, vless, trojan, selector) | 1,370 | rewrite | ~1,100 | medium |
| `src/config` | 1,879 | rewrite (serde) | ~700 | low |
| `src/instance.zig` | 1,430 | rewrite | ~700 | medium (wiring) |
| `src/core` (relay, guard, metrics, dispatch) | 689 | mostly delete | ~300 | low |
| `src/net` (endpoint, cidr) | 268 | port | ~250 | low |
| `src/routing` | 269 | port | ~250 | low |
| `tests` (fuzz, integration, public API) | 4,369 | port fixtures, rewrite harness | ~2,000 | medium |
| `examples/*` | 566 | rewrite | ~300 | low |
| **Total** | **~34,900** | | **~11,400** | |

Net effect: about 15.5k lines of security-critical infrastructure leave the
repository, and the Rust tree is roughly one third the size of the Zig tree.

## 6. Invariants that must survive the rewrite

These are the contracts the current ADRs and audit encode. Each becomes a
review checklist item and, where possible, a test.

1. Untrusted bytes never panic, never allocate unboundedly, never recurse.
2. Every loop, queue, session table, and cache has a bound fixed at init.
3. Half-close is propagated; a half-close is never turned into a full close.
4. Secrets are zeroized and compared in constant time; never logged.
5. Config parsing is strict; unknown fields are errors; diagnostics are
   path-aware.
6. No global mutable state; no implicit runtime, logger, or thread.
7. UDP datagrams above `max_datagram_size` are rejected, not fragmented.
8. Timeouts are deterministic and injectable in tests.
9. Protocol work stays clean-room (ADR-0009); fixtures keep provenance.
10. No allocation on the per-packet path; relay buffers are fixed and reused.

New Rust-specific invariants:

11. Every `select!` branch is cancel-safe, or the future is not dropped.
12. No `std::sync::Mutex` guard held across `.await` (`clippy::await_holding_lock`).
13. No unbounded `tokio::spawn`; every task is owned by a `JoinSet`/`TaskTracker`.
14. No blocking work on the async executor (`spawn_blocking` for file/cert I/O).
15. `unsafe` is denied outside the transport crate and justified per block.

## 7. Risks and mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Cancellation-safety bugs in protocol state machines | silent data loss, half-open sessions | cancel-safety column in the port matrix; drop-mid-await tests; `select!` discipline review |
| Protocol regressions while porting | interop failures, security holes | byte fixtures unchanged; differential interop vs `shadowsocks-rust`/`sing-box`; fuzz before cutover |
| Dependency supply chain | compromised or abandoned crates | pinned `Cargo.lock`, `--locked` CI, `cargo-deny` (licenses, advisories, bans), `cargo-audit`, MSRV policy, optional `cargo vendor` |
| License drift (GPL/AGPL/MPL) | copyleft contamination | `cargo-deny` allowlist per ADR-0020; deny GPL/AGPL/MPL; `NOTICE`; CI gate |
| C toolchain in crypto backend | breaks a stated constraint and CI simplicity | explicit decision; pin one provider (`aws-lc-rs` or `ring`); document the build prerequisite; CI image installs it |
| Compile time / binary size | slower iteration | 5-crate workspace, tuned release profile, `cargo nextest` |
| Throughput regression vs Zig | user-visible | criterion benches + loopback comparison against the Zig build before deleting it |
| Ecosystem churn (rustls/quinn majors) | upgrade work | pin ranges, isolate in `marmo-transport` adapters |
| Tokio lock-in in the public API | embedder constraint | documented; `Handle` injection keeps ownership explicit |

## 8. Roadmap

Gates are decision points; phases end with green CI and a parity row, not with
"code written".

### Gate G0 — decision (1 day)

Write and accept ADR-0017..ADR-0020 (see §10) and approve
`docs/architecture.md`. No code before G0.

### R0 — scaffold and decisions (2 days)

- `crates/` workspace, `rust-toolchain.toml`, MSRV, release profile.
- CI: `fmt`, `clippy -D warnings`, `test`, `cargo-deny`, `cargo-audit`,
  Linux x86_64 + macOS arm64 + Windows x86_64.
- Move `tests/fixtures/` and `docs/protocols/` unchanged; keep the Zig tree
  building so fixtures can be cross-checked.
- `marmo-testkit` skeleton: fake stream, loopback helper, fixture loader.
- **Exit:** empty facade compiles on all three OS targets; CI gates enforce the
  license allowlist.

### S — spikes, in parallel with R0/R1 (2-3 days)

- **S1:** `rustls` server with ALPN + mTLS + ECDSA/Ed25519 certs, and a client
  that talks VLESS-over-TLS to a reference server.
- **S2:** `quinn` with a custom congestion controller (Brutal feasibility) and
  datagram support; proves Phase 3 is a wiring job, not a protocol job.
- **S3:** relay throughput/CPU on loopback compared with the Zig build at 32 KiB
  buffers.

Spikes are throwaway code; their output is a short written note under
`docs/`, not a merge.

### R1 — core plumbing and TCP path (3 days)

- `Endpoint`, CIDR, socket options, resolver trait.
- `Instance`, `CancellationToken` tree, `JoinSet`, `Semaphore` limits,
  graceful shutdown.
- Relay with counting/idle adapters; direct outbound; TCP inbound skeleton.
- **Exit:** loopback TCP relay test with handshake/idle/half-close deadlines;
  limit-exceeded path covered; no reaper, no guard registry.

### R2 — config, routing, Phase 1 protocols (5 days)

- serde config with strict unknown-field rejection and path diagnostics.
- Compiled rules (domain exact/suffix/keyword, CIDR, port, network, inbound).
- SOCKS5 inbound (CONNECT + UDP ASSOCIATE), HTTP inbound (CONNECT + forward),
  HTTP CONNECT outbound, direct UDP.
- SS2022 TCP + UDP on `aes-gcm`/`chacha20poly1305`/`blake3`.
- **Exit:** config-error snapshots match the Zig behaviour; SS2022 interop both
  directions against `shadowsocks-rust`; UDP session caps tested.

### R3 — TLS and Phase 2 protocols (6 days)

- `rustls` adapters: client, server, ALPN, mTLS, platform verifier, TLS 1.3 only.
- Trojan inbound/outbound (TCP/UDP, routed fallback).
- VLESS inbound/outbound: TCP, simple UoT, XUDP.
- Transport composition: TCP, TLS, WebSocket, HTTP/2; `transport.network`
  config, ALPN defaults, WS compression/subprotocols.
- **Exit:** every row of the protocol matrix that says "yes" today still says
  yes; interop against reference implementations; fixture and fuzz parity.

### R4 — hardening, cutover (5 days)

- Fuzz all decoders (`cargo-fuzz`, reuse corpus) for 24h clean.
- Property tests for config and rule compilation; `loom`/`miri` where useful.
- Benchmarks vs the Zig baseline; document any regression and accept or fix.
- Port the three examples; rewrite README/AGENTS/architecture docs.
- **Exit:** parity matrix complete; audit findings from `docs/security/audit.md`
  re-checked against the Rust code; Zig tree deleted in one commit after a
  `zig-final` tag.

### R5 — post-parity (new capability, 14-23 days)

Not migration work, but the reason to migrate. Ordered by value:

| Item | Effort | Enabled by |
| --- | --- | --- |
| QUIC, TUIC, Hysteria2 | 6-10 d | `quinn` |
| DNS cache + DoH/DoT | 2-3 d | `hickory-resolver` |
| gRPC transport | 1-2 d | `h2`/`tonic` |
| Rule sets, GEOIP/GEOSITE, process rules | 3-5 d | `aho-corasick`, `sysinfo` |
| HTTP/2 root multiplexing/pooling | 1-2 d | `h2` |
| `http_head` health checks, jitter, backoff | 1 d | `tokio::time` |

### Total

| Phase | Engineer-days |
| --- | --- |
| G0 + R0 + spikes | 5-6 |
| R1 | 3 |
| R2 | 5 |
| R3 | 6 |
| R4 | 5 |
| **Parity** | **25 (range 18-35)** |

Assumptions: one experienced engineer familiar with both languages, agent
assistance, ~6 productive hours/day, no new protocol scope during migration.
Calendar: 4-7 weeks full time; 7-14 weeks at ~3 h/day. R5 is separate.

## 9. Migration mechanics

**Repository strategy (recommended).** One repository, two trees. Add
`crates/` beside `src/`, keep `docs/` shared, keep the Zig build green until
R4. This preserves the fixtures, protocol notes, and git history in one place
and lets the Rust integration tests run *against* the Zig build during the
transition.

Rejected alternatives:

- **Long-lived `rust` branch or a new repository.** Same work, worse review
  ergonomics, and fixtures/docs would fork.
- **Strangler via C ABI** (Zig calls Rust or vice versa). Async runtimes do not
  compose across an FFI boundary; the C ABI would grow into a second design.
- **Incremental per-module rewrite behind FFI.** Only pays off with an installed
  user base, which does not exist.

**Freeze policy.** From R1 on, the Zig tree takes only security fixes and
fixture additions. No new protocols, no refactors.

**Parity matrix.** One row per capability (config field, protocol, transport,
matcher, limit, metric) with columns: Zig behaviour, Rust test, interop,
fuzz. Cutover requires every row green and no `todo!()`/`unimplemented!()` on a
reachable path.

**Cutover criteria.** Parity matrix complete; 24h fuzz clean per decoder;
interop green in both directions; benchmarks within an agreed tolerance;
`docs/architecture.md`, `AGENTS.md`, `README.md` rewritten; Zig tree deleted
after a `zig-final` tag.

**Rollback.** Because the Zig tree stays buildable until cutover, rollback is a
branch revert, not a rescue.

## 10. Decisions, status, and ADR sequencing

The 2026-11-21 review settled the ADR strategy: **do not restart numbering and
do not delete the Zig-era records.** Start a new era inside the existing series,
with ADR-0017 as the baseline that resets the language, runtime, and interface
assumptions. Most decisions (scope, routing, selection, limits, Trojan
fallback, transport wiring) are language-independent and carry over; only the
baseline, the dependency policy, the packaging, and the license need new ADRs.

Status after the 2026-11-21 acceptance:

| Item | Status | Decision |
| --- | --- | --- |
| Go / no-go | decided | Go; implementation starts at G1 |
| License | decided | MIT OR Apache-2.0 (ADR-0020) |
| Runtime | decided | tokio (ADR-0017); runtime-agnostic was rejected at +4-6 engineer-days |
| Crypto backend | decided | C toolchain allowed; `aws-lc-rs` pinned (ADR-0018) |
| Parity scope | decided | Current implemented set only; Phase 3 waits for R5 |
| Repository strategy | decided | Same repository, two trees (architecture §19.2) |
| ADR sequencing | decided | ADR-0017 (baseline), 0018 (dependencies), 0019 (workspace), 0020 (license) |

Supersessions (accepted 2026-11-21):

| New ADR | Decision | Supersedes |
| --- | --- | --- |
| 0017 | Language, runtime, and interface model: Rust + tokio | 0001, 0003 |
| 0018 | Dependency and crypto-backend policy | 0007; the in-tree clause of 0004 |
| 0019 | Workspace layout and packaging | 0010, 0013, 0014 |
| 0020 | License change | the license half of 0009 |

ADR-0002 (scope/phasing), 0005 (routing), 0006 (selection), 0008 (API and
config), 0011 (Trojan fallback), 0015 (limits), and 0016 (transport wiring)
carry over as decisions; their implementations change, their intent does not.

## 11. What this study did not verify

- Actual throughput and CPU parity with the Zig build (S3).
- Interop of `rustls`/`quinn` against the reference servers used today for
  VLESS, Trojan, TUIC, and Hysteria2 (SS2022 interop does not involve either).
- Hysteria2's Brutal congestion control through `quinn`'s controller trait (S2).
- Behaviour of `rustls` client-certificate verification against the mTLS cases
  covered by `packages/tls13` today (S1).
- Long-run stability of the `h2` crate under VLESS's one-stream-per-connection
  usage and the planned root-level pooling.

Each is a spike in R0/S and a written finding before R1 closes.

## Appendix A. Parity matrix (seed)

Frozen at G1. `Zig source` names the behavior being preserved; `Interop` means
a self-hosted reference peer or fixture; `Cancel` is the dropped-future test.

| Capability | Zig source | Rust test | Interop | Fuzz | Cancel |
| --- | --- | --- | --- | --- | --- |
| Config: v1 schema, strict unknown fields, defaults | `config.zig` | snapshot per field | — | proptest | — |
| Config: path-aware diagnostics | `diagnostic.zig` | snapshot `inbounds[0].port` | — | proptest | — |
| Limits: max connections, handshake/idle/half-close | `limits.zig`, `connection_guard.zig` | paused-time loopback | — | — | yes |
| SOCKS5 CONNECT | `inbound/socks5.zig` | duplex + loopback | fixture | decoder | yes |
| SOCKS5 UDP ASSOCIATE | `inbound/socks5.zig` | loopback UDP | fixture | decoder | yes |
| HTTP CONNECT + forward | `inbound/http.zig` | duplex + loopback | fixture | decoder | yes |
| HTTP CONNECT outbound | `outbound/http_connect.zig` | loopback | fixture | decoder | yes |
| SS2022 TCP (AES-128/256-GCM) | `protocol/shadowsocks2022.zig` | vectors + loopback | shadowsocks-rust | decoder | yes |
| SS2022 UDP | `protocol/shadowsocks2022.zig` | vectors + loopback | shadowsocks-rust | decoder | yes |
| Trojan TCP + fallback | `protocol/trojan.zig`, `inbound/trojan.zig` | loopback TLS | reference server | decoder | yes |
| Trojan UDP | `protocol/trojan.zig` | loopback TLS | reference server | decoder | yes |
| VLESS TCP + simple UoT | `protocol/vless.zig` | loopback | reference server | decoder | yes |
| VLESS XUDP | `protocol/xudp.zig` | vectors | reference server | decoder | yes |
| TLS 1.3: ALPN, mTLS, suites, certs, KeyUpdate | `packages/tls13` | rustls tests + loopback | reference server | — | — |
| WebSocket: framing, deflate, subprotocols | `packages/ws` | `tokio-tungstenite` tests | reference server | decoder | — |
| HTTP/2 transport: 16 streams, 1xx, trailers | `packages/http2` | `h2` tests + loopback | reference server | — | — |
| Transport object: tcp/ws/h2, ALPN defaults | `instance.zig` | config + loopback | reference server | — | — |
| Routing: domain, suffix, CIDR, port, network | `routing/rules.zig` | table tests | — | proptest | — |
| Selection: manual/RR/random/fallback/least-latency | `outbound/selector.zig` | deterministic unit | — | — | — |
| Health: TCP probe, EWMA, failure counter | `outbound/selector.zig` | paused-time unit | — | — | — |
| Metrics and redaction | `core/metrics.zig` | unit | — | — | — |
| Examples: ss2022, trojan, vless | `examples/` | build + smoke | — | — | — |
