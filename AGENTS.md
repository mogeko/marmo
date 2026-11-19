# AGENTS.md

marmo is a Zig library for TCP/UDP proxying: L4/L7 inbounds, multiple proxy
protocols, rule-based routing, and latency-aware outbound selection. This
repository ships the library only: no CLI, daemon, or `app` layer.

## Design gate

- Read `docs/architecture.md` and `docs/decisions/` before coding. A `Proposed`
  ADR is not approved: do not implement it. Use the `adr` skill to record a
  decision and wait for the user.
- Accepted ADRs are immutable; supersede them with a new ADR instead of editing.
- Keep `docs/architecture.md`, the ADR index, and this file in sync.
- `Instance` is the composition root; do not add an application layer, CLI, or
  process-level signal handling.

## Repo state

- Phase 1 MVP is implemented. Phase 2 has started with outbound selectors:
  manual, round-robin, random, fallback, and least-latency, plus active TCP
  health probes, VLESS outbound and inbound over TLS (TCP, simple UoT, and
  XUDP), Trojan inbound and outbound over TLS (TCP/UDP, optional routed
  fallback per ADR-0011), a TLS 1.3 client/server with ALPN (ADR-0012), and
  HTTP/2 and WebSocket transport packages (ADR-0013, ADR-0014). `http_head`,
  jitter, and exponential backoff remain, along with VMess, other TLS
  inbounds, protocol-level WS/H2 wiring, sniffing, rule sets, process rules,
  and DNS cache/DoH.
- `packages/tls13/`, `packages/http2/`, and `packages/ws/` are first-party
  packages (ADR-0010, ADR-0013, ADR-0014) with their own builds; the root
  depends on them by path. They have no marmo imports. Root adapters live in
  `src/transport/tls_{client,dialer,server}.zig`, `src/transport/ws_{stream,
  dialer}.zig`, and `src/transport/h2_{stream,dialer}.zig`; inbound
  credentials are loaded by `src/transport/tls_credentials.zig`,
  `src/inbound/vless.zig` handles the protocol, and
  `src/outbound/vless_udp.zig` implements UDP framing. Package rules are in
  `packages/README.md`; root `build.zig` aggregates package tests and exposes
  `check`, `fuzz`, and `examples` steps.
- The bounded fuzz harness lives in `tests/fuzz.zig`; synthetic corpus fixtures
  are under `tests/fixtures/`. The threat model, audit findings, and residual
  risks are in `docs/security/audit.md`. TLS wire details are in
  `docs/protocols/tls.md`.
- `examples/shadowsocks2022/`, `examples/trojan/`, and `examples/vless/` are
  standalone: each has its own `build.zig` and `build.zig.zon` and is not part
  of the root build.
- ADR-0001–0014 are accepted; new architecture decisions need a new ADR.
- Snell is deferred and WireGuard is out of scope (ADR-0002).

## Toolchain gotchas (verified Zig 0.17.1)

- `std.Io` is the runtime: pass `io: std.Io`, never create threads or an event
  loop, and never use `async`/`await` keywords.
- `Io.Evented` exists only on aarch64/x86_64/riscv64 (io_uring, kqueue,
  Dispatch); everything else uses `Io.Threaded`.
- `std` has a TLS **client** only, and it cannot send ALPN. The TLS 1.3
  client and server are in-tree in `packages/tls13`; HTTP/2 and WebSocket are
  in-tree packages. QUIC is still missing. ADR-0007 requires implementing
  missing transports in-tree; there are no optional backends.
- Every allocating API takes an explicit allocator; no globals or thread-locals.

## Zig style

Adapted from TigerBeetle's
[`TIGER_STYLE.md`](https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md)
(Apache-2.0). This is the enforceable Zig style for this repository.

### Priorities

- Safety first, then performance, then developer experience. When they
  conflict, safety wins; when in doubt, choose the simpler design.
- Zero technical debt: fix known flaws now. Missing features are acceptable;
  incorrect code is not. Fewest abstractions that fit the domain.
- Prefer explicit, boring code. Style is design; make correctness visible.

### Safety and bounds

- Untrusted bytes never cause a panic, undefined behavior, an unbounded read,
  or unbounded allocation. Return typed errors.
- Every loop, queue, buffer, cache, and rule set has a fixed upper bound chosen
  at initialization. If a loop cannot terminate (relay, accept), assert the
  invariant that lets it run.
- No recursion. Use a bounded stack or queue for nested protocols.
- No allocation on the per-byte or per-packet path. Long-lived state belongs in
  `Instance.init`; per-connection state comes from a bounded arena.
- English only in code, comments, docs, and commit messages.

### Assertions and errors

- Assertions detect programmer errors; input validation uses typed errors.
  `assert` is removed in `ReleaseFast`; never rely on it for security.
- Target two meaningful assertions per non-trivial function. Pair them at
  boundaries: before write/after read, encode/decode, state transitions.
  Assert compile-time wire sizes and limits.
- Split compound assertions and conditions. Assert the positive and negative
  space; use `if (condition) assert(invariant);`.
- Handle or propagate every error. No `catch {}` or silent fallback. Public
  APIs use typed error sets; diagnostics stay separate from errors.
- `unreachable` only for impossible states proven by types or prior checks;
  never on network data, never `catch unreachable` on I/O.

### Memory and wire data

- Thread allocators explicitly. `gpa` is long-lived; `arena` is
  connection/session-lived. Never use a global allocator or
  `std.heap.page_allocator` in library code.
- `errdefer` partial initialization; group allocation/deallocation to expose
  leaks. Handle allocation failure at the call site.
- Fixed relay buffers (default 32 KiB), zero-initialized before send. No buffer
  bleeds; no per-read allocation.
- Zeroize secrets with `std.crypto.secureZero`; compare passwords, tokens, and
  tags with `std.crypto.timing_safe.eql`.
- Use fixed-width wire types and explicit `std.mem.readInt`/`writeInt`. Never
  pointer-cast network data. Check before `@intCast`; never `@truncate` a
  hostile length.
- Treat every length as hostile until bounded by the remaining input. Parse
  field by field; do not rely on struct layout. Keep `index`, `count`, and
  `size` distinct.

### Shape and naming

- Hard limits: 70 lines per function (excluding signature/comments), 100
  columns, four-space indentation. `zig fmt` decides layout.
- Prefer simple signatures/returns; pass values over 16 bytes as `*const`;
  initialize large structs in place; declare variables at the smallest scope.
- File order: important declarations first, then fields, types, methods. There
  is no executable entrypoint.
- Files `snake_case.zig`; types `CamelCase`; functions/variables/fields
  `snake_case`. No abbreviations except `io`, `tcp`, `udp`, `tls`, `dns`,
  `http`, `sni`, `gpa`, `arena`, `ctx`, `id`.
- Put units/qualifiers last (`latency_ms_max`); align related names (`source`,
  `target`). Options structs when arguments can be mixed up; callbacks last.
- Comments explain why, invariants, and surprises. Cite ADRs for non-obvious
  choices. Delete dead code; TODOs name an issue or ADR and owner.
- Commit messages: imperative subject, why in the body, one logical change.

### I/O and performance

- Every I/O operation takes `io: std.Io`; pure helpers do not. `close` must
  unblock pending I/O; cancellation is cooperative.
- No pointer into a buffer across a suspension point. Re-check invariants after
  I/O. Use `Io.Group` for structured shutdown.
- Atomics for counters; a mutex only for config/state swaps. No locks in the
  relay loop.
- Sketch network, disk, memory, and CPU costs before a hot path. Separate
  control plane (config/rules/health) from data plane (relay/parsing).
- Measure before optimizing; prefer one copy and vectored I/O. Do not rely on
  the compiler to fix a bad data layout.

### Testing and dependencies

- Every bug fix adds a regression test; every decoder has a fuzz target. Test
  zero/max length, truncation, overflow, and invalid transitions.
- Use fixtures in `tests/fixtures/<protocol>/`; loopback port 0; deterministic
  timeouts and `std.Io`. Never use live third-party servers in tests.
- `zig fmt` and `zig build test` before finishing. Run one file with
  `zig test src/net/endpoint.zig --test-filter <name>`.
- Zero dependencies: no C, no third-party packages, no vendored crypto. No
  optional transport backends; implement missing transports in-tree (ADR-0007).
- std-first: when a Zig upgrade provides the primitive, switch to `std` and
  delete in-tree code.
- LGPL-2.1: never copy GPL/AGPL/MPL code. Implement from specs and record sources
  in `docs/protocols/<protocol>.md` (ADR-0009).

### Security

- Never log payloads, passwords, UUIDs, private keys, or tokens; redact them in
  `Debug` output and diagnostics.
- Bound pre-authentication state and buffers; do not allocate unbounded memory
  before a peer completes its handshake.
- Compare secrets in constant time; do not branch on secret data. Keep parsers
  and handshakes fuzzable and free of TOCTOU gaps.

### Review checklist

- Bounds on every loop, queue, buffer, and cache.
- No allocation or panic on the packet path.
- Input validation uses errors; invariants use assertions.
- Endianness and casts explicit; secrets zeroized and constant-time compared.
- Functions ≤70 lines, lines ≤100 columns, `zig fmt` clean, negative-space
  tests present; architectural changes cite or update an ADR.

## Commands and tests

- `zig build test` runs the root unit, public API, and integration tests, the
  package tests, and the deterministic fuzz corpus smoke (152 today: 54 root
  unit, 4 public API, 23 integration, 21 tls13, 20 http2, 18 ws, 12 fuzz).
  `zig build check` adds the formatting check, and `zig build examples` builds
  all examples. CI runs `zig build check` and
  `zig build test -Doptimize=ReleaseSafe`.
- `zig build fuzz` runs the bounded harness with a fixed seed and 1024 inputs
  per target. `-Dfuzz-seed=<decimal>` and `-Dfuzz-iterations=<count>` change
  those values; long runs stay opt-in.
- `(cd packages/tls13 && zig build test)` runs one package in isolation.
- `zig test src/root.zig` runs the module tests directly; use
  `zig test src/net/endpoint.zig --test-filter <name>` for one file or test.
- `zig fmt build.zig src tests packages examples` before finishing.
- Integration tests will use loopback port 0 and never live servers.
- Protocol tests use synthetic fixtures under `tests/fixtures/<protocol>/`;
  provenance and license are recorded in `tests/fixtures/README.md`.
