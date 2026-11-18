# AGENTS.md

marmo is a Zig library for TCP/UDP proxying: L4/L7 inbounds, multiple proxy
protocols, rule-based routing, and latency-aware outbound selection. This
repository ships the library only: no CLI, daemon, or `app` layer.

## Design gate

- Read `docs/architecture.md` and `docs/decisions/` before coding. A `Proposed`
  ADR is not approved: do not implement it. Use the `adr` skill to record a
  decision and wait for the user.
- Accepted ADRs are immutable; supersede them with a new ADR instead of editing.
- Keep `docs/architecture.md`, the ADR index, and this file in sync with
  behavior changes.
- `Instance` is the composition root; do not add an application layer, CLI, or
  process-level signal handling to the library.
- Follow `.opencode/instructions/zig-style.md` (loaded through
  `.opencode/opencode.json`); it is the enforceable Zig style for this
  repository.

## Repo state

- Phase 1 MVP is implemented: strict JSON config, direct TCP/UDP and HTTP
  CONNECT outbounds, SOCKS5 (CONNECT + UDP ASSOCIATE), HTTP CONNECT + forward
  proxying, Shadowsocks 2022 TCP/UDP (AES-128/256-GCM), domain/IP-CIDR/port
  routing, relay, and metrics. Phase 2 is next; SIP022 gaps are listed in
  `docs/protocols/shadowsocks.md`.
- ADR-0001–0009 are accepted; new architecture decisions need a new ADR.
- Snell is deferred and WireGuard is out of scope (ADR-0002).

## Toolchain gotchas (verified Zig 0.17.1)

- `std.Io` is the runtime: pass `io: std.Io`, never create threads or an event
  loop, and never use `async`/`await` keywords.
- `Io.Evented` exists only on aarch64/x86_64/riscv64 (io_uring, kqueue,
  Dispatch); everything else uses `Io.Threaded`.
- `std` has a TLS **client** only. No TLS server, no QUIC, no HTTP/2, no
  WebSocket client. ADR-0007 requires implementing missing transports in-tree;
  there are no optional backends.
- Every allocating API takes an explicit allocator; no globals or thread-locals.

## Hard rules

- English only: code, comments, docs, commit messages.
- Default build is std-only: no C toolchain, no network access, no optional
  backends, no vendored crypto. Never implement crypto primitives by hand.
- No third-party TLS/QUIC/HTTP2/WebSocket packages: implement missing
  transports in-tree (ADR-0007). They are std-first stopgaps: when a Zig
  upgrade adds the primitive, switch to `std` and delete the in-tree code.
- LGPL-2.1. Never copy code from sing-box/Xray/v2ray (GPL/AGPL/MPL); implement
  from specs and record sources in `docs/protocols/<protocol>.md` (ADR-0009).
- Parsers see untrusted bytes: bounded reads, typed errors, no panics, and a
  fuzz target for every decoder.
- Never log payloads, passwords, UUIDs, private keys, or tokens.

## Commands and tests

- `zig build test` runs the unit, public API, and integration tests (34 tests
  today). Reference-implementation interop is local-only and not part of this
  repository or CI.
- `zig test src/root.zig` runs the module tests directly; use
  `zig test src/net/endpoint.zig --test-filter <name>` for one file or test.
- `zig fmt build.zig src tests` before finishing; CI runs
  `zig fmt --check build.zig src tests`.
- Integration tests will use loopback port 0 and never live servers.
- Protocol tests use captured fixtures under `tests/fixtures/<protocol>/`.
