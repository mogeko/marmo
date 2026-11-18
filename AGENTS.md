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
- Follow `.agents/instructions/zig-style.md` (loaded through `opencode.json`);
  it is the enforceable Zig style for this repository.

## Repo state

- Design-only right now: no `build.zig` or `src/` yet. Don't invent module work
  or run `zig build` until the Phase 0 scaffold exists (architecture §12/§15).
- ADR-0001–0009 are accepted; new architecture decisions need a new ADR.
  Implement Phase 1 only until the user moves on.
- Snell is deferred and WireGuard is out of scope (ADR-0002).

## Toolchain gotchas (verified Zig 0.17.1)

- `std.Io` is the runtime: pass `io: std.Io`, never create threads or an event
  loop, and never use `async`/`await` keywords.
- `Io.Evented` exists only on aarch64/x86_64/riscv64 (io_uring, kqueue,
  Dispatch); everything else uses `Io.Threaded`.
- `std` has a TLS **client** only. No TLS server, no QUIC, no HTTP/2, no
  WebSocket client. ADR-0007 requires implementing missing transports in-tree;
  there are no optional backends.
- Every API takes an explicit allocator; no globals or thread-locals.

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

- No build commands exist yet. A single test file can be run directly with
  `zig test <file> --test-filter <name>`.
- After scaffolding, put the verified `zig build test` invocation here and add a
  `test` step; integration tests use loopback port 0 and never live servers.
- Run `zig fmt` and the documented tests before finishing.
- Protocol tests use captured fixtures under `tests/fixtures/<protocol>/`.
