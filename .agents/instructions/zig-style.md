# Zig Style

Adapted from TigerBeetle's
[`TIGER_STYLE.md`](https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md)
(Apache-2.0, retrieved 2026-11-18). The principles are shared; the wording and
the adaptations are marmo's. This is the enforceable Zig style for this
repository.

Read `AGENTS.md` first for the design gate. Style is design: every rule below
should make the code safer, faster, or easier to change, in that order.

## The standard

- Safety first, then performance, then developer experience. When they
  conflict, safety wins; when in doubt, choose the simpler design.
- Simplicity is the hardest revision, not the first attempt. Spend time on the
  design, not on defending a weak one.
- Zero technical debt: a known flaw gets fixed now, not "later". Missing
  features are acceptable; incorrect code is not.
- Abstractions are never free. Use the fewest excellent ones the domain needs,
  and keep them leak-proof.
- Prefer explicit, boring code over clever code. Do not make the compiler or
  the next reader guess.

## Adaptations from TigerStyle

TigerStyle assumes a single static binary that owns the machine. marmo is a
library, and the differences are deliberate:

- **Allocation**: all long-lived state is allocated in `Instance.init`, and
  per-connection state comes from a bounded arena at accept/session creation. We
  cannot allocate everything at process start because the embedder owns the
  process and the connection count. The invariant we keep is stricter than
  "allocate early": no allocation on the per-byte or per-packet path.
- **Batching**: the control plane batches config, rules, health checks, and
  metrics. The data plane does not batch relay bytes at the cost of latency;
  predictable per-connection progress matters more.
- **No `main`**: this repository has no executable entrypoint. Public API
  declarations come first in `src/root.zig`; there is no `main` to put at the
  top of a file.
- **Errors before assertions at the boundary**: assertions still guard
  invariants, but every byte from the network is validated with typed errors.
- **std-first stopgaps**: missing transports are implemented in-tree only until
  `std` provides them; deleting in-tree code is expected work.

## Non-negotiables

- Untrusted bytes never cause a panic, undefined behavior, an unbounded read,
  or unbounded allocation. Return typed errors.
- Every loop, queue, buffer, cache, and rule set has a fixed upper bound chosen
  at initialization. If a loop cannot terminate (relay, accept loop), assert the
  invariant that lets it run.
- No allocation on the per-byte or per-packet path. Allocation happens in
  `Instance.init` or at connection/session creation, from a bounded allocator.
- `std`-only: no C, no third-party packages, no vendored crypto (ADR-0007).
  Prefer `std`; in-tree transports are stopgaps and must be deleted when `std`
  provides the same primitive.
- English only in code, comments, docs, and commit messages.

## Control flow and bounds

- No recursion. If a protocol can nest, use an explicit bounded stack or queue
  with a fixed depth and assert it; do not recurse on hostile input.
- Bound every loop. Prefer `for (slice)` over index arithmetic.
- Centralize control flow: push `if`s up and `for`s down. The parent decides;
  leaf helpers compute.
- Split compound conditions. Handle both branches, and avoid negations when a
  positive form exists.
- Keep `if` bodies braced unless the whole statement fits on one line and is a
  single `assert`, `return`, `break`, or `continue`.
- Return early on error; avoid deep nesting.
- Do not duplicate state or alias it. One owner per fact.
- Do not hold a pointer into a buffer across a suspension point. Re-read or
  re-derive it after I/O.

## Assertions

- Assertions detect programmer errors. Use them for invariants, not input
  validation.
- Validate untrusted input with explicit checks and typed errors. `assert` is
  removed in `ReleaseFast`; never rely on it for a security property.
- Target at least two meaningful assertions per non-trivial function. Do not add
  tautologies to hit a quota.
- Pair assertions at boundaries: before writing and after reading, on encode and
  decode, at both ends of a state transition.
- Assert the positive space you expect and the negative space you do not.
  Assert implications with `if (condition) assert(invariant);`.
- Split compound assertions: `assert(a); assert(b);`.
- Assert compile-time relationships with `comptime assert`: wire sizes, field
  offsets, limits.
- `unreachable` is only for states proven impossible by types and prior checks.
  Never use it on network data. Never `catch unreachable` on I/O.

## Errors and diagnostics

- Handle or propagate every error. No `catch {}` that hides a failure and no
  silent fallback.
- Public APIs use typed error sets. No `anyerror` at boundaries.
- Error names describe the failure, not the operation.
- Keep diagnostics separate from errors; a diagnostic carries config paths and
  context but is not part of the error set.
- Panic only for programmer errors, never for malformed input.

## Memory and resources

- Thread allocators explicitly. `gpa` is long-lived; `arena` is
  connection/session-lived. Never use a global allocator or
  `std.heap.page_allocator` in library code.
- Handle allocation failure at the call site. `try` is not a strategy.
- `errdefer` every partial initialization; `defer` cleanup in reverse order.
- Group allocation and deallocation with blank lines so leaks are visible.
- Use fixed relay buffers (default 32 KiB). No per-read or per-packet
  allocation.
- Initialize every byte before sending it. Zero padding; no buffer bleeds.
- Zeroize secrets before free with `std.crypto.secureZero`. Compare passwords,
  tokens, and tags with `std.crypto.timing_safe.eql`.

## Integers, wire formats, parsing

- Use fixed-width types for wire values and limits: `u8`, `u16`, `u32`, `u64`.
  `usize` is only for indexing and slice lengths.
- Read and write endianness explicitly with `std.mem.readInt` and
  `std.mem.writeInt`. Never pointer-cast a network buffer to a struct.
- Check a value before `@intCast`; prefer `std.math.cast`. Never `@truncate` an
  untrusted length.
- Use checked arithmetic for lengths and offsets; reject overflow.
- Slices carry their length. Do not use sentinel-terminated data on the wire.
- Assert wire header sizes and offsets at compile time.
- Treat every length as hostile until bounded by the remaining input.
- Parse field by field. Do not rely on struct layout, alignment, or packing for
  untrusted bytes.
- Distinguish `index`, `count`, and `size`, and make casts between them explicit.
  Use `@divExact` or `@divFloor` when division is intentional.

## Functions and files

- Hard limit: 70 lines per function, excluding the signature and comments. Split
  by responsibility, not by line count.
- Hard limit: 100 columns. Use `zig fmt`; add a trailing comma and let it wrap.
- Four-space indentation. `zig fmt` decides the rest of the layout.
- Prefer simple signatures and return types: `void` over `bool`, `bool` over
  `u64`, `u64` over `?u64`, `?u64` over `!u64`.
- Pass values larger than 16 bytes as `*const` unless a copy is intended.
- Initialize large structs in place through an out-pointer.
- Declare variables at the smallest scope; do not introduce them before use.
- File order: important declarations first; fields, then types, then methods.
  There is no executable entrypoint in this repository.
- File names are `snake_case.zig`; types are `CamelCase`; functions, variables,
  and fields are `snake_case`.
- Do not abbreviate names. Allowed exceptions: `io`, `tcp`, `udp`, `tls`, `dns`,
  `http`, `sni`, `gpa`, `arena`, `ctx`, `id`.
- Put units and qualifiers last: `latency_ms_max`, `buffer_size_max`.
- Related names should align: `source` and `target`, not `src` and `dest`.
- Callbacks go last in parameter lists. Boolean names read positively:
  `is_ready`, not `not_ready`.
- Use the `options: struct` pattern when two arguments can be mixed up.
- Pass options explicitly at the call site; do not rely on library defaults.

## Comments and commits

- Comments explain why, invariants, and surprises. Code explains what.
- Comments are sentences: capital letter, punctuation, and a space after `//`.
- Cite the ADR for non-obvious architectural choices, for example
  `// ADR-0005: first match wins.`
- Delete commented-out code. Do not leave it in place.
- Every TODO or FIXME names an issue or ADR and an owner. Otherwise fix it now.
- Commit messages use an imperative subject and explain why in the body. One
  logical change per commit. A pull request description is not a substitute.

## Concurrency and I/O

- Every I/O operation takes `io: std.Io`; pure helpers do not. Never create
  threads or an event loop.
- `close` unblocks pending I/O. Cancellation is cooperative. Never sleep or
  block on the evented path.
- Shared state uses atomics for counters and a mutex only for config/state
  swaps. No locks in the relay loop.
- Document ownership across tasks. Do not hold a pointer into a buffer across a
  suspension point.
- Re-check invariants after I/O; a precondition may not survive a suspension.
- Use `Io.Group` for structured shutdown: stop accepting, cancel, then close.

## Performance

- Sketch the four resources (network, disk, memory, CPU) and their bandwidth and
  latency before designing a hot path. Put the sketch in the PR or ADR.
- Separate control plane (config, rules, health checks) from data plane (relay,
  parsing). Batch control-plane work; keep the data plane predictable.
- Optimize the slowest resource first, weighted by frequency of use.
- Measure before optimizing. Keep benchmarks out of the default test run.
- Prefer one copy over three; use vectored I/O where it removes a copy.
- Do not rely on the compiler to fix a bad data layout. Write the obvious
  version and measure.

## Testing

- Every bug fix adds a regression test. Every decoder has a fuzz target.
- Test valid and invalid inputs: zero length, maximum length, truncation,
  overflow boundaries, and state transitions.
- Protocol tests use fixtures in `tests/fixtures/<protocol>/`. Never use live
  third-party servers.
- Integration tests bind loopback port 0; no fixed ports.
- Tests are deterministic. No arbitrary sleeps; use timeouts and `std.Io`.
- Run the documented test command before finishing: `zig test <file>` today,
  `zig build test` once the scaffold exists. Keep `AGENTS.md` in sync with the
  verified command.
- Run a single test file with `zig test <file> --test-filter <name>`.

## Tooling and dependencies

- `zig fmt` is mandatory. Run it before finishing.
- Keep repository tooling in Zig where practical. A tiny POSIX sh shim is
  acceptable for bootstrapping (for example, the ADR generator).
- Use the standard Zig build system only. No code generation or network access
  at build time.
- Zero dependencies: every protocol, transport, and helper is ours.
- Never copy code from GPL/AGPL/MPL implementations; implement from specs and
  record sources per ADR-0009. This repository is LGPL-2.1 and stays original.

## Security

- Never log payloads, passwords, UUIDs, private keys, or tokens. Redact them in
  `Debug` output and diagnostics.
- Bound all pre-authentication state and buffers; do not allocate unbounded
  memory before a peer proves it can complete the handshake.
- Compare secrets in constant time. Do not branch on secret data.
- Keep request parsers and handshake state machines fuzzable and free of
  time-of-check/time-of-use gaps.

## Review checklist

- Bounds on every loop, queue, buffer, and cache.
- No allocation or panic on the packet path.
- Input validation uses errors; invariants use assertions.
- Endianness and integer casts are explicit and checked.
- Secrets are zeroized and compared in constant time.
- Function at most 70 lines; line at most 100 columns; `zig fmt` clean.
- Tests cover the negative space; every decoder has a fuzz target.
- Architectural changes cite or update an ADR.
