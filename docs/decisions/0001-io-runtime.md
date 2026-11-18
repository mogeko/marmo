# ADR-0001: I/O and concurrency runtime

- Status: Accepted (2026-11-18)
- Date: 2026-11-18
- Deciders: @mogeko
- Related: ADR-0003, ADR-0008

## Context

A proxy is dominated by network I/O: accept, handshake, relay, timeouts, and
cancellation. Zig 0.17.1 provides `std.Io`, which abstracts I/O and concurrency
across platforms with two useful implementations:

- `Io.Threaded`: blocking operations on worker threads, available everywhere.
- `Io.Evented`: io_uring on Linux, kqueue on BSD, Dispatch on Apple platforms,
  but only on architectures where fiber switching exists (aarch64, x86_64,
  riscv64). Windows and other architectures use `Io.Threaded`.

marmo is a library. Embedders may already own a runtime, and tests need to run
the same code on both implementations. The decision determines the public API
shape and the cancellation model for everything else.

## Decision

Parameterize on `std.Io` and never own the runtime.

- Public entry points take `io: std.Io` and an explicit allocator.
- The library creates no OS threads and no event loop. Concurrency uses
  `io.async`, `io.concurrent`, and `Io.Group`.
- The embedder creates `Io.Threaded` or `Io.Evented`; the library never chooses
  or owns the runtime.
- Timeouts use `Io.Timeout`; cancellation relies on `close` unblocking pending
  operations plus group cancellation.
- No global state, no thread-locals, and no reliance on blocking `poll`/`select`
  outside `std.Io`.

## Alternatives

1. **Thread per connection with `std.Thread` and blocking sockets.** Simple and
   portable, but the library would own threads, scale poorly with thousands of
   idle connections, and make shutdown/cancellation ad hoc.
2. **Own reactor** over epoll/kqueue/io_uring. Maximum control, but duplicates
   `std.Io`, multiplies platform code, and makes embedding hostile.
3. **Callback-only API** where the embedder drives I/O. Flexible but pushes the
   entire state machine into user code; poor ergonomics for a library.

## Consequences

- The Zig version is pinned; `std.Io` is pre-1.0 and may change.
- Every public operation carries `io`; this is intentional and must not be
  hidden behind a global.
- `Io.Evented` requires fiber support; unsupported architectures fall back to
  `Io.Threaded`. CI should test both where possible.
- Interfaces must document that `close` unblocks readers/writers, or relay
  shutdown will hang.
- Benchmarks must compare Threaded and Evented; do not assume Evented is faster
  for small relays.

## Approval

- [x] Accepted 2026-11-18 as recommended.
