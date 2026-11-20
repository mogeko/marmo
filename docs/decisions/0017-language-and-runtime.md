# ADR-0017: Language, runtime, and interface model

- Status: Accepted (2026-11-21)
- Date: 2026-11-21
- Deciders: @mogeko
- Related: ADR-0001, ADR-0003, ADR-0007, ADR-0018

## Context

Zig 0.17.1 provides no TLS server, QUIC, HTTP/2 client, WebSocket client, or
DoH client. `std.Io` is pre-1.0, `Io.Evented` exists on three architectures
only, and the toolchain is pinned. As a result this project maintains 15,465
lines of transport code (44% of the tree), and Phase 3 would add QUIC, the
largest state machine of all. The repository is four days old, has no released
API and no downstream users, and its durable assets (protocol notes, fixtures,
ADRs, audit) are language-neutral.

The decider prefers a runtime that is not tied to tokio, but accepts tokio if
runtime independence costs too much. The decision also has to settle the
interface model, because the Zig `Stream`/`PacketConn` vtables exist only
because Zig has no async traits.

## Decision (recommended)

Rewrite the library in Rust, edition 2024, with tokio as the only supported
runtime.

- Public entry points take a `tokio::runtime::Handle`. The library never
  creates or shuts down a runtime; `Instance::run` may own one for examples
  only.
- Concurrency uses `JoinSet`, `TaskTracker`, `CancellationToken`, `Semaphore`,
  `select!`, and `tokio::time`. No bare `tokio::spawn` outside an owner.
- Traits with `async fn` are used where the implementation is static. `dyn` is
  restricted to the two boundaries chosen from config (outbound and transport
  layer), through `dynosaur` or `async-trait`.
- A stream is an `AsyncRead + AsyncWrite + Send + Unpin + 'static` bound, not
  a bespoke trait. Per-connection state is a struct owned by the connection
  task: no arena, no allocator threading, no `close`-unblocks-I/O contract.
- Errors are `thiserror` enums, `#[non_exhaustive]`. `anyhow` appears only in
  examples and tests.
- Codecs and policy code (`marmo-proto`, routing) stay runtime-free and
  I/O-free.
- MSRV starts at 1.85 (edition 2024) and rises only when a pinned dependency
  requires it, recorded in the commit message.

Runtime independence was considered and rejected for this phase. Replacing
tokio's net/sync/time traits with a project-owned `Runtime` trait plus
`futures-io`, `async-lock`, `futures-timer`, `async-net`, `futures-rustls`,
and `async-tungstenite` would add an estimated 4-6 engineer-days, 600-1,000
lines of abstraction, a second CI matrix, and less mature dependency paths. It
would recreate the `std.Io` abstraction tax that this migration exists to
remove.

## Alternatives

1. **Stay on Zig and keep implementing transports in-tree.** No rewrite cost,
   but Phase 3 is blocked on a hand-written QUIC stack and the 15.5k-line
   security surface stays owned by this project. Rejected.
2. **Stay on Zig and wrap C backends (BoringSSL, ngtcp2).** Removes the
   transport work but adds a C ABI, build complexity, and leaves `std.Io`
   churn in place. Rejected.
3. **Rust with a runtime-agnostic I/O layer.** Best for embedders, but the
   cost above is material for a weak requirement with no named embedder.
   Rejected for parity; revisit only with a concrete embedder and a budget.
4. **Rust on async-std or smol.** Smaller ecosystems and less mature
   TLS/QUIC integration, with no benefit for this workload. Rejected.

## Consequences

- The Zig API is replaced by a Rust API; pre-1.0 breaking changes are
  acceptable.
- Embedders must use tokio. The README and API docs say so explicitly.
- Cancellation safety becomes the main new bug class. Every `select!` branch
  is audited, and the parity matrix carries a cancel-safety column.
- The Rust tree is expected at ~11,400 lines versus ~34,900 Zig lines, with
  15,465 lines of transport code deleted.
- Tests run under both tokio flavors; Windows becomes a CI target instead of a
  port.
- No implementation starts before G1: the architecture and roadmap in
  `docs/architecture.md` are approved after this ADR and ADR-0018/0019/0020
  are accepted.

## Approval

- [x] Accept the recommendation (Rust + tokio).
- [ ] Choose the runtime-agnostic I/O layer instead (+4-6 engineer-days).

Accepted 2026-11-21 as recommended.

## Amendment (2026-11-21)

The public API was refined during G1 review. The builder defaults to
`tokio::runtime::Handle::try_current()` and accepts an explicit handle through
`.runtime(handle)` instead of requiring a `Handle` argument on every entry
point. There is no `Instance::run` convenience: the embedder always either is
inside a runtime or supplies one. The tokio decision itself is unchanged; see
§14 of `docs/architecture.md`.
