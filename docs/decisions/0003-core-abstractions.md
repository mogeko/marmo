# ADR-0003: Core interfaces and dispatch

- Status: Accepted (2026-11-18)
- Date: 2026-11-18
- Deciders: @mogeko
- Related: ADR-0001, ADR-0004, ADR-0005

## Context

Config chooses inbounds, outbounds, transports, and rules at runtime, so the
implementation behind an interface is not known at compile time. The hot path
is a byte relay; per-operation overhead must stay negligible compared with a
syscall, and ownership must be explicit so connections do not leak.

Zig offers three ways to model this: vtable-based interfaces (like `std.Io`),
tagged unions, or comptime monomorphization. Third-party protocol plugins are
not a requirement.

## Decision

Use vtable interfaces at layer boundaries, with concrete types kept internal.

Core interfaces:

- `Stream` (duplex bytes, half-close, unblocking `close`).
- `PacketConn` (datagrams with source/destination, bounded queues).
- `Dialer` (connect to a target; optional packet dialer).
- `Inbound` (accept loop producing a `Connection` + `Metadata`).
- `Outbound` (dialer + capabilities + health state).
- `Router` (allocation-free `match(Metadata) -> Action`).
- `Resolver` and `Sniffer`.
- `Codec` functions with per-connection state, no I/O.

Contracts:

- No `anyerror` in interfaces; each method has a documented error set.
- Ownership is explicit: the connection arena owns metadata, codec state, and
  buffers; `close` never frees memory owned by a parent.
- `close` is idempotent and must unblock pending operations.
- Implementations must be safe for concurrent use unless documented otherwise.
- Public interfaces live in `src/root.zig`; implementations are not exported.

## Alternatives

1. **Tagged unions** (`Outbound = union(enum) { direct, ss, trojan, ... }`).
   Fast, no indirection, exhaustive switches. Rejected for the boundary because
   every new protocol edits central enums and transport composition becomes
   awkward; may still be used internally for small closed sets.
2. **Comptime generics** (monomorphized stacks). Best performance and type
   safety, but config-driven runtime choice would require combinatorial
   instantiation and huge binaries.
3. **Namespace/plugin ABI** (runtime shared libraries). Rejected for v1:
   safety, portability, and LGPL implications.

## Consequences

- One pointer indirection per relay operation; measure before optimizing.
- Interfaces are an internal ABI: changing a vtable is a breaking change.
- Tests can provide fake `Stream`/`PacketConn` implementations without sockets.
- Error-set design requires discipline; map I/O errors to stable library errors
  and keep diagnostics separate.
- Document that callbacks must not block or call back into the same connection.

## Approval

- [x] Accepted 2026-11-18 as recommended.
