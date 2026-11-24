# ADR-0033: Datagram boundary for UDP outbounds

- Status: Proposed
- Date: 2026-11-24
- Deciders: @mogeko
- Related: ADR-0004, ADR-0017, ADR-0027, ADR-0031

## Context

`Outbound::connect_datagram` currently returns the concrete
`UdpOutbound` enum (`crates/marmo/src/outbound/udp.rs`). That enum contains
every datagram implementation: direct, Shadowsocks, Trojan, VLESS, VLESS XUDP,
VMess, and Mux.Cool. Its `send_to` and `recv_from` methods are exhaustive
matches over the enum.

This has three costs:

1. A new datagram transport, such as the QUIC adapter planned for P3-1/P3-2,
   must add an enum variant and edit every match, even though the inbound and
   routing layers only need send/receive behavior.
2. The direct implementation has protocol-policy code (bounded destination
   allowlist and unknown-source rejection) mixed into the enum dispatch rather
   than living behind a clear datagram boundary.
3. The current `recv_from` returns `io::Result`. "All received packets came from
   unknown sources" is not an I/O error and must not close a UDP association.

`docs/architecture.md` §8.2 already describes a `Datagram` trait as the intended
boundary, but the tree has never implemented it.

## Decision (recommended)

Introduce an internal, object-safe `Datagram` boundary and remove the
`UdpOutbound` enum.

```rust
pub(crate) trait Datagram: Send {
    fn send_to<'a>(
        &'a mut self,
        target: &'a Endpoint,
        payload: &'a [u8],
    ) -> BoxFuture<'a, Result<(), DatagramError>>;

    fn recv_from<'a>(
        &'a mut self,
        buffer: &'a mut [u8],
    ) -> BoxFuture<'a, Result<(usize, Endpoint), DatagramError>>;

    fn max_datagram_size(&self) -> usize;
}

pub(crate) type BoxDatagram = Box<dyn Datagram>;

#[derive(Debug, Error)]
pub(crate) enum DatagramError {
    #[error(transparent)]
    Io(#[from] io::Error),

    /// Every received packet came from a source this association has not
    /// contacted. This is not an association-fatal condition.
    #[error("no valid datagram reply")]
    NoReply,
}
```

Rules:

- `Datagram` is object-safe and uses the existing `BoxFuture` alias; no
  `async-trait` dependency is added.
- `send_to` and `recv_from` take `&mut self`; a datagram association owns its
  socket, target set, counters, and queues. `Sync` is not required.
- `max_datagram_size` is at most `65_535`; implementations may return a smaller
  protocol-specific limit. The library never fragments.
- `DatagramError::NoReply` is a non-fatal retry signal. Callers continue
  waiting or drop the current datagram; they do not close the association.
- `Outbound::connect_datagram` returns
  `BoxFuture<'a, io::Result<Option<BoxDatagram>>>`. The outer `io::Result` still
  covers setup failures; `DatagramError` covers per-datagram operations.
- Existing bounds remain inside each implementation: bounded target sets,
  bounded queues, bounded frame sizes, and the same idle/cancellation owners.
- No wire format, configuration field, or public dependency changes.

### Direct datagram policy

`DirectDatagram` retains the current security behavior:

- a bounded set of destinations the association has sent to (currently 128);
- replies from unknown sources are ignored;
- after a bounded number of unknown packets it returns
  `DatagramError::NoReply` instead of an I/O error.

Inbound UDP reply loops treat `NoReply` as "keep waiting", not as a reason to
terminate the association.

### Migration

1. Add `outbound/datagram.rs` with the trait, box type, and error.
2. Implement `Datagram` for each existing protocol adapter. Move direct
   destination tracking into `DirectDatagram`.
3. Change `Outbound::connect_datagram` to return `Option<BoxDatagram>`.
4. Change `Context::udp_outbound` and every inbound UDP handler to receive
   `&mut dyn Datagram`.
5. Delete the `UdpOutbound` enum and the exhaustive dispatch matches.
6. Add `NoReply` tests that prove the association remains alive.

## Alternatives

1. **Keep the `UdpOutbound` enum.** It is simple today but makes every future
   datagram transport edit a central enum and all dispatch sites. Rejected for
   P3-1.
2. **Make the trait public.** Embedders do not currently provide datagram
   outbounds; making it public adds a semver surface and a contract the library
   cannot fully validate. Keep it crate-private until a concrete embedder use
   case exists.
3. **Use `&self` plus internal `Mutex`.** It would hide mutability from callers
   but adds lock contention to every datagram and makes cancellation/ownership
   less obvious. Rejected.
4. **Use `async-trait`.** It would simplify signatures but adds a dependency and
   per-call boxing similar to `BoxFuture`. The existing boundary already uses
   `BoxFuture`; no new dependency is justified.
5. **Return `Option` from `recv_from` for `NoReply`.** `None` already means a
   clean close in stream APIs; using it for "no matching reply yet" would
   conflate two states. Rejected.
6. **Return `io::ErrorKind::WouldBlock` for `NoReply`.** It loses the distinction
   between a transient policy result and a syscall/backpressure error. Rejected.

## Consequences

Positive:

- A QUIC/TUIC/Hysteria2 datagram adapter implements one trait and does not edit
  existing protocol matches.
- The direct UDP source policy lives in one place and `NoReply` is semantically
  explicit.
- `BoxDatagram` mirrors the existing `BoxStream` boundary.
- Existing queue and memory bounds can be preserved per implementation.

Negative:

- One virtual call per `send_to`/`recv_from` operation; the datagram hot path is
  already asynchronous and allocates protocol frames, so this is acceptable.
- The trait uses `&mut self`; shared datagram handles are not supported.
- Moving direct policy into `DirectDatagram` requires tests for target-set
  bounds and `NoReply`.
- The migration touches every UDP inbound and outbound and must be done as one
  reviewed boundary.

Tests and observation:

- Unit tests for `DirectDatagram`: valid reply accepted, unknown source
  ignored, bounded target set, `NoReply` returned after the attempt limit.
- Integration tests for SOCKS5 UDP, Shadowsocks UDP, Trojan UDP, VLESS UoT,
  VLESS XUDP, VMess UDP, and Mux UDP.
- A test that `NoReply` does not close a SOCKS5/Trojan/VLESS/VMess association.
- Fuzz/build checks remain unchanged; no new decoder is added.

## Approval

- [ ] Accept the recommendation (`Datagram`, `BoxDatagram`,
  `DatagramError::NoReply`, remove `UdpOutbound`).
- [ ] Keep the `UdpOutbound` enum and defer this to P3-1.
- [ ] Make the trait public.
- [ ] Choose a different error model: ...
- [ ] Reject this boundary change.
