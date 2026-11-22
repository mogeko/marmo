# ADR-0027: Client-side Mux.Cool outbound

- Status: Accepted (2026-11-22)
- Date: 2026-11-22
- Deciders: @mogeko
- Related: ADR-0015, ADR-0016, ADR-0025, ADR-0026

## Context

VMess and VLESS inbounds now terminate full Mux.Cool (TCP and UDP, multiple
sessions) on one physical connection. Their outbounds still dial once per TCP
stream and once per UDP target, so a workload with many short connections pays
a TCP/TLS/WebSocket/HTTP2 handshake each time. `xudp` covers only a
single-target UDP subset, and the roadmap defers client-side pooling as P5-11
(VMess) and P5-13 (VLESS).

Mux.Cool has no per-stream flow control: one slow consumer can stall the whole
physical connection. The client therefore needs bounded queues, an explicit
backpressure policy, a session-id lifetime rule, and owned background tasks
that the instance can cancel.

`Instance` currently starts outbound background work through
`Outbound::start_health(runtime, token)`; outbound connections themselves are
per-operation. A mux pool needs the runtime and the instance cancellation
token before the first `connect`.

## Decision (recommended)

Add one shared client-side Mux.Cool pool used by VMess and VLESS outbounds when
`mux` is enabled.

### Configuration

- Add `mux: bool` to VMess and VLESS outbounds; default `false`.
- `mux` and `xudp` are mutually exclusive on VLESS. `xudp` keeps its
  single-target UDP subset; `mux` carries TCP and UDP sessions, including
  per-datagram UDP targets.
- Fixed bounds, not configuration: 4 physical connections per outbound, 128
  sessions per connection, 16 queued frames per session, a 4 MiB
  connection-wide queued-byte cap, a 32 KiB TCP pipe, 64 KiB frame data, a
  15 s keep-alive interval, and a 30 s idle close.
- No new dependency.

### Client core

Add `outbound/mux.rs` with a protocol-neutral pool:

- `MuxPool` owns up to four `MuxConnection`s and enforces the connection cap.
- `MuxConnection` owns one read driver, one serialized writer, and a bounded
  session table. The driver reads `MuxReader` frames and dispatches data; the
  writer serializes New/Keep/End/KeepAlive.
- Session ids are nonzero, monotonic, and never reused. When the id space is
  exhausted the connection stops accepting new sessions and is replaced.
- A TCP session is a `tokio::io::duplex` pair plus one task. Downlink is
  backpressured by a bounded queue, so a slow reader pauses the physical read
  (head-of-line blocking is accepted and documented). An uplink or remote End
  closes the session.
- A UDP session is a bounded datagram queue. `send_to` writes a targeted Keep
  when the destination changes, so a SOCKS5 association can switch targets.
  Replies carry the source target; a full queue drops the datagram.
- A connection-wide queued-byte cap closes the offending session rather than
  letting 128 slow sessions accumulate a bounded but large amount of data.
- Idle connections send KeepAlive and close after the idle bound; the pool
  prunes closed entries when opening a session.
- On physical EOF or error, every session is closed and the pool reconnects on
  the next `connect`.

### Protocol integration

Each protocol provides a `dial_mux` that opens the physical stream and returns
a `BoxStream` after the mux request:

- VLESS: command `3`, no address, read the two-byte response header.
- VMess: command `3` with the synthetic target, boxed `ChunkStream`; the
  response header is read lazily by the first frame read.

### Lifecycle

Add `Outbound::start(runtime, token)` with a default no-op. `BoundInstance`
calls it for every outbound before accepting; selectors propagate to their
nodes. The mux outbound stores the runtime and a child token, and owns every
driver/writer/session task through a `JoinSet` or `TaskTracker`. Shutdown
cancels the token, which closes physical connections and reaps tasks.

### xudp

Port the VLESS `xudp` outbound to the shared mux codec (session `0`, UDP, one
fixed target, eight-byte GlobalID) and delete the duplicate implementation:
`marmo/src/xudp.rs`, `marmo-proto/src/xudp.rs`, the `xudp` fuzz target, and its
corpus. The `xudp: true` configuration mode remains; it becomes a strict subset
of the mux codec, with session/network checks and the fixed-target rule in the
outbound. There is no API-stability promise, so no deprecation facade is kept;
the CHANGELOG records the removal.

The port does not depend on the pool and can land first. Keeping a second
framing implementation risks drift in the mask/data-length/End rules; a strict
subset check at the call site preserves the safety property without duplicating
the codec.

### Out of scope

- XUDP GlobalID/cone NAT and their per-packet semantics (roadmap P5-5).
- Dynamic ports, alterId, legacy VMess, and client-side config knobs beyond
  `mux`.
- Root-level HTTP/2 pooling (P2-12); mux reuses the existing one-stream-per-H2
  adapter.

## Alternatives

1. **One mux connection per logical stream.** No reuse, so no benefit over the
   current outbound. Rejected.
2. **Separate VMess and VLESS pools.** Duplicates session tables, driver
   cancellation, and bounds. Rejected.
3. **Unbounded queues or connections.** Violates the bounded-state rule and lets
   one peer exhaust memory. Rejected.
4. **Make every outbound mux by default.** Breaks peers and changes existing
   behavior without opt-in. Rejected.
5. **Add per-connection tuning now.** Premature; fixed bounds keep the config
   strict and can be exposed later with evidence. Rejected.
6. **Keep the xudp codecs as a parallel strict implementation.** A smaller
   parser is easier to audit, but it duplicates the mask, data-length, End, and
   GlobalID rules and can drift from the shared codec. The strictness is a few
   checks in the `xudp` mode, not a second parser. Rejected.
7. **Delete the `xudp` configuration mode as well.** Removes a compatibility
   behavior that peers still use; the mode is a subset of `mux`, not the codec.
   Rejected until a later product decision.

## Consequences

- `mux: true` carries many TCP and UDP sessions over a bounded pool; `xudp`
  remains a compatibility subset.
- New `Outbound::start` lifecycle work and a background task owner; selectors
  and `BoundInstance` change.
- TCP sessions are subject to mux head-of-line blocking; UDP drops under queue
  pressure. Both are documented and bounded.
- Tests: pool/session unit tests, loopback TCP/UDP/mixed sessions, connection
  cap and id exhaustion, cancellation, TLS/WS/H2, and Xray interop for our mux
  outbound against both protocols.
- P5-11 and P5-13 are closed; P5-5 remains deferred. The duplicate `xudp`
  codecs, fuzz target, and corpus are removed once the outbound is ported.
  Estimated 9-12 days (the `xudp` port can be a smaller standalone change).

## Approval

- [x] Accept the recommendation (shared mux pool, `mux: true`, fixed bounds).
- [ ] Accept with per-connection tuning exposed in config: ...
- [ ] Choose an alternative: ...
