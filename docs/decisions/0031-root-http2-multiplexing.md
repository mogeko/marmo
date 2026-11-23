# ADR-0031: Root-level HTTP/2 multiplexing and pooling

- Status: Accepted (2026-11-23)
- Date: 2026-11-23
- Deciders: @mogeko
- Related: ADR-0013, ADR-0015, ADR-0016, ADR-0022, ADR-0027

## Context

HTTP/2 is currently a `Layer`. `Layer::wrap` receives a stream that has already
been dialed through TCP and TLS, so `H2Client::connect` performs a fresh HTTP/2
handshake for every logical connection and opens exactly one `PUT` stream. The
inbound mirror accepts the first stream and drops every later stream on the
same connection. `Instance` therefore pays one TCP + TLS + HTTP/2 handshake per
proxied connection, and the server advertises 16 concurrent streams but serves
one.

This is the concrete gap recorded by ADR-0016 (deferred inbound lifecycle,
per-stream guards, and metrics), ADR-0027 (deferred root-level H2 pooling), and
roadmap item P2-12. Reference peers such as V2Ray 5.53 and Xray 1.8.24 expect an
HTTP/2 connection to carry multiple request streams; a one-stream adapter is
correct only because it never reuses a connection.

The `Layer` boundary cannot fix this by itself: it has no access to the base
connect path, so it cannot keep a connection alive between calls. Pooling must
move to the root outbound and inbound composition, while the `h2` crate keeps
owning framing, HPACK, flow control, and stream lifecycle.

## Decision (recommended)

Move HTTP/2 out of the `Layer` stack and make it a root connection manager for
VLESS and VMess, in both directions. Keep the wire behavior of ADR-0016 and
ADR-0022 unchanged: client `PUT`, no content type, server accepts `PUT` and
`POST`, path enforced, ALPN `h2` required, TLS required.

### Transport adapters

Add connection-level types in `marmo-transport`:

- `H2ClientConnection` performs the HTTP/2 handshake once over an already
  dialed stream and exposes `open_stream() -> BoxStream`; each call sends one
  request and waits for the `200` response head.
- `H2ServerConnection` drives one server connection and exposes
  `accept_stream()`; each accepted request is validated independently, answered
  with `200`, and bridged to a `BoxStream`. An invalid method or path resets
  only that stream with `400`, not the whole connection.
- Each bridged stream owns only its duplex pipe, pump task, and h2 stream
  handles. Dropping a stream resets that stream; it never aborts or shuts down
  the shared connection.
- The connection object owns the connection task and cancels it on drop.
- `H2Client::connect` and `H2Server::accept` remain as one-shot convenience
  methods for standalone callers and tests. Their `impl Layer` blocks are
  removed so config wiring cannot accidentally compose a one-stream HTTP/2
  layer again.

Fixed limits stay in the adapter: 16 KiB frames, 8 KiB header lists, and 16
concurrent server streams. The server advertises the same 16-stream limit.

### Outbound pool

Split the pool by responsibility so a later QUIC adapter does not live inside
the HTTP/2 module:

- `crates/marmo/src/outbound/stream_pool.rs` holds the transport-agnostic
  `StreamPool<C>`: connection slots, stream and connection permits, selection,
  retry, pruning, and the supervisor. It knows only a connection type that can
  open a `BoxStream`.
- `crates/marmo/src/outbound/h2.rs` holds the HTTP/2 connection factory, the
  base TCP/TLS dial, and the `StreamPool<H2ClientConnection>` instantiation.
- A future QUIC adapter adds `outbound/quic.rs` with its own connection
  factory and reuses `StreamPool`; QUIC code is not added to `h2.rs`.

Add one `StreamPool<H2ClientConnection>` per VLESS/VMess outbound node that
uses `transport.network = "h2"`, started through `Outbound::start` and owned by
the instance cancellation tree.

- Fixed bounds: 4 physical HTTP/2 connections per outbound, 16 concurrent
  streams per connection, 64 in-flight streams per pool.
- Pool acquisition is bounded: `open()` waits on a permit, cancellable by the
  connection's handshake deadline, instead of failing immediately. It selects a
  connection with a free stream slot and dials a new connection only while
  below 4.
- A connection error or `GOAWAY` prunes that connection and fails only its
  active streams. The next `open()` replaces it; one retry is allowed when a
  selected connection fails before a stream is established.
- No idle-close timer in this change. A pool holds at most 4 connections per
  outbound and closes them on instance shutdown or peer close.
- `mux: true` remains valid over HTTP/2. The mux pool opens each physical mux
  connection as one HTTP/2 stream, so the two bounds nest rather than
  conflict.

### Inbound streams

An HTTP/2 inbound connection is one accepted TCP connection and up to 16
logical VLESS/VMess connections.

- TLS is terminated once per TCP connection; the H2 connection manager accepts
  all streams.
- Each stream gets its own `Connection` handler, source endpoint, handshake
  deadline, sniffing buffer, routing decision, relay, and cancellation branch.
- `max_connections` continues to count accepted TCP connections, as in
  ADR-0015. A separate per-instance stream budget of `max_connections` permits
  bounds concurrent HTTP/2 streams. When it is exhausted, the stream is reset
  and counted as rejected; the TCP connection stays open.
- The TCP connection holds its normal admission permit for its lifetime, so
  idle HTTP/2 connections remain bounded.
- The handler closes all its stream tasks through a connection-owned `JoinSet`
  when the TCP connection ends, the instance shuts down, or the stream count
  is exhausted.

### Configuration and errors

No new configuration fields. `transport.network = "h2"` keeps the same meaning,
and h2 still requires TLS with ALPN containing `h2`. Typed errors gain a closed
connection/capacity variant in `H2Error`; no error is converted into a panic.

## Alternatives

1. **Keep the `Layer` and add a global connection registry keyed by server,
   path, and TLS settings.** The registry still needs a different dial path
   because the base TCP/TLS stream is already open before `wrap` runs. It hides
   a second composition model and leaks connection ownership across layers.
   Rejected.
2. **One unbounded HTTP/2 connection per outbound.** Simple, but ignores the
   peer stream limit and gives one slow peer a connection-wide stall with no
   admission bound. Rejected.
3. **Use the same `max_connections` semaphore for both TCP connections and
   HTTP/2 streams.** A single HTTP/2 connection holds the only permit at
   `max_connections = 1`, so no stream can be admitted. Splitting the budgets
   keeps both bounds meaningful. Rejected.
4. **Fail fast when the pool is full instead of waiting.** Turns normal
   multiplexing pressure into connection failures. Waiting under the existing
   handshake deadline is bounded and matches the rest of the dial path.
   Rejected.
5. **Reuse the Mux.Cool pool for HTTP/2.** Mux.Cool is a byte-stream
   multiplexer with its own session table; HTTP/2 already multiplexes. Stacking
   two session layers would duplicate bounds and backpressure. Rejected.
6. **Add configurable connection/stream limits now.** ADR-0027 already chose
   fixed bounds without evidence for tuning. Keep that policy until an embedder
   needs a knob. Rejected.
7. **Keep one stream per HTTP/2 connection.** Does not close P2-12 and does not
   match reference peers. Rejected.

## Consequences

Positive:

- Multiple VLESS/VMess TCP, UoT, XUDP, and mux streams share one TLS + HTTP/2
  connection per outbound.
- The inbound serves every stream the client opens, so a single HTTP/2
  connection is no longer limited to one relay.
- Connection and stream counts are fixed and observable; no unbounded queue or
  task set is introduced.
- Wire format and ALPN behavior do not change.

Negative:

- One connection error or `GOAWAY` fails every active stream on that
  connection.
- HTTP/2 connection-level flow control can still cause head-of-line stalls
  across streams; per-stream windows are separate but the connection window is
  shared.
- `max_connections` alone no longer describes the total logical connection
  count; the separate stream budget must be documented.
- The inbound handler signatures change from `TcpStream` to a stream plus a
  source endpoint, and the VLESS/VMess handlers gain per-stream deadlines.
- A pool of 4 connections and 16 streams each multiplies per-connection
  buffers by up to 16; the stream budget is the guard.

Tests and observation:

- Transport unit tests: two or more concurrent streams over one connection,
  independent stream close, wrong-path reset without connection loss,
  connection close failing all streams, and a large message per stream.
- Pool unit tests: connection reuse, 4-connection and 16-stream caps, bounded
  wait, dead-connection replacement, and cancellation.
- Integration: several concurrent SOCKS5 connections through VLESS/VMess over
  HTTP/2; the proxy inbound reports one accepted TCP connection while every
  stream relays. TCP and UoT/XUDP keep passing. The same checks for `mux: true`
  over HTTP/2.
- Shutdown: cancelling the instance closes all streams and reaps pool and
  inbound tasks within the grace period.
- Reference interop outside CI: concurrent streams against V2Ray 5.53 and Xray
  1.8.24 in both directions.
- Docs updated: `architecture.md` §4.1, §8.3, §9, §12, §16,
  `protocols/vless.md`, `protocols/vmess.md`, `roadmap.md`, `CHANGELOG.md`, and
  the security audit's resource-bound note.

Follow-up work: idle-close for unused HTTP/2 connections, configurable pool
bounds, and per-stream HTTP/2 metrics if the existing counters are not enough.

## Approval

- [x] Accept the recommendation (root H2 connection managers, fixed 4/16/64
      outbound bounds, per-instance inbound stream budget, no config change).
- [ ] Accept with different fixed bounds: connections ___ , streams per
      connection ___ , inbound stream budget ___ .
- [ ] Choose an alternative: ...
