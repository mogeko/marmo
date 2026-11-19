# ADR-0013: HTTP/2 transport as a first-party package

- Status: Accepted (2026-11-19, on direct implementation request)
- Date: 2026-11-19
- Deciders: @mogeko
- Related: ADR-0004, ADR-0007, ADR-0010, ADR-0012

## Context

VLESS and VMess can run over HTTP/2, and HTTP/2 is also the transport under
gRPC. `std` has no HTTP/2 implementation. The transport needs framing, HPACK,
SETTINGS negotiation, flow control, and stream lifecycle, but not a general
HTTP client or a caching server.

Embedding the protocol in the root package would repeat the TLS coupling that
ADR-0010 removed: the parser and state machine should be testable with only
`std`, on `std.Io.Reader`/`Writer`, without marmo's `Stream` types.

## Decision

Add `packages/http2/` as a std-only first-party package with its own build,
following ADR-0010. It implements the HTTP/2 transport subset:

- connection preface, SETTINGS and SETTINGS ACK, PING/ACK, GOAWAY, RST_STREAM,
  WINDOW_UPDATE, and unknown-frame ignoring as required by RFC 9113;
- HEADERS + CONTINUATION with a bounded HPACK decoder (static table, dynamic
  table, Huffman decoding) and a simple encoder (static indices and literals,
  no Huffman);
- DATA on one active stream per connection; endpoints advertise
  `MAX_CONCURRENT_STREAMS = 1`, so callers get a multiplexing-free tunnel and
  do not need a demultiplexer;
- bounded frames (16 KiB default maximum frame size), header lists (64 KiB),
  dynamic table (4 KiB), and stream data windows (64 KiB, replenished as data
  is consumed);
- a client role that opens one request stream and a server role that accepts
  one request stream, both exposing a duplex byte stream.

The package exposes `Client.init`, `Client.openStream(headers)`,
`Server.init`, `Server.acceptStream()`, `Stream.read/write/close`, and the
frame/HPACK modules for fuzzing. Root adapters in `src/transport/h2_*.zig`
wrap marmo's `Stream` and require ALPN `h2`.

## Alternatives

1. **Put HTTP/2 in `src/transport`.** Simpler imports, but couples framing to
   marmo types and makes independent testing harder. Rejected for consistency
   with ADR-0010.
2. **Implement full HTTP/2 multiplexing and a general API.** Much larger state
   machine (per-stream queues, priority, server push) than the transports need.
   Rejected for Phase 2.
3. **Only encode/decode frames, no connection state.** Leaves SETTINGS, flow
   control, and stream lifecycle to every caller. Rejected: duplicated and
   error-prone.
4. **Depend on an external HTTP/2 library.** Violates std-only and zero
   dependencies. Rejected.

## Consequences

- Positive: HPACK and frame parsing are fuzzable without sockets; TLS is the
  only layer that knows about ALPN; gRPC can build on the same framing.
- Negative: one stream per connection is less efficient than multiplexing and
  does not match VLESS/VMess H2 deployments that share a connection. This is
  recorded as a follow-up, not hidden. No server push or PRIORITY handling.
- Tested by HPACK known-answer vectors, frame truncation/overflow tests, an
  in-tree client/server loopback exchange over `std.testing.Reader`/`Writer`,
  and TLS ALPN integration. Malformed input returns typed errors.
