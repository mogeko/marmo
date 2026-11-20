# HTTP/2

> **Archived: Zig era.** These are notes for the in-tree `packages/http2`
> implementation, deleted under ADR-0018. The Rust target uses `h2`; see
> [`../../architecture.md`](../../architecture.md) §13 and the live index at
> [`../../protocols/README.md`](../../protocols/README.md).

Sources consult: [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113) (HTTP/2),
[RFC 7541](https://www.rfc-editor.org/rfc/rfc7541) (HPACK), RFC 8441 (extended
CONNECT, not implemented). Implemented in `packages/http2` (ADR-0013); the root
package provides `Stream`/`Dialer` adapters. Reference behavior was checked
locally against Python `h2` 4.4.1, Python `hpack` 4.2.0, and curl 8.7.1
(nghttp2 1.69.0); no live third-party servers are used.

## Implemented scope

- Connection preface, SETTINGS and SETTINGS ACK, PING/ACK, GOAWAY,
  RST_STREAM, WINDOW_UPDATE, PRIORITY (ignored), CONTINUATION, and
  unknown-frame ignoring.
- Frames are capped at 16 KiB; stream ids and reserved bits are validated.
- HPACK decoding with the static table, a 4 KiB dynamic table, integer
  decoding bounded to 32 bits, and RFC 7541 Appendix B Huffman decoding.
  Encoding uses static indices and literals without Huffman or dynamic-table
  insertion. Header lists are accounted per RFC 9113 as
  `name.len + value.len + 32`; `MAX_HEADER_LIST_SIZE = 8 KiB` is advertised and
  enforced.
- Multiplexing over a fixed 16-stream table: odd/even stream ids,
  OPEN/HALF_CLOSED_LOCAL/HALF_CLOSED_REMOTE/CLOSED state, per-stream DATA
  queues and header/trailer storage, and a frame pump that demultiplexes
  frames for concurrent readers and writers.
- Flow control in both directions. The initial stream receive window is 8 KiB
  and the connection window is 128 KiB. WINDOW_UPDATE is sent as DATA is
  consumed; padding is credited when the frame is parsed. DATA discarded on a
  closed stream, or queued DATA dropped by reset/abort/GOAWAY, is credited back
  to the connection window. A connection-level violation sends GOAWAY with
  `FLOW_CONTROL_ERROR`; stream-level violations send RST_STREAM.
- Field blocks on closed/refused streams are fully decompressed before being
  discarded so the connection-level HPACK state stays aligned. A block beyond
  the header-list/storage bound closes the connection with COMPRESSION_ERROR
  rather than continuing with a half-updated decoder. Up to 256 fields are
  accepted within the 8 KiB accounting limit.
- Strict header validation: pseudo headers must precede regular fields, be
  unique, known, and lowercase; field names are token-checked; values reject
  CR/LF/NUL/controls and leading/trailing whitespace; connection-specific
  headers are rejected; `TE` may only be `trailers`; CONNECT omits
  `:scheme`/`:path` and requires `:authority` (or `Host`); `:status` is a
  three-digit 100-599 value.
- gRPC-enabling semantics: 1xx informational responses are accepted before the
  final response, a second HEADERS block is decoded as trailers with
  END_STREAM, and separate accessors expose initial headers, trailers, and the
  last 1xx status. Sending 1xx from the server is not implemented yet.
- GOAWAY/RST_STREAM behavior: local connection errors send GOAWAY with the
  matching code and cancel the connection; stream errors send RST_STREAM and
  leave other streams usable. Graceful close sends GOAWAY with `NO_ERROR` and
  stops new streams.
- Buffers (frames, raw header blocks, per-stream DATA/header/trailer storage)
  and the HPACK table are zeroized on deinit and on stream abort/reuse.

## Test evidence

Package tests cover multi-stream interleaving, trailers/1xx, per-stream flow
control, RST/GOAWAY state transitions, SETTINGS deltas and limits, strict
header validation, and a bounded stateful frame-pump smoke test. A local
differential harness generated 24 HPACK block sets with Python `hpack` 4.2.0
(Huffman and non-Huffman, dynamic-table reuse, long values) and decoded them
with this package. A Python `h2` 4.4.1 client exercised two concurrent streams
against `Server`; the Python server exercised `Client` with 1xx, final
headers, bodies, and trailers. curl 8.7.1 (nghttp2 1.69.0) fetched a response
from `Server` with `--http2-prior-knowledge`. The harness is not committed.

## Known gaps

- No server push (and no PUSH_PROMISE support), PRIORITY effects, HTTP/1.1
  upgrade/h2c, connection pooling, or HTTP/2 WebSocket.
- No general request router, caching, or response-body framing beyond DATA.
- gRPC message framing is application-level and out of scope.
- VLESS outbound/inbound can select `transport.network = "h2"` (ADR-0016),
  with TLS ALPN `h2` and a configured path/host (the inbound enforces `path`,
  not `host`). `Instance` currently serves
  one VLESS stream per H2 connection, so the package's 16-stream multiplexer
  and connection pooling are not yet used by the root library. VMess and gRPC
  remain unimplemented.
- The server cannot send 1xx responses. The fixed 8 KiB per-stream receive
  window is a throughput trade-off for high-RTT single-stream use.
- A blocked writer pumps frames itself; with many streams and an application
  that never reads, flow control eventually stalls that stream by design.
- The adapter handshake timer uses a running/done/fired state so a late timer
  cannot abort a completed connection; `Instance` disables it and relies on
  the ADR-0015 reaper.
- No external audit. Parser fuzz targets remain `http2_frame` and
  `http2_hpack`; the connection state machine is covered by unit tests and a
  deterministic stateful pump test.
