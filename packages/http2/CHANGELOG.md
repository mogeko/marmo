# Changelog

## Unreleased

> Package version not bumped yet; the root release decides when this becomes
> a tagged package version.

### Added

- Connection multiplexing: a fixed 16-entry stream table, odd/even stream ids,
  OPEN/HALF_CLOSED/CLOSED transitions, per-stream DATA queues and header
  storage, and a frame pump shared by concurrent stream readers. `openStream`
  and `acceptStream` can now be called repeatedly.
- gRPC-enabling semantics: 1xx informational responses are accepted before the
  final response, a second HEADERS block is decoded as trailers, and
  `Stream.headers()`, `Stream.trailers()`, `Stream.informationalStatus()`, and
  `Stream.sendTrailers()` expose the three header blocks independently.
- `Stream.reset()` sends RST_STREAM for one stream; `Client.closeGracefully()`
  and `Server.closeGracefully()` send GOAWAY with `NO_ERROR`.
- `Stream.close()` keeps the existing half-close semantics; reads continue
  until the peer's END_STREAM.

### Changed

- Receive flow control is enforced. DATA beyond the stream or connection
  window sends GOAWAY with `FLOW_CONTROL_ERROR`; padding is credited when it is
  parsed and data is credited when the application consumes it.
- Strict header validation replaces the previous request-only checks: pseudo
  headers must be unique, ordered first, and known; field names must be
  lowercase tokens; connection-specific headers are rejected; `TE` may only be
  `trailers`; CONNECT omits `:scheme`/`:path`; trailers may not contain pseudo
  headers and must carry END_STREAM.
- Local protocol and stream-state errors now send GOAWAY or RST_STREAM.
  Receiving RST_STREAM aborts one stream, while a GOAWAY aborts only streams
  above its last-stream-id unless the error code is non-zero.
- SETTINGS are applied to every existing stream (INITIAL_WINDOW_SIZE deltas),
  the peer's MAX_FRAME_SIZE and MAX_CONCURRENT_STREAMS are enforced, and
  invalid or oversized ACK/settings payloads produce FRAME_SIZE_ERROR or
  PROTOCOL_ERROR GOAWAYs. `ENABLE_PUSH = 0` is accepted from hyper-h2 servers
  for interoperability; push is never enabled.
- `MAX_HEADER_LIST_SIZE` now advertises the real limit (8 KiB), and HPACK
  header-list accounting uses `name.len + value.len + 32` per field.
- HPACK integer decoding accumulates in 64 bits and rejects values above
  32 bits instead of overflowing `usize` on 32-bit targets.
- Frame, header, DATA, trailer, and HPACK buffers are zeroized on deinit and
  on stream abort/reuse.
- `write` pumps incoming frames while waiting for flow-control credit so a
  single-threaded embedder does not deadlock on WINDOW_UPDATE.

### Known limitations

- No server push, PRIORITY effects, HTTP/1.1 upgrade/h2c, connection pooling,
  HTTP/2 WebSocket, or gRPC message framing.
- HPACK encoding has no Huffman or dynamic-table insertion. Decoding supports
  both.
- The stream table and all queues are fixed inline storage (16 streams, 8 KiB
  per-stream window/header list); sizing is not configurable yet.
- No external audit. Tests: 36 package tests. Differential checks against
  Python h2/hpack and curl are local, not part of CI.

## 0.0.1 - 2026-11-19

- Initial HTTP/2 package: framing, HPACK with Huffman decoding, SETTINGS
  exchange, flow control, one-stream client/server, and bounded parsers.
