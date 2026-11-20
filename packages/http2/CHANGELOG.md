# Changelog

## Unreleased

> Package version not bumped yet; the root release decides when this becomes
> a tagged package version.

### Security

- The server sends its own SETTINGS before ACKING the client, does not wait
  for the client ACK before accepting HEADERS, and accepts legal server
  `ENABLE_PUSH = 0`.
- A local `END_STREAM` no longer closes the TCP write side, so WINDOW_UPDATE
  and other control frames can still be sent after a half-close.
- Truncated frames/EOF map to `ConnectionReset` and wake blocked writers;
  request pseudo-headers, configured paths, header names, and the first
  response `:status` are validated; header-list and HPACK size-update limits
  are enforced.
- DATA padding is stripped and validated, a second HEADERS block (trailers) is
  rejected instead of overwriting the request/response headers, and a failed
  WINDOW_UPDATE write no longer discards already received DATA.
- A writer waiting for flow control pumps control frames after the peer
  half-closes, so `WINDOW_UPDATE`/PING/RST are still processed when no read
  task remains.

### Changed

- Added `Stream.cancel()` and internal cancellation/wakeup state so an aborted
  connection unblocks writers.
- `Server.acceptStream()` marks the first HEADERS block as seen.
- `MAX_HEADER_LIST_SIZE` is advertised and large single header values are
  accepted up to the implementation limit.

### Known limitations

- One active stream per connection; no multiplexing, connection reuse, server
  push, PRIORITY effects, or HTTP/1.1 upgrade.
- No gRPC: 1xx responses and trailers are rejected; no CONNECT or extended
  CONNECT; no WebSocket over HTTP/2.
- HPACK encoding has no Huffman or dynamic-table insertion. Decoding caps
  header count and value size below the advertised 64 KiB list.
- Receive flow control is not enforced, updates are sent on receipt rather
  than consumption, and a failed update disables further updates.
- Data and control frames share one write lock; large writes can delay PING
  ACKs and WINDOW_UPDATE. GOAWAY/RST_STREAM are not sent on local errors.
- No external audit. Tests: 23 package tests.

## 0.0.1 - 2026-11-19

- Initial HTTP/2 package: framing, HPACK with Huffman decoding, SETTINGS
  exchange, flow control, one-stream client/server, and bounded parsers.
