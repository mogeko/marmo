# WebSocket

> **Archived: Zig era.** These are notes for the in-tree `packages/ws`
> implementation, deleted under ADR-0018. The Rust target uses
> `tokio-tungstenite`; see [`../../architecture.md`](../../architecture.md) §13
> and the live index at [`../../protocols/README.md`](../../protocols/README.md).

Sources consulted: [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455) (The
WebSocket Protocol) and [RFC 7692](https://www.rfc-editor.org/rfc/rfc7692)
(Compression Extensions for WebSocket), plus Python `websockets` 17.4 and Node
`ws` 8.23 for negotiation behavior and loopback interop. Implemented in
`packages/ws` (ADR-0014); the root package provides `Stream`/`Dialer` adapters.

## Implemented scope

- Client opening handshake (`GET`, `Host`, `Upgrade`, `Connection`,
  `Sec-WebSocket-Key`, `Sec-WebSocket-Version: 13`) and a bounded 8 KiB
  response parser that verifies `Sec-WebSocket-Accept` with SHA-1.
- Server opening handshake with request-line/path validation, required headers,
  and key decoding.
- Subprotocol negotiation: the client offers `Sec-WebSocket-Protocol` from its
  options, the server selects the first configured protocol that the client
  offered, and both expose the selection. A non-empty server list rejects a
  request with no match; the client rejects a protocol it did not offer.
  Duplicate protocol headers, duplicate tokens within one offer, and non-token
  values are rejected.
- `permessage-deflate` (RFC 7692) negotiation of
  `server_no_context_takeover`, `client_no_context_takeover`,
  `server_max_window_bits`, and `client_max_window_bits`. Unknown parameters,
  duplicate parameters, values outside 8..15, leading-zero values, malformed
  extension headers (even for disabled extensions), and extensions the client
  did not offer are rejected. The server declines offers it cannot accept and never
  echoes an unrequested extension.
- RFC 6455 frames: FIN/opcode/mask, 7/16/64-bit lengths, client masking,
  binary/text, continuation, ping/pong, and close. Control frames must be
  final, at most 125 bytes, and never carry RSV1. Reads accept a single frame
  up to the 1 MiB message limit (the connection buffers it); writes fragment at
  64 KiB so peers with smaller limits stay compatible.
- Compressed messages: RSV1 marks only the first data frame; a continuation
  with RSV1 is a protocol error. Message fragments are accumulated up to
  `max_compressed_message` (1 MiB plus one eighth plus the flush header), then
  inflated with a 1 MiB output bound. Context takeover reuses one raw-DEFLATE
  stream and a 32 KiB history; `no_context_takeover` reinitializes both sides
  per message. Compressed input is decoded with `std.compress.flate` after
  appending the RFC 7692 `00 00 ff ff` suffix.
- Encoding is an in-package raw-DEFLATE encoder (fixed-Huffman blocks, LZ77,
  hash heads, RFC 7692 sync flush). `std.compress.flate.Compress` is not used
  because its writer flush does not produce the zlib-compatible sync-flush
  marker and its output is rejected by strict inflaters. The encoder honors the
  negotiated window bits (8..15) as a maximum match distance.
- Text messages are validated incrementally across fragments, including a
  multi-byte sequence split between frames. Invalid UTF-8 closes with 1007.
  Writes remain binary. Inflated messages that set BFINAL are rejected rather
  than silently truncated.
- Close handling echoes valid close frames (including 1001/1008/3000), answers
  invalid codes with 1002, invalid UTF-8 with 1007, and oversized
  frames/messages with 1009. Invalid
  compressed data is a protocol error (1002). `closeWithCode` sends
  application policy codes such as 1008.
- A reader detecting a protocol error never blocks on the writer lock: it
  queues the close code and attempts a non-blocking send; a concurrent writer
  flushes the close at its next frame boundary. Pings are answered by a
  bounded queue drained by the writer when the lock is busy. No data or pong
  follows a close.
- Message, fragment, per-read control, and per-read frame limits are bounded
  (1 MiB, 1024, 1024, and 4096); hits are treated as protocol violations.
  Each connection reserves a 1 MiB frame buffer and a 1.125 MiB compressed
  message accumulator. Non-minimal length encodings are rejected.

## Known gaps

- VLESS wires `path`, `host`, `compression`, and `subprotocols` through its
  `transport` object (ADR-0016). The inbound enforces `path` but not `host`;
  Host checking is outbound-only for now. Close codes and the full
  `DeflateOptions` surface remain package-only. Trojan-Go WebSocket is not
  implemented.
- The adapter's handshake timer now uses a running/done/fired state so a late
  timer cannot abort a completed connection; `Instance` disables the timer and
  lets the ADR-0015 reaper own the deadline.
- No redirects, HTTP proxy authentication, Origin checks, or HTTP/2 WebSocket
  (RFC 8441).
- The encoder is intentionally simple: fixed Huffman only and one hash entry
  per three-byte sequence. Dynamic Huffman, lazy matching, a compression
  threshold, and a stored-block fallback for incompressible data are later
  optimizations.
- The read frame buffer and compressed-message accumulator are reserved before
  the handshake. Lazy or pooled allocation is a later optimization; the current
  API takes no allocator.
- Server handshakes default to no internal timer so that inbound servers use
  the ADR-0015 reaper. Standalone embedders that need a self-contained deadline
  set `handshake_timeout_ns` on the root adapter (one sleeping task per
  handshake).
- No external audit. The package has deterministic hostile-input tests plus
  `ws_deflate` and `ws_connection_deflate` fuzz targets.

## Interop evidence

Loopback-only differential runs (not part of the repository test suite) covered
Python `websockets` 17.4 and Node `ws` 8.23 as both peer roles, with compression
on/off, context takeover, `no_context_takeover`, subprotocol selection, 100 KB
binary messages, and 10 KB text/binary messages. All echoes matched.

## Fuzz targets

`ws_frame` reads arbitrary frame bytes as a server (masked input required),
`ws_handshake` parses a bounded HTTP head, and `ws_connection` drives the
connection reader. They run in the deterministic corpus smoke and in
`zig build fuzz`.
