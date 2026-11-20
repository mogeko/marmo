# WebSocket

Sources consult: [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455) (The
WebSocket Protocol). Implemented in `packages/ws` (ADR-0014); the root package
provides `Stream`/`Dialer` adapters.

## Implemented scope

- Client opening handshake (`GET`, `Host`, `Upgrade`, `Connection`,
  `Sec-WebSocket-Key`, `Sec-WebSocket-Version: 13`) and a bounded 8 KiB
  response parser that verifies `Sec-WebSocket-Accept` with SHA-1.
- Server opening handshake with request-line/path validation, required headers,
  and key decoding.
- RFC 6455 frames: FIN/opcode/mask, 7/16/64-bit lengths, client masking,
  binary/text, continuation, ping/pong, and close. Control frames must be
  final and at most 125 bytes. Reads accept a single frame up to the 1 MiB
  message limit (the connection buffers it); writes fragment at 64 KiB so
  peers with smaller limits stay compatible.
- Writes use binary messages and split payloads over 64 KiB into a binary
  frame plus continuation frames; reads accept text and binary payloads as
  bytes. The transport does not validate UTF-8.
- Close handling echoes valid close frames, answers invalid codes with 1002,
  invalid UTF-8 with 1007, and oversized frames or messages with 1009.
- Message, fragment, per-read control, and per-read frame limits are bounded
  (1 MiB, 1024, 1024, and 4096); hits are treated as protocol violations.
  Each connection reserves a 1 MiB frame buffer to accept standard-client
  single frames.

## Known gaps

- No extensions (including `permessage-deflate`), subprotocol negotiation,
  redirects, or HTTP proxy authentication.
- Protocol violations detected by the frame codec are reported to the caller;
  only close-frame, oversize, and message-limit paths send a close frame.
- Server handshakes default to no internal timer so that inbound servers use
  the ADR-0015 reaper; standalone embedders that need a self-contained
  deadline set `handshake_timeout_ns` (one sleeping task per handshake).
- No external audit. Parser fuzz targets are `ws_frame`, `ws_handshake`, and
  `ws_connection`.

## Fuzz targets

`ws_frame` reads arbitrary frame bytes as a server (masked input required) and
`ws_handshake` parses a bounded HTTP head. Both run in the deterministic corpus
smoke and in `zig build fuzz`.
