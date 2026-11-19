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
  final and at most 125 bytes; frame payloads are capped at 64 KiB.
- Writes use binary messages; reads accept text and binary payloads as bytes.
  The transport does not validate UTF-8.

## Known gaps

- No extensions (including `permessage-deflate`), subprotocol negotiation,
  redirects, or HTTP proxy authentication.
- No dedicated close-code policy beyond echoing a received close frame.
- No external audit. Parser fuzz targets are `ws_frame` and `ws_handshake`.

## Fuzz targets

`ws_frame` reads arbitrary frame bytes as a server (masked input required) and
`ws_handshake` parses a bounded HTTP head. Both run in the deterministic corpus
smoke and in `zig build fuzz`.
