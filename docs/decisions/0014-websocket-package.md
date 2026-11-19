# ADR-0014: WebSocket transport as a first-party package

- Status: Accepted (2026-11-19, on direct implementation request)
- Date: 2026-11-19
- Deciders: @mogeko
- Related: ADR-0004, ADR-0007, ADR-0010

## Context

VLESS and VMess use WebSocket as an L7 transport, usually over TLS, with a
caller-chosen path and `Host` header. `std` has no WebSocket client and no
general upgrade helper suitable for this use. The transport needs the RFC 6455
opening handshake and binary framing, not a browser-grade API.

## Decision

Add `packages/ws/` as a std-only first-party package with its own build,
following ADR-0010. It implements:

- client opening handshake: `GET` request with `Upgrade`, `Connection`,
  `Sec-WebSocket-Key`, `Sec-WebSocket-Version: 13`, `Host`, optional path and
  extra headers; bounded 8 KiB response parsing; `Sec-WebSocket-Accept`
  verification using SHA-1 and constant-time comparison;
- server opening handshake: bounded 8 KiB request parsing, required header
  validation, 101 response generation;
- framing: FIN/opcode/mask, 7/16/64-bit lengths, client masking, binary and
  text messages, continuation, ping/pong, and close with a bounded reason;
- a `Stream`-like duplex byte API where each `write` becomes one binary
  message split into bounded frames, and `read` returns binary payload bytes
  across fragmented messages; control frames are handled internally;
- explicit bounds: 8 KiB handshake, 64 KiB frame payload, 1 MiB message.

Root adapters in `src/transport/ws_*.zig` expose marmo `Stream` and compose
with TLS/TCP dialers. The package imports only `std`.

## Alternatives

1. **Put WebSocket in `src/transport`.** Couples the handshake/framing to
   marmo types and makes independent tests harder. Rejected for consistency
   with ADR-0010.
2. **Support permessage-deflate.** Adds a compression state machine and a
   negotiation surface the proxy transports do not need. Rejected for Phase 2.
3. **Rely on a third-party Zig WebSocket package.** Violates zero dependencies
   and std-only. Rejected.
4. **Frame at the relay layer instead of a transport adapter.** Duplicates
   masking, control-frame, and close handling in every protocol. Rejected.

## Consequences

- Positive: one bounded implementation serves inbound and outbound, and can be
  fuzzed without sockets. Text frames are accepted on read but the transport
  writes binary frames, matching proxy use.
- Negative: no extensions (compression), no HTTP redirects, no proxy
  authentication in the handshake. Client masking is mandatory and enforced.
- Tested by handshake accept-vector tests, frame parser truncation/masking
  tests, an in-tree client/server loopback echo, and a TLS+WS integration path.
