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

## Amendment (2026-11-20)

The opening handshake now keeps bytes after the HTTP terminator, rejects
obs-fold/whitespace-before-colon/duplicate required headers/body-bearing
upgrades, and preserves frames coalesced with the handshake. Messages are
bounded at 1 MiB and 1024 fragments, control frames per read are bounded, close
codes and UTF-8 reasons are validated, and client masking uses a 4 KiB scratch
buffer. A single frame remains capped at 64 KiB; larger messages must be
fragmented by the peer.

## Amendment (2026-11-20, read frame limit)

The read side now accepts a single frame up to the 1 MiB message limit so
standard clients that send a whole message as one frame interoperate. The write
side still fragments at 64 KiB, and the previous sentence about a 64 KiB read
cap no longer applies. Each connection reserves a 1 MiB frame buffer.

## Amendment (2026-11-20, permessage-deflate and subprotocols)

On direct implementation request by @mogeko, the package now implements
`permessage-deflate` and subprotocol negotiation. This supersedes the earlier
statement that compression and subprotocol negotiation are out of scope
(including alternative 2 in this ADR); the package, not `Config`/`Instance`,
owns the negotiation surface.

- The client offers `Sec-WebSocket-Protocol` from `ClientOptions.subprotocols`;
  the server selects the first configured protocol the client offered and
  rejects a request with no acceptable protocol. Both expose the selected
  token. A client rejects a server selection it did not request.
- Both roles negotiate RFC 7692 `permessage-deflate` with
  `server_no_context_takeover`, `client_no_context_takeover`,
  `server_max_window_bits`, and `client_max_window_bits`. RSV1 is accepted only
  on the first data frame of a compressed message; control frames are never
  compressed. The client rejects extensions and parameters it did not offer;
  the server declines offers it cannot accept.
- Encoding uses a new in-package raw-DEFLATE encoder (fixed Huffman, LZ77, and
  the RFC 7692 sync flush). `std.compress.flate.Compress` cannot be used for
  encoding in Zig 0.17.1: its writer flush does not produce the interoperable
  `00 00 ff ff` sync-flush tail. Decoding still uses
  `std.compress.flate.Decompress`, appending the RFC 7692 suffix and bounding
  output at the 1 MiB message limit.
- Text messages are validated incrementally across fragments and invalid UTF-8
  closes with 1007. Protocol failures close with 1002/1007/1009 through a
  non-blocking path that queues the code when a data writer holds the lock;
  application policy closes (1008) use `closeWithCode`. No data or pong follows
  a close.
- Bounds: compressed input is capped at `max_compressed_message` (1 MiB plus
  one eighth plus a flush header) and decompressed output at 1 MiB. Each
  connection is about 2.5 MiB (1 MiB frame buffer, 1.125 MiB compressed-message
  accumulator, 64 KiB write scratch, 64 KiB encoder ring, 128 KiB hash table,
  and 64 KiB inflater window); lazy compression state is a recorded later
  optimization.
- Wiring into `Config`/`Instance`, Origin/auth checks, redirects, HTTP/2
  WebSocket, true half-close, and configurable limits remain out of scope.
