# Changelog

## Unreleased

> Package version not bumped yet; the root release decides when this becomes
> a tagged package version.

### Added

- `permessage-deflate` (RFC 7692) for client and server, including
  `server_no_context_takeover`, `client_no_context_takeover`,
  `server_max_window_bits`, and `client_max_window_bits` negotiation. RSV1 is
  validated per message; control frames are never compressed. The decoder
  bounds decompressed messages at 1 MiB through `max_compressed_message`.
- Subprotocol negotiation (RFC 6455 §4.1/4.2) through `subprotocols` options,
  with `selectedSubprotocol` on the connection. Servers reject a request with
  no acceptable protocol; clients reject a selection they did not request.
- Incremental UTF-8 validation for text messages across fragments, closing with
  1007 on invalid data.
- `closeWithCode` for application policy closes (1008 and others).
- A deterministic hostile-input smoke test for the inflater and a bounded
  in-package DEFLATE encoder (fixed Huffman + LZ77 + RFC 7692 sync flush).

### Security

- Writes over 64 KiB use a binary frame followed by continuation frames;
  oversized single frames and fragmented messages send Close 1009.
- Close handling validates codes and UTF-8 reasons (1002/1007), rejects
  1-byte close payloads, and preserves frames coalesced with the handshake.
- The opening handshake rejects obs-fold, whitespace before the colon,
  duplicate required headers, body-bearing upgrades, duplicate/unknown
  extension parameters, and unrequested subprotocols/extensions.
- Empty/zero-length frame floods are bounded per read (4096 frames), and
  control/fragment counts are bounded.
- Protocol failures queue their Close code and send it with a non-blocking
  lock attempt, so a reader cannot deadlock behind a blocked data writer.
- Handshake-failure buffers are zeroized, and close state is checked under the
  write lock so no data or pong is sent after a close.

### Changed

- Reads accept standard-client single frames up to the 1 MiB message limit;
  writes still fragment at 64 KiB. Each connection reserves a 1 MiB frame
  buffer.
- Control frames per read allow 1024 (up from 32), and a 1 MiB message may use
  up to 1024 fragments.
- Pongs are dropped when a data writer holds the lock instead of blocking the
  reader.

### Known limitations

- No redirects or HTTP proxy authentication.
- Compression, subprotocols, and close codes are not wired into
  `Config`/`Instance`; use the package options directly.
- No true half-close: `end()` sends Close and ends both directions.
- No HTTP/2 WebSocket (RFC 8441); one reader and one writer are supported.
- Each connection is about 2.5 MiB (read frame buffer, compressed-message
  accumulator, write scratch, encoder ring/hash, inflater window), reserved
  before the handshake; wiring this to an inbound needs a per-connection memory
  budget or lazy allocation (recorded later optimization).
- The inflater accepts any conforming raw-DEFLATE stream; a peer using extreme
  dynamic-Huffman expansion can be rejected at the compressed-input bound.
- Tests: 60 package tests.

## 0.0.1 - 2026-11-19

- Initial WebSocket package: bounded client/server opening handshake, RFC 6455
  frame codec with masking, continuation, ping/pong, and close.
