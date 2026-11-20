# Changelog

## Unreleased

> Package version not bumped yet; the root release decides when this becomes
> a tagged package version.

### Security

- Writes over 64 KiB use a binary frame followed by continuation frames;
  oversized single frames and fragmented messages send Close 1009.
- Close handling validates codes and UTF-8 reasons (1002/1007), rejects
  1-byte close payloads, and preserves frames coalesced with the handshake.
- The opening handshake rejects obs-fold, whitespace before the colon,
  duplicate required headers, and body-bearing upgrades.
- Empty/zero-length frame floods are bounded per read (4096 frames), and
  control/fragment counts are bounded.
- Handshake-failure buffers are zeroized, and close state is checked under the
  write lock so no data or pong is sent after a close.

### Changed

- Reads accept standard-client single frames up to the 1 MiB message limit;
  writes still fragment at 64 KiB. Each connection reserves a 1 MiB frame
  buffer.
- Control frames per read allow 1024 (up from 32), and a 1 MiB message may use
  up to 1024 fragments.

### Known limitations

- No extensions (including `permessage-deflate`), subprotocol negotiation,
  redirects, or HTTP proxy authentication.
- Text frames are accepted without UTF-8 validation; most frame-level
  protocol violations do not send Close 1002.
- No true half-close: `end()` sends Close and ends both directions.
- No HTTP/2 WebSocket (RFC 8441); one reader and one writer are supported.
- The 1 MiB read buffer is reserved before the handshake; wiring this to an
  inbound needs a per-connection memory budget or lazy allocation.
- Tests: 22 package tests.

## 0.0.1 - 2026-11-19

- Initial WebSocket package: bounded client/server opening handshake, RFC 6455
  frame codec with masking, continuation, ping/pong, and close.
