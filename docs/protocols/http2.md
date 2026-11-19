# HTTP/2

Sources consult: [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113) (HTTP/2),
[RFC 7541](https://www.rfc-editor.org/rfc/rfc7541) (HPACK). Implemented in
`packages/http2` (ADR-0013); the root package provides `Stream`/`Dialer`
adapters.

## Implemented scope

- Connection preface, SETTINGS and SETTINGS ACK, PING/ACK, GOAWAY,
  RST_STREAM, WINDOW_UPDATE, and CONTINUATION.
- Frames are capped at 16 KiB; stream ids and reserved bits are validated.
- HPACK decoding with the static table, a 4 KiB dynamic table, integer
  decoding, and RFC 7541 Appendix B Huffman decoding. Encoding uses static
  indices and literals without Huffman.
- One active stream per connection (`MAX_CONCURRENT_STREAMS = 1`), with
  stream and connection flow control. The initial stream window is 1 MiB.
- Client opens stream 1 with caller-provided headers; server accepts the first
  HEADERS frame and exposes the decoded list. Both roles expose a duplex byte
  stream over DATA frames.

The Huffman table in `packages/http2/src/huffman_table.zig` is generated from
RFC 7541 Appendix B; `code`/`bits` pairs are transcribed from the RFC text, not
ported from an implementation.

## Known gaps

- No multiplexing, server push, PRIORITY effects, or HTTP/1.1 translation.
- No general request router, caching, or response-body framing beyond DATA.
- A writer can wait for WINDOW_UPDATE; the receive side must be reading frames
  on the same connection. A peer that stops reading can stall the writer.
- No external audit. Parser fuzz targets are `http2_frame` and `http2_hpack`.

## Fuzz targets

`http2_frame` parses arbitrary frame bytes; `http2_hpack` decodes arbitrary
header blocks with bounded storage and header arrays. Both run in the
deterministic corpus smoke and in `zig build fuzz`.
