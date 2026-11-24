# HTTP/1 proxy

Source: RFC 9112 (HTTP/1.1) and RFC 9110 (HTTP semantics), retrieved
2026-11-24. The request and response heads are parsed with `httparse`; marmo
owns the proxy policy around them (ADR-0018).

## Implemented

- HTTP/1.0 and HTTP/1.1 request heads, origin-form and absolute-form targets,
  and CONNECT response heads.
- Inbound `CONNECT host:port` tunnels and forward proxying. One request head is
  parsed per connection; bytes after that head are relayed as opaque bytes.
  Pipelined requests are not parsed or routed individually, so clients must not
  rely on pipelining.
- Bounds: 8 KiB request head, 64 headers, 8 KiB + 1 KiB rewritten forward head;
  control characters and invalid header names/values are rejected.
- CONNECT requires a `host:port` target. Normally the `200 Connection
  Established` response is sent only after the outbound connects; when sniffing
  needs client bytes, it is sent before routing so the client starts its TLS or
  HTTP handshake. A rejected route returns `403`, a failed outbound returns
  `502`, an oversized/invalid head returns `431`/`400`, and an unsupported
  version returns `505`.
- Forward requests are rewritten from absolute-form to origin-form. `Host` is
  taken from the URI authority, hop-by-hop headers are stripped, including
  fields nominated by `Connection:` (framing fields are kept), and the upstream
  is forced to `Connection: close`. The request body (if any) is relayed after
  the rewritten head.
- Outbound HTTP CONNECT sends the request head, validates the response head,
  and replays any bytes that followed it.
- Optional inbound credentials are not part of this release; routing and
  rejection are the only request-level policy.
- TLS, WebSocket, and HTTP/2 are transport layers, not part of this inbound.
  There is no HTTP cache, content rewriting, or general-purpose server.

## Known gaps

- No HTTP/1.1 chunked-body decoding or trailing headers in the proxy itself;
  bodies are relayed as opaque bytes after the head.
- No upgrade, WebSocket-over-HTTP/1.1, or request pipelining.
- No HTTP/2 inbound and no proxying of HTTP/2 requests as HTTP/1 for upstream.
- Header forwarding does not canonicalize arbitrary fields beyond the
  hop-by-hop and framing checks above.

## Fixtures and tests

- Golden fixtures: `crates/marmo-proto/tests/fixtures/http/`.
- Unit: request parsing, absolute target, CONNECT response, control characters,
  bad versions, framing ambiguity, truncation, and size limits.
- Fuzz: `http` target over request, absolute target, and CONNECT response
  parsing; corpus seeds are spec-derived heads.
- Integration: HTTP CONNECT, forward rewrite, hop-by-hop stripping, reject, and
  outbound CONNECT loopback tests.
- Local RFC conformance: curl 8.7.1 forward and proxied-CONNECT requests through
  a marmo HTTP inbound to a local HTTP server passed on 2026-11-24. The
  differential matrix is in [`interop.md`](interop.md).
