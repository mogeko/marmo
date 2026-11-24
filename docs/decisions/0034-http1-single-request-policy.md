# ADR-0034: HTTP/1 single-request forwarding policy

- Status: Proposed
- Date: 2026-11-24
- Deciders: @mogeko
- Related: ADR-0008, ADR-0018, ADR-0032

## Context

The HTTP inbound parses one request head, routes it, and then relays every byte
after that head as opaque data (`crates/marmo/src/inbound/http.rs`). The
upstream is forced to `Connection: close`, but the proxy does not parse
`Content-Length`, `Transfer-Encoding: chunked`, trailers, or a second request.

The original protocol note claimed "one request per connection; there is no
request pipelining". That is true only for the code that parses and routes; a
client can still send a second request in the opaque remainder, and the origin
may process it. Without body framing the proxy cannot reliably distinguish
"body bytes" from "second request head", so it cannot both preserve arbitrary
bodies and reject pipelining.

The project needs an honest, small first step now and a separate full HTTP/1
framing decision later. The first step must not claim a safety property it does
not enforce.

## Decision (recommended)

Implement the single-request policy (Option A) now and record full HTTP/1
message framing and pipelining as a future roadmap item (P4-6).

### Option A: single request head, opaque remainder

- Parse and route exactly one request head per connection.
- Treat all bytes after that head, and all later client bytes, as an opaque
  body/tunnel. Do not parse a second request head.
- Force `Connection: close` on the upstream request.
- Strip `Connection:`-nominated hop-by-hop fields while retaining
  `Content-Length` and `Transfer-Encoding` as framing fields.
- Do not advertise keep-alive; do not claim that pipelining is safe.
- Reject `CONNECT` targets that are not endpoints; preserve the existing
  status mapping (`400`, `403`, `431`, `502`, `505`).
- Rename the internal `leftover` value to `body_prefix` so future changes do not
  mistake it for a second request.
- Document that clients must not pipeline requests to this inbound.

Tests:

- a forward request with a body prefix sends the prefix unchanged to the
  upstream;
- a second request line in the remainder is not separately parsed or routed;
- `Connection:` nominations are stripped, while `Content-Length` and
  `Transfer-Encoding` are preserved;
- `CONNECT` with a body prefix still forwards the prefix after `200`;
- oversized heads and header counts remain bounded.

### Option B: full framing and pipelining, later

The future item must add:

- `Content-Length` and chunked body framing, trailers, and request-boundary
  validation;
- per-request routing on one connection;
- pipelining tests against a reference server and a smuggling regression suite;
- an ADR before implementation.

This is tracked as **P4-6** in `docs/roadmap.md`, not P2: Phase 2 is closed and
HTTP/1 framing is production hardening, not part of the protocol-set phase.

## Alternatives

1. **Implement full HTTP/1 framing and pipelining now (Option B).** This is the
   correct long-term behavior, but it adds a request parser, body framing,
   trailers, and a new smuggling surface before the rest of the API refactor.
   Rejected for this slice; track as P4-6.
2. **Keep the current behavior and call it "one request per connection".** The
   parser only routes one request, but the connection can carry more bytes.
   The claim is misleading and was an audit finding. Rejected.
3. **Tunnel all bytes after the head, including CONNECT and forward requests,
   with no request semantics.** This is already what happens for the remainder,
   but it does not describe the first request; it also makes policy/routing
   expectations unclear. Rejected as a standalone policy.
4. **Reject all forward requests with a body.** Safe but breaks ordinary POST
   and any body-bearing request. Rejected.

## Consequences

Positive:

- The HTTP inbound has a small, explicit policy that matches what it actually
  enforces.
- Body bytes are preserved without a partial framing implementation.
- The remaining HTTP/1 work has a concrete roadmap item and a required ADR.

Negative:

- Pipelining is still unsupported; a client that pipelines can have its second
  request treated as body bytes by the origin.
- The policy is not a request-smuggling defense; it is a scope statement.
- Full framing may later change the forwarding path and require new tests.

Tests and observation:

- Existing HTTP forward, CONNECT, hop-by-hop, reject, and outbound CONNECT tests
  remain green.
- New tests cover body-prefix preservation, no separate second-request routing,
  and framing-header preservation.
- The protocol note and architecture section describe the exact behavior and
  reference P4-6.

## Approval

- [ ] Accept Option A now and P4-6 for full framing/pipelining.
- [ ] Implement Option B now.
- [ ] Keep the current behavior and reword the docs only.
- [ ] Choose a different request-boundary policy: ...
- [ ] Reject this policy change.
