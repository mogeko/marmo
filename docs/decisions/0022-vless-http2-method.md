# ADR-0022: VLESS HTTP/2 transport method

- Status: Proposed
- Date: 2026-11-21
- Deciders: @mogeko
- Related: ADR-0016, ADR-0018

## Context

ADR-0016 specifies that the VLESS `h2` transport uses an HTTP/2 `POST`
request with `content-type: application/octet-stream`. R3g implemented that
behavior and it works against marmo's own peers.

R4 reference interop found that this is not what deployed implementations do:

- Xray 26.11 and 24.12 have removed the HTTP/2 transport in favour of XHTTP,
  so they can no longer serve as an HTTP/2 reference.
- V2Ray 5.53 still implements it. Its client sends
  `PUT https://host/path` **without** a `content-type` header, and its server
  rejects a `POST`.
- Xray 1.8.24 keeps the same HTTP transport family and can be used as an older
  reference if needed.

The references also do not validate the media type. Probes with `curl --http2`
against V2Ray 5.53 and Xray 1.8.24 HTTP/2 inbounds returned `200` for both
`PUT` and `POST` and for every tested `content-type`: absent,
`application/octet-stream`, `text/plain`, `application/json`,
`application/x-www-form-urlencoded`, `application/grpc`, and an arbitrary
`x/y`. The HTTP method is the only request-line value they inspect; the path
must still match the configured one.

A scratch build with three changes was run against V2Ray 5.53 on loopback:

1. the client sends `PUT`;
2. the server accepts both `POST` and `PUT`;
3. the server accepts a missing or arbitrary content type.

With those changes both directions pass: marmo server <- V2Ray client, and
V2Ray server <- marmo client. One configuration detail matters when the
reference server sets `httpSettings.host`: the `:authority` must match it
exactly. V2Ray rejects `localhost:20115` when it is configured for `localhost`
with `404`; Xray 1.8.24 accepted the port in our probe. marmo's host
derivation already omits the port for an IP/domain server, and
`transport.host` overrides it.

The concrete failure this decision prevents: keeping a POST-only h2
implementation that cannot talk to the only remaining reference peers, while
the parity matrix still claims HTTP/2 interop.

## Decision (recommended)

Change the VLESS HTTP/2 transport to the reference-compatible method while
keeping every other ADR-0016 rule.

- **Client**: send `PUT` instead of `POST`. Keep the current
  `content-type: application/octet-stream` header; reference servers accept it.
- **Server**: accept both `PUT` and `POST`. Do not validate `content-type`:
  accept an absent header or any value, matching the references. The request
  path is still required to match, and anything else returns `400`.
- **Unchanged**: TLS is required for h2; ALPN `h2` is offered and required as
  before; `transport.host` still supplies `:authority`; no h2c, no
  request body media-type semantics, no change to WebSocket or TCP.
- The h2 stream still carries the VLESS byte stream over the request body, and
  the response body carries the reverse direction.

This supersedes only the "POST request and `content-type:
application/octet-stream`" clause of ADR-0016. The rest of ADR-0016 remains in
force.

## Alternatives

1. **Keep `POST`.** No HTTP/2 reference interop with V2Ray or Xray;
   marmo-to-marmo tests would be the only coverage. Rejected.
2. **Require `application/octet-stream`.** Stricter than both references and
   would reject clients that omit or vary the header; the header carries no
   protocol meaning for this tunnel. Rejected.
3. **Use `PUT` only on both ends.** Breaks mixed-version deployments during
   upgrade (an R3g server would reject a new client and vice versa). Accepting
   both methods costs nothing and keeps upgrades safe. Rejected as
   unnecessary compatibility loss.
4. **Try `POST`, retry with `PUT` on 400/405.** Doubles the handshake, depends
   on how a reference resets the stream, and leaves a second code path to test.
   Rejected.
5. **Drop HTTP/2 from parity.** Loses a transport that works and is part of
   the Zig feature set. Rejected.
6. **Replace HTTP/2 with XHTTP.** XHTTP is a different, Xray-specific transport
   and is not in the current plan; it needs its own decision. Rejected here.

## Consequences

Positive:

- HTTP/2 works in both directions against V2Ray 5.53 and Xray 1.8-era peers.
- The change is wire-local: one method token and a relaxed content-type check;
  no framing, TLS, ALPN, or config-schema change.
- Mixed marmo versions keep working because the server accepts both methods.

Negative:

- The server no longer validates the media type at all. This matches the
  references and avoids a false rejection; the path and method still bound the
  route.
- `httpSettings.host` enforcement in V2Ray is exact, so `transport.host` must
  match the reference's authority (without a port when the reference omits
  it).
- The implementation now differs from the literal text of ADR-0016; the
  amendment must be tracked so a later reader does not "fix" it back to POST.
- Reference Xray versions are moving to XHTTP, so HTTP/2 interop will keep
  depending on V2Ray or older Xray releases until XHTTP is considered.

Testing and observation:

- Unit tests in `marmo-transport`: `PUT` and `POST` both succeed, a missing or
  arbitrary content type succeeds, a wrong path still fails, and the response
  body still round-trips.
- VLESS integration: H2 TCP and UoT keep passing.
- Reference interop: V2Ray 5.53 both directions, with `transport.host` set to
  the authority the server expects. This is run outside the test suite, as
  with the rest of R4 interop.
- On acceptance, update `docs/protocols/vless.md` (it currently says POST) and
  the ADR index.

Rollback: revert to `POST` and the required content type. Older reference
servers that accepted POST would work again; V2Ray 5.53 would not.

## Approval

- [ ] Accept the recommendation (`PUT` client, `POST`/`PUT` server, optional
      content type).
- [ ] Choose an alternative: keep `POST`, or another approach.
