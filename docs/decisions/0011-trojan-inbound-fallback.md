# ADR-0011: Trojan inbound fallback

- Status: Accepted (2026-11-19)
- Date: 2026-11-19
- Deciders: @mogeko
- Related: ADR-0002, ADR-0005, ADR-0008, ADR-0009

## Context

Trojan is a Phase 2 protocol (ADR-0002). Its specification
(<https://trojan-gfw.github.io/trojan/protocol>, retrieved 2026-11-19) requires
a real TLS handshake before the client sends
`hex(SHA224(password)) | CRLF | request | CRLF | payload`. When the password or
request does not match, the specification says the server should tunnel the
decrypted traffic to a preset endpoint (the reference default is
`127.0.0.1:80`) so an active prober sees an ordinary HTTPS service instead of
a distinguishable close.

Without that behavior, an invalid authentication is observable: a marmo
listener closes where a real Trojan server would proxy the probe to a web
server. This is the main active-detection vector for Trojan.

marmo is design-first and explicit: no implicit network I/O, no hidden
defaults, and configuration is trusted. A fallback is a new egress path, so it
needs a config field and must follow the same routing policy as other
connections rather than hard-coding a localhost address or bypassing rules.

The confirmed v1 scope for Trojan is standard trojan-gfw behavior (TCP
`CONNECT` and UDP `ASSOCIATE`), TLS required on both inbound and outbound, and
no Trojan-Go WebSocket, Mux, or XTLS extensions. Those constraints belong in
`docs/protocols/trojan.md` when implementation starts; this ADR decides only
the fallback behavior.

## Decision

Add an optional `fallback` endpoint to the Trojan inbound configuration and
route fallback traffic through `Dispatch`.

- `inbounds[].fallback` is a `host:port` string, parsed with
  `Endpoint.parse`. It has no default; when absent, an authentication failure
  closes the connection.
- It is valid only for `protocol: "trojan"`. Other inbound protocols reject
  the field.
- On an authentication failure (hash or CRLF mismatch, or EOF before the
  58-byte authentication prefix), the inbound:
  1. builds TCP `Metadata` with `source` set to the client, `destination` and
     `domain` set from the fallback endpoint, `network` set to `tcp`, and
     `inbound` set to the Trojan inbound tag;
  2. calls `Dispatch.route` and connects to the selected tag, or to `direct`
     for a `direct` action; a `reject` or `hijack_dns` action closes the
     connection;
  3. writes the already-consumed prefix (at most 58 bytes) to the selected
     outbound;
  4. relays the remaining decrypted TLS stream with `relay.relay` and stops
     parsing Trojan.
- The consumed prefix is the only buffered attacker data; its length is fixed
  by the wire format. No payload is logged.
- If fallback is unset, invalid authentication, or the selected outbound
  fails, the connection is closed. marmo does not synthesize an HTTP error
  response.
- Authentication uses `std.crypto.hash.sha2.Sha224` and a constant-time
  comparison. A valid authentication followed by a malformed request is a
  protocol error and closes the connection; it does not enter fallback.
- The fallback path uses the same connection lifecycle as any other tunnel and
  does not create a new session table or per-datagram allocation.
- Tests cover: wrong password reaches a loopback HTTP fallback and receives the
  exact prefix; fallback follows a configured route, including an explicit
  reject rule; no fallback closes; malformed request after valid authentication
  closes without fallback.

## Alternatives

1. **Default `127.0.0.1:80` as in the reference implementation.** Closest to the
   specification, but performs network I/O the operator did not configure and
   can silently forward probes to an unrelated local service. Rejected: it
   conflicts with explicit configuration.
2. **No fallback in v1.** Smallest implementation, but leaves the primary
   active-probing signal and diverges from standard Trojan server behavior.
   Rejected for deployments that need anti-probing; it remains a documented
   option if the operator leaves `fallback` unset.
3. **Direct dialing that bypasses the router.** Simpler and impossible to loop
   through a proxy outbound, but it ignores routing policy and makes the
   fallback target unreachable through an operator-selected egress. Rejected:
   fallback traffic should follow the same policy as other TCP traffic.

## Consequences

- Positive: standard anti-probing behavior with an explicit endpoint, and the
  fallback obeys routing, observability, and outbound selection like any other
  connection.
- Negative: the operator must keep the route for the Trojan inbound tag
  acyclic. A rule that sends fallback traffic to a proxy outbound which points
  back at the same listener creates a loop; this is a configuration error and
  must be documented and tested with a reject rule.
- The operator must protect the fallback service: unauthenticated probes reach
  it by design. Configuration is trusted input, so this is an operator
  responsibility, not a runtime policy.
- A listener without `fallback` remains distinguishable from a standard
  Trojan server; documentation must state this.
- Metrics and logs must count fallback connections without recording the
  prefix, password, or hash.
- The fallback feature adds a fixed 58-byte buffer per connection and one
  routed outbound connection on authentication failure.
- If a later release wants a loop guard or a dedicated fallback outbound, that
  is a new ADR.

## Approval

- [x] Accepted 2026-11-19 with routing-aware fallback: optional explicit
      `fallback`, `Dispatch`/router selection, prefix replay, no default;
      close when unset or rejected.
