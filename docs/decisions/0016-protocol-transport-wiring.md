# ADR-0016: Protocol transport composition wiring

- Status: Accepted (2026-11-20, on direct implementation request)
- Date: 2026-11-20
- Deciders: @mogeko
- Related: ADR-0004, ADR-0007, ADR-0012, ADR-0013, ADR-0014, ADR-0015

## Context

ADR-0004 requires proxy protocols to compose with transports, and ADR-0012
through ADR-0014 delivered the TLS ALPN, HTTP/2, and WebSocket packages. Until
now the packages were programmatic adapters only: `Config`/`Instance` exposed
plain TCP and TCP/TLS, so VLESS could not run over WebSocket or HTTP/2 and the
new WebSocket compression/subprotocol and TLS ALPN surfaces were unused.

VLESS is the only implemented protocol whose wire format is transport
agnostic. Standard Trojan is defined over TLS, and Trojan-Go WebSocket is a
non-standard extension; VMess is not implemented.

## Decision

Add one optional `transport` object to VLESS inbounds and outbounds:

```json
"transport": {
  "network": "tcp" | "ws" | "h2",
  "path": "/",
  "host": "cdn.example.com",
  "compression": false,
  "subprotocols": ["marmo"]
}
```

- `network` defaults to `tcp`. `path` must start with `/` and is at most 255
  bytes. `host` is the HTTP `Host`/`:authority`; when absent it falls back to
  `tls.sni`, then the server domain, then the formatted server IP. The
  inbound enforces `path` but not `host`; Host checking is outbound-only for
  now.
- `ws` uses the RFC 6455 package. `compression` enables
  `permessage-deflate`; `subprotocols` is the offered/accepted list. Both are
  rejected for `tcp` and `h2`.
- `h2` uses the HTTP/2 package with a POST request and
  `content-type: application/octet-stream`. It requires TLS.
- Inbound VLESS still requires TLS for every network. Outbound VLESS keeps
  TLS optional for `tcp` and `ws`; `h2` requires it.
- ALPN defaults are transport-aware and only apply when `tls.alpn` is absent:
  `h2` uses `["h2"]` and requires it; `ws` over TLS offers `["http/1.1"]` but
  does not require a selection. An explicitly configured `h2` ALPN list must
  contain `h2`, and an explicit WS list must contain `http/1.1`.
- The `transport` object is rejected on every other inbound/outbound protocol.
  It is not a generic stream-settings replacement and does not introduce
  arbitrary header, early-data, heartbeat, or h2c options.
- `Instance` disables the WebSocket/HTTP/2 adapter handshake timers and lets
  the ADR-0015 reaper own the deadline. Standalone adapters keep their
  10-second default. A timer that completes after the handshake uses an atomic
  running/done/fired state so it cannot abort a live connection.
- The HTTP/2 server adapter can accept multiple streams on one connection, but
  `Instance` currently consumes one stream per H2 connection. Root-level
  HTTP/2 multiplexing and connection pooling remain follow-up work.

## Alternatives

1. **Per-protocol dial functions** (`dialVlessTlsWs`). Multiplies combinations
   and bypasses ADR-0004. Rejected.
2. **Copy Xray `streamSettings` verbatim.** Adds unused fields (early data,
   heartbeat, arbitrary headers, sockopt, REALITY) and a second config schema
   for features the packages do not implement. Rejected.
3. **Wire only HTTP/2 because it is new.** Leaves WebSocket path/host,
   compression, subprotocols, and ALPN untested through `Config`. Rejected.
4. **Add Trojan-Go WebSocket.** Standard Trojan remains TLS-only; the extension
   needs its own compatibility and interop evidence. Deferred.
5. **Implement root HTTP/2 multiplexing now.** The package supports 16 streams,
   but the inbound lifecycle, per-stream guards, and metrics need a separate
   design. Deferred rather than shipping a partially safe multiplexer.

## Consequences

- VLESS inbounds and outbounds can use TLS + WebSocket or TLS + HTTP/2, with
  path, Host, WS compression, subprotocols, and ALPN selected through strict
  config validation.
- The transport is still bounded by the package limits: 8 KiB WS handshake,
  1 MiB WS messages, 16 KiB H2 frames, 8 KiB H2 header lists, and the existing
  connection limits.
- HTTP/2 multiplexing is available to package callers but not yet used by
  `Instance`; each inbound H2 connection carries one VLESS stream.
- No VMess wiring, WS early data/heartbeat, H2 h2c, gRPC framing, or TLS
  session resumption is introduced by this decision.
- Tested by config validation cases and loopback integration tests for VLESS
  over WS and H2, including WS compression/subprotocols and H2 ALPN.

## Approval

- [x] Accept the recommendation.
