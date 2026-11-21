# VLESS

Source: the VLESS protocol as documented by XTLS/Xray-core and V2Fly
(<https://xtls.github.io/en/config/protocols/vless.html>,
<https://github.com/v2fly/v2ray-core/blob/master/common/protocol/headers.go>),
retrieved 2026-11-19. TLS record details come from RFC 8446. Both TLS roles
use the in-tree TLS 1.3 implementation in `packages/tls13`; WebSocket and
HTTP/2 use the first-party packages from ADR-0013 and ADR-0014.

## Implemented

- VLESS outbound and inbound; TCP command `1`, simple UDP command `2`, and
  Xray-compatible XUDP command `3`.
- Outbound transport is TCP, optional TLS 1.3, WebSocket, or HTTP/2, selected
  by `transport.network` (ADR-0016). Inbound transport is mandatory TLS 1.3,
  optionally wrapped by WebSocket or HTTP/2; the accepted stream is wrapped
  before the VLESS header is parsed.
- WebSocket transport uses `path` and `host`, and optionally
  `permessage-deflate` (`compression`) and subprotocols (`subprotocols`).
  HTTP/2 uses a `PUT` stream with `:authority` from `host` and `:path` from
  `path`, and requires ALPN `h2` (defaulted when `tls.alpn` is absent). The
  client sends no `content-type`; the server accepts `PUT` and `POST` and
  ignores the header (ADR-0022).
- Inbound UUID authentication uses a constant-time comparison, then routes and
  connects to the selected outbound. The empty response header is sent only
  after the outbound connection is established.
- Inbound TLS credentials are loaded from PEM/DER certificate files and a PEM
  PKCS#8 or SEC1 ECDSA P-256 private key. The leaf certificate must match the
  key.
- Strict config validation:
  - outbound `server` is required and must be `host:port`;
  - `uuid` is required and accepts `8-4-4-4-12` or 32 hex digits;
  - outbound `tls` is optional; `tls.sni` is required for an IP `server` when
    verification is enabled;
  - inbound `tls.certificate` and `tls.private_key` are required and must not
    be empty;
  - outbound `xudp` is optional and defaults to `false`;
  - inbound/outbound TLS `handshake_timeout_s` defaults to 10 and must be
    positive;
  - `uuid` and `tls` are rejected on other outbound/inbound protocols;
  - `transport.network` is `tcp`, `ws`, or `h2`; `ws`/`h2` reject an invalid
    path/host, `compression`/`subprotocols` are WS-only, and `h2` requires TLS
    with an ALPN list containing `h2`; a configured WS ALPN list must contain
    `http/1.1`.
  - The inbound enforces the configured path but not the configured `host`;
    host checking is outbound-only for now.
- Request header: version `0`, 16-byte UUID, zero addon length, command `1`
  (TCP) or `2` (UDP), big-endian port, address type (`1` IPv4, `2` domain,
  `3` IPv6), address. Command `3` (Mux/XUDP) omits the address on the wire and
  is represented internally as `v1.mux.cool:666`.
- Response header is read lazily: version `0`, addon length, addons. The
  response payload is passed through unchanged.
- Simple UDP uses one fixed destination per stream and
  `[2B length BE][payload]` frames. The outbound sends one request with the
  destination and rejects a different `send_to` destination; the inbound
  creates one outbound `PacketConn` for the request destination and writes
  replies with the same framing.
- XUDP is implemented for both directions. The inbound accepts VLESS Mux
  command `3` with the synthetic `v1.mux.cool` target and parses New/Keep
  frames; the outbound can opt into XUDP with `"xudp": true`.
- The outbound defaults to simple UoT, which is more interoperable with
  non-Xray servers.
- Zero-length UDP frames are skipped on receive and dropped on send, matching
  the base Xray behavior.
- Request header is written once, in a single vectored write where possible.
- TLS:
  - SNI and hostname verification use `tls.sni`, or the server domain name when
    `sni` is absent.
  - Certificate chains are verified against the host CA bundle, loaded lazily
    with `std.crypto.Certificate.Bundle.rescan` on the first verifying
    connection.
  - `tls.insecure = true` skips CA-chain verification. When a server name is
    available (from `tls.sni` or the server domain), the hostname is still
    verified by the in-tree client; use a trusted certificate for full SNI
    behavior.
  - Client secrets are zeroized when the TLS stream is closed.
  - A missing `close_notify` is treated as EOF: proxied byte streams have no
    application length framing that could detect truncation.
- The TLS adapters implement the public `Stream` interface and preserve the
  underlying endpoints. TLS lives in `packages/tls13`: the outbound uses the
  std-backed client and the inbound uses the in-tree TLS 1.3 server.

### XUDP framing

XUDP is a Mux.Cool subset carried after the VLESS request header:

```text
[2B metadata length][metadata][2B data length][data]
```

Metadata begins with the 2-byte session ID (XUDP uses `0`), a status byte, and
an option byte. New frames (`status=1`) carry a UDP network byte, big-endian
port, address type/address, and an 8-byte GlobalID; Keep frames (`status=2`)
may carry a per-packet address or no destination. The data flag is option bit
`1`. Replies use Keep frames with no destination. This implementation ignores
GlobalID/cone NAT and binds the stream to the first New frame's target.

### Config example

```json
{
  "inbounds": [
    {
      "tag": "vless-in",
      "protocol": "vless",
      "listen": "0.0.0.0:443",
      "uuid": "00112233-4455-6677-8899-aabbccddeeff",
      "tls": {
        "certificate": "server-cert.pem",
        "private_key": "server-key.pem"
      },
      "transport": { "network": "ws", "path": "/vless" }
    }
  ],
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "vless",
      "server": "example.com:443",
      "uuid": "00112233-4455-6677-8899-aabbccddeeff",
      "tls": { "sni": "cdn.example.com" },
      "transport": { "network": "ws", "path": "/vless", "host": "cdn.example.com" },
      "xudp": true
    }
  ],
  "route": { "final": "proxy" }
}
```

Without a `tls` object the outbound sends VLESS over plain TCP; this is useful
for loopback tests and for deployments that terminate TLS in front of the proxy.
The inbound always requires TLS; plaintext VLESS inbound is not supported.

## Limits and known gaps

- Simple UDP and XUDP both support one fixed destination per stream. XUDP
  GlobalID/cone NAT is not implemented; per-packet destination changes are
  rejected. A SOCKS5 UDP association that switches targets will have later
  datagrams rejected by the VLESS outbound.
- XUDP outbound is opt-in (`"xudp": true`); the default remains simple UoT for
  broader interoperability. XUDP uses a synthetic `v1.mux.cool:666` request.
- UDP replies carry no source address; the client reports the bound target (or
  its resolved IP) as the source.
- Empty UDP datagrams are dropped/skipped, so peers cannot rely on preserving
  zero-length datagrams.
- The inbound requires TLS and has no fallback to another protocol on the same
  listener. TLS credentials are loaded at `Instance.init`; there is no hot
  reload.
- TLS handshakes are bounded by `handshake_timeout_s` (default 10 seconds) in
  both directions. A timed-out handshake is canceled and the connection is
  closed.
- No request addons are generated; response addons are skipped. No
  `flow`/XTLS Vision.
- WebSocket/HTTP/2 are configured only through the VLESS `transport` object;
  there are no arbitrary WS headers, early-data (`?ed=`), heartbeat, h2c, or
  HTTP/2 WebSocket options. `Instance` serves one VLESS stream per H2
  connection even though the package supports multiple streams; root-level
  HTTP/2 multiplexing/pooling is a follow-up. gRPC is not implemented.
- One request per stream and no multiplexing (Mux.Cool).
- No custom CA file or pinning yet for the outbound; verification uses the host
  bundle or `insecure`.
- Certificate verification and SNI still share the configured `tls.sni`; no
  custom CA file or pinning is exposed by the root config.
- Concurrent TLS writes and `shutdown(.send)` are serialized. A relay abort
  (`shutdown(.both)`) closes the transport without sending `close_notify` so it
  cannot race with a writer. TLS 1.3 `KeyUpdate` is handled by the in-tree
  record layer, with disjoint read/write key state.
- No anti-probing or replay behavior beyond what TLS provides.

## XHTTP (future work)

XHTTP (formerly SplitHTTP) is Xray's HTTP-carried transport and is not
implemented. Current Xray releases removed their HTTP/2 transport in favour of
XHTTP, so XHTTP is the transport to add when compatibility with current Xray
peers is required. It is not in the current plan or the R5 schedule; it needs
its own ADR and design.

Planned scope when it is taken up:

- `transport.network = "xhttp"` with `path` and `host`, over TLS; ALPN `h2`
  first, `h3` later if QUIC is available.
- Start with stream-one: one HTTP request/response whose bodies carry the
  VLESS byte stream, matching Xray's `stream-one` mode.
- Evaluate stream-up/stream-down and separate uplink/downlink requests only if
  real peers require them.
- Padding, header names, and metadata only as far as needed for interop; no
  arbitrary header configuration.
- Bounded request/response bodies, headers, and buffers; no h2c.
- Tests: config validation, loopback TCP/UoT/XUDP, Xray interop in both
  directions, and a fixture derived from the public Xray documentation.
- Clean-room from the public Xray XHTTP description; record the sources in this
  file before implementation.

## Tests

- Unit: UUID parsing, request-header encoding for IPv4/domain/IPv6, tiny-buffer
  rejection.
- Integration: SOCKS5 CONNECT -> VLESS over plain TCP -> mock VLESS server ->
  echoed payload, with the mock server validating UUID, command, port, and
  address.
- Integration: a TLS VLESS outbound against a listener that closes immediately;
  the handshake failure is reported as a SOCKS5 failure reply.
- Integration: client and server TLS handshakes against peers that never send
  TLS records, asserting `TimedOut` with a short test timeout.
- Integration: TLS client -> VLESS inbound over the in-tree TLS 1.3 server ->
  direct TCP echo, including PEM credential loading and response-header order.
- Integration: SOCKS5 UDP ASSOCIATE -> VLESS UDP outbound (simple and XUDP) ->
  TLS -> VLESS UDP inbound (command `2` and XUDP command `3`) -> direct UDP
  echo.
- Unit: XUDP New/Keep frame roundtrip and address encoding.
- Local interop with Xray-core 26.11.9: TCP in both directions; UDP/XUDP in
  both directions.
- Local-only interop: the TLS adapter and VLESS-over-TLS request/response were
  checked against a Python/OpenSSL TLS echo and VLESS mock. The harness is not
  committed.
- Fixtures: `tests/fixtures/vless/request_ipv4.bin` and
  `tests/fixtures/vless/xudp_new.bin` are synthetic, spec-derived inputs (no
  captured traffic).
- Fuzz targets: `vless_request` and `xudp_frame` under `zig build fuzz`; the
  short corpus smoke runs in `zig build test`. See `docs/security/audit.md`.
- No reference-implementation interop has been recorded in the repository.
