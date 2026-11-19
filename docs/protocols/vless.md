# VLESS

Source: the VLESS protocol as documented by XTLS/Xray-core and V2Fly
(<https://xtls.github.io/en/config/protocols/vless.html>,
<https://github.com/v2fly/v2ray-core/blob/master/common/protocol/headers.go>),
retrieved 2026-11-19. TLS record details come from RFC 8446. The client uses
`std.crypto.tls.Client`; the server is the in-tree TLS 1.3 implementation in
`packages/tls13`.

## Implemented

- VLESS outbound and inbound; TCP command `1`, simple UDP command `2`, and
  Xray-compatible XUDP command `3`.
- Outbound transport is optional TLS 1.2/1.3 via `std.crypto.tls.Client`.
- Inbound transport is mandatory TLS 1.3 via `packages/tls13`; the accepted
  TCP stream is wrapped before the VLESS header is parsed.
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
  - `uuid` and `tls` are rejected on other outbound/inbound protocols.
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
    verified because `std.crypto.tls.Client` couples SNI and host verification;
    use a trusted certificate for full SNI behavior.
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
      }
    }
  ],
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "vless",
      "server": "example.com:443",
      "uuid": "00112233-4455-6677-8899-aabbccddeeff",
      "tls": { "sni": "cdn.example.com" },
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
- The inbound listener has no explicit TLS handshake timeout; cancellation
  comes from the `Io.Group` that owns the connection.
- No request addons are generated; response addons are skipped. No
  `flow`/XTLS Vision.
- No WebSocket, HTTP/2, or gRPC transport; only TCP and TLS.
- One request per stream and no multiplexing (Mux.Cool).
- The outbound TLS handshake has no explicit timeout; cancellation comes from
  the `Io.Group` that owns the connection. Add a bounded handshake timeout with
  the health-check/jitter work.
- No custom CA file or pinning yet for the outbound; verification uses the host
  bundle or `insecure`.
- Certificate verification and SNI cannot be configured independently because
  of the `std.crypto.tls.Client` API.
- Concurrent TLS writes and `shutdown(.send)` are serialized. A relay abort
  (`shutdown(.both)`) closes the transport without sending `close_notify` so it
  cannot race with a writer. A server-initiated TLS 1.3 `KeyUpdate` handled by
  the read path is not synchronized with a concurrent write; the in-tree TLS
  record layer planned with the server will own this state and remove the gap.
- No anti-probing or replay behavior beyond what TLS provides.

## Tests

- Unit: UUID parsing, request-header encoding for IPv4/domain/IPv6, tiny-buffer
  rejection.
- Integration: SOCKS5 CONNECT -> VLESS over plain TCP -> mock VLESS server ->
  echoed payload, with the mock server validating UUID, command, port, and
  address.
- Integration: a TLS VLESS outbound against a listener that closes immediately;
  the handshake failure is reported as a SOCKS5 failure reply.
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
- Fixtures: none yet. No reference-implementation interop has been recorded.
