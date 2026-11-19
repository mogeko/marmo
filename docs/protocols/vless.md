# VLESS

Source: the VLESS protocol as documented by XTLS/Xray-core and V2Fly
(<https://xtls.github.io/en/config/protocols/vless.html>,
<https://github.com/v2fly/v2ray-core/blob/master/common/protocol/headers.go>),
retrieved 2026-11-19. TLS record details come from RFC 8446. The client uses
`std.crypto.tls.Client`; the server is the in-tree TLS 1.3 implementation in
`packages/tls13`.

## Implemented

- VLESS outbound and inbound, TCP command 1 only.
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
  - `uuid` and `tls` are rejected on other outbound/inbound protocols.
- Request header: version `0`, 16-byte UUID, zero addon length, command `1`,
  big-endian port, address type (`1` IPv4, `2` domain, `3` IPv6), address.
- Response header is read lazily on the first `read`: version `0`, addon
  length, addons. The response payload is passed through unchanged.
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
      "tls": { "sni": "cdn.example.com" }
    }
  ],
  "route": { "final": "proxy" }
}
```

Without a `tls` object the outbound sends VLESS over plain TCP; this is useful
for loopback tests and for deployments that terminate TLS in front of the proxy.
The inbound always requires TLS; plaintext VLESS inbound is not supported.

## Limits and known gaps

- No UDP command 2 on either side; `supports_udp` is false and SOCKS5 UDP
  ASSOCIATE cannot use the outbound.
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
- Local-only interop: the TLS adapter and VLESS-over-TLS request/response were
  checked against a Python/OpenSSL TLS echo and VLESS mock. The harness is not
  committed.
- Fixtures: none yet. No reference-implementation interop has been recorded.
