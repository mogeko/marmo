# Trojan

Source: the Trojan protocol as documented by trojan-gfw
(<https://trojan-gfw.github.io/trojan/protocol>, retrieved 2026-11-19), the
SOCKS5 address format in RFC 1928, and SHA-224 in FIPS 180-4. The in-tree TLS
1.3 server in `packages/tls13` terminates inbound TLS; outbound TLS uses
`std.crypto.tls.Client` through the root adapter.

## Implemented

- Trojan inbound and outbound; TCP `CONNECT` (`0x01`) and UDP `ASSOCIATE`
  (`0x03`).
- Inbound transport is mandatory TLS 1.3. Outbound configuration also requires
  a `tls` object; plaintext Trojan is not exposed by the config schema.
- Authentication is `hex(SHA224(password)) | CRLF`: 56 lower-case hex bytes,
  compared with `std.crypto.timing_safe.eql`. The password hash is computed at
  `Instance.init`; the plaintext password is not stored by the protocol layer.
- The request is `CMD | ATYP | DST.ADDR | DST.PORT | CRLF` using the SOCKS5
  address types: `0x01` IPv4, `0x03` domain, `0x04` IPv6. A domain is 1-255
  bytes; the port is big-endian.
- There is no response header. After the request, both directions are raw
  payload bytes.
- UDP uses one frame per datagram:
  `ATYP | DST.ADDR | DST.PORT | Length (2B BE) | CRLF | Payload`.
  Every frame carries its own address, so one association can switch
  destinations. Server-to-client frames carry the source address.
- The first TCP write is coalesced with the request header when the stream
  layer provides a single buffer; a read that happens first sends the header
  alone. A mutex/atomic pair prevents a concurrent read and write from sending
  the header twice.
- Inbound UDP routes each datagram independently. The first accepted datagram
  selects the outbound tag; later datagrams that select a different tag are
  dropped, matching SOCKS5 UDP ASSOCIATE. A single `PacketConn` may send to
  multiple destinations when the selected outbound supports it (direct and
  Trojan; VLESS simple UoT rejects changes).
- Zero-length UDP datagrams are dropped in both directions.
- Authentication failure with a configured `fallback` endpoint replays the
  consumed prefix to a routed TCP connection and relays the rest (ADR-0011).
  A non-hex byte in the would-be hash stops the prefix read immediately, so a
  short HTTP probe does not wait for 58 bytes. Without `fallback`, the
  connection is closed.
- A valid authentication followed by a malformed request is a protocol error
  and closes the connection; it does not enter fallback.
- The consumed prefix is at most 58 bytes. Only that prefix is buffered for the
  fallback path; no payload is logged.
- Strict config validation:
  - inbound `password` is required and non-empty;
  - inbound `tls` is required, with non-empty certificate and private-key
    paths and a positive `handshake_timeout_s`;
  - inbound `fallback` is optional, must parse as `host:port`, and is rejected
    on other protocols;
  - outbound `server` and `password` are required;
  - outbound `tls` is required; `tls.sni` is required for an IP `server` when
    verification is enabled;
  - `method`, `uuid`, and `xudp` are rejected on Trojan outbounds;
  - `handshake_timeout_s` defaults to 10 and must be positive.

## Config example

```json
{
  "inbounds": [
    {
      "tag": "trojan-in",
      "protocol": "trojan",
      "listen": "0.0.0.0:443",
      "password": "change-me",
      "fallback": "127.0.0.1:8080",
      "tls": {
        "certificate": "server-cert.pem",
        "private_key": "server-key.pem"
      }
    }
  ],
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "trojan",
      "server": "example.com:443",
      "password": "change-me",
      "tls": { "sni": "example.com" }
    }
  ],
  "route": {
    "rules": [
      { "ip_cidr": ["127.0.0.1/32"], "outbound": "direct" }
    ],
    "final": "proxy"
  }
}
```

The fallback target follows normal routing. This example sends loopback
fallback traffic to the implicit `direct` outbound and everything else to the
Trojan outbound. Do not route the Trojan inbound tag back to a Trojan outbound
that points at the same listener.

## Limits and known gaps

- No Trojan-Go WebSocket, Mux, XTLS, or other extensions. No multiplexing; one
  request per stream.
- No plaintext Trojan inbound or outbound configuration. Tests may construct
  the outbound struct directly with a plain transport; the public config does
  not.
- The in-tree TLS 1.3 server supports X25519, AES-128-GCM/SHA-256, and ECDSA
  P-256 certificates only. It has no TLS 1.2, RSA certificates, ALPN, client
  auth, session tickets, KeyUpdate, or 0-RTT. Trojan clients that require TLS
  1.2 or ALPN cannot interoperate.
- The authentication prefix read has no protocol-level timeout. A peer that
  completes TLS and then stalls can hold a connection until the embedder closes
  it. This is the same class as the open inbound timeout finding in
  `docs/security/audit.md`.
- The fallback path is routed and therefore can loop if the operator routes
  the Trojan inbound tag to a proxy outbound that points back at the same
  listener. Configuration is trusted; there is no runtime loop detector.
- A listener without `fallback` closes on authentication failure and remains
  distinguishable from a standard Trojan server.
- UDP frames are limited to 65535 bytes, further limited by the OS UDP maximum.
  The library does not fragment.
- UDP replies report the source address from the server frame. The inbound
  forwards it to the client; it does not verify that the source matches the
  original destination.
- No custom CA file or certificate pinning for the outbound; verification uses
  the host CA bundle or `insecure`, as with VLESS.
- No Trojan-specific metrics beyond the shared connection/byte/UDP counters.

## Tests

- Unit: SHA-224 vectors, request encoding for IPv4/domain/IPv6, truncation at
  every prefix, authentication match/mismatch/partial reads, early non-hex
  fallback detection, UDP frame roundtrip and oversized payload.
- Unit: fallback routing calls `Dispatch`, a `reject` action does not connect,
  and a valid authentication followed by a malformed request closes without
  fallback.
- Integration: SOCKS5 -> Trojan outbound over TLS -> Trojan inbound over TLS
  -> direct TCP echo, including the in-tree TLS 1.3 server.
- Integration: SOCKS5 UDP ASSOCIATE -> Trojan UDP association over TLS, with
  two destinations in one association.
- Integration: an unauthenticated HTTP probe over TLS reaches a routed
  fallback HTTP service and receives its response.
- Fuzz: `trojan_auth`, `trojan_request`, and `trojan_udp_frame` under
  `zig build fuzz`; deterministic corpus smoke in `zig build test`.
- Fixtures: `tests/fixtures/trojan/auth_line.bin`,
  `request_ipv4.bin`, and `udp_packet.bin` are synthetic, spec-derived inputs
  (no captured traffic).
- Standalone example: `examples/trojan/` runs a server and a SOCKS5 client,
  with an optional fallback HTTP service for local probes.

## Interop

Local, self-hosted checks only. Reference binaries, configs, certificates, and
the harness are not committed and are not part of CI.

### Xray-core 26.11.9 (darwin/arm64)

- Xray SOCKS client -> marmo Trojan server over TLS -> direct TCP: passed.
- Xray SOCKS UDP client -> marmo Trojan server -> direct UDP: passed.
- marmo SOCKS client -> Xray Trojan server over TLS -> direct TCP: passed.
- marmo SOCKS UDP client -> Xray Trojan server -> direct UDP: passed.
- Xray 26 warns that Trojan without Flow is deprecated; the wire behavior is
  still the standard Trojan protocol.
- The Xray client used `pinnedPeerCertSha256` from `xray tls hash --cert
  cert.pem` against the local self-signed ECDSA P-256 certificate. The Xray
  server needed `finalRules` to allow loopback targets for this local setup.

### trojan-gfw 1.16.0 (macOS x86_64 under Rosetta 2)

- trojan-gfw SOCKS client -> marmo Trojan server over TLS: TCP and UDP passed.
- marmo SOCKS client -> trojan-gfw server over TLS: TCP and UDP passed.
- Both sides used a self-signed ECDSA P-256 certificate for `localhost`.
  trojan-gfw used `verify: false` (client) and `--insecure` (marmo client).
- Both directions set `"alpn": []`; the in-tree TLS 1.3 server does not
  negotiate ALPN.
- The trojan-gfw server used `cipher_tls13: TLS_AES_128_GCM_SHA256`, matching
  the in-tree server and the std TLS client.
- The trojan-gfw client sends UDP ASSOCIATE to `0.0.0.0:0` when talking to the
  marmo server. marmo routes the first datagram, so the association works.
- A local check exposed a TLS client bug: a partial TLS record could be
  reported as EOF by `packages/tls13/src/reader.zig`, which lost a
  trojan-gfw UDP reply split across TCP reads. `readSome` now waits for a
  complete record and has a regression test. This affects all TLS-client
  streams, not just Trojan.

No live third-party servers were used. The reference implementations are
GPL-3.0/MPL-2.0; only their published behavior was exercised, and no code or
binary is committed (ADR-0009).
