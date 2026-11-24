# SOCKS5

Source: RFC 1928 (SOCKS Protocol Version 5), retrieved 2026-11-24. The wire
codec is in `marmo-proto/src/socks5.rs`; the inbound relay state machine is in
`marmo/src/inbound/socks5.rs`.

## Implemented

- Greeting negotiation with the no-authentication method only. A client that
  does not offer `0x00` is rejected with `0xFF`; username/password and GSSAPI
  authentication are not implemented.
- `CONNECT` for IPv4, domain, and IPv6 destinations. The success reply is sent
  only after the outbound connects.
- `UDP ASSOCIATE`: a per-association local UDP relay, one bounded session, with
  the first datagram selecting the outbound. Datagram targets are parsed per
  packet; a later datagram selecting a different outbound tag is dropped.
- No fragmentation: `FRAG != 0` is rejected. The relay buffer is 65,535 bytes;
  replies reserve additional headroom for the SOCKS5 UDP header.
- `BIND` is not implemented and closes the connection without a tunnel.
- Boundaries: one request per TCP connection, strict reserved-byte and
  trailing-data checks, bounded domains, and no domain-to-IP resolution in the
  codec.
- SNI/Host sniffing can fill the routing domain for a CONNECT target that
  supplied only an IP; an inbound-provided domain always wins.

## Known gaps

- No authentication methods beyond no-auth.
- No `BIND` command.
- No FRAG support and no per-datagram outbound switching after the first
  accepted datagram.
- UDP relays are bounded by the fixed association/session model, not by a
  configurable SOCKS5-specific cap.

## Fixtures and tests

- Golden fixtures: `crates/marmo-proto/tests/fixtures/socks5/`.
- Unit: greeting, IPv4/domain/IPv6 requests, UDP datagrams, reply encoding,
  truncation, trailing data, and RFC status codes.
- Fuzz: `socks5` target over greeting, request, and UDP parsing.
- Integration: SOCKS5 CONNECT and UDP ASSOCIATE loopback relay tests.
- Local RFC conformance: curl 8.7.1 `--socks5-hostname` to a local HTTP server
  through a marmo SOCKS5 inbound passed on 2026-11-24 (CONNECT path); UDP
  ASSOCIATE is covered by loopback integration tests. See
  [`interop.md`](interop.md).
