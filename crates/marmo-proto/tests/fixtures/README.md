# Protocol fixtures

Golden wire images for the `marmo-proto` codecs. Each fixture is consumed by
`crates/marmo-proto/tests/fixtures.rs`, which checks both the decoder result and
the deterministic encoder output where one exists.

These are synthetic, spec-derived vectors. None is a capture of real traffic,
and no reference binary or GPL/AGPL/MPL code is involved. Crypto fixtures use
fixed keys, IVs, timestamps, and nonces so they are reproducible:

| Codec | Fixture | Provenance |
| --- | --- | --- |
| HTTP/1 | `http/request-connect.http` | RFC 9112 CONNECT request, hand-written |
| HTTP/1 | `http/request-forward.http` | RFC 9112 absolute-form request, hand-written |
| HTTP/1 | `http/response-connect.http` | RFC 9112 200 response, hand-written |
| SOCKS5 | `socks5/greeting.bin` | RFC 1928 greeting, hand-written |
| SOCKS5 | `socks5/connect-ipv4.bin` | RFC 1928 IPv4 CONNECT, hand-written |
| SOCKS5 | `socks5/connect-domain.bin` | RFC 1928 domain CONNECT, hand-written |
| SOCKS5 | `socks5/udp-ipv4.bin` | RFC 1928 UDP request, hand-written |
| SS2022 | `shadowsocks/tcp-request.bin` | `encode_client_request`, fixed PSK/salt/timestamp/padding |
| SS2022 | `shadowsocks/udp-packet.bin` | `encode_udp_packet`, fixed PSK/session/packet id/timestamp |
| Trojan | `trojan/auth.bin` | SHA-224 of `password` plus CRLF, hand-written from the spec |
| Trojan | `trojan/request-ipv4.bin` | Spec request header for 1.2.3.4:443, hand-written |
| Trojan | `trojan/udp-ipv4.bin` | Spec UDP frame header plus `hello`, hand-written |
| VLESS | `vless/request-ipv4.bin` | Spec request header for 1.2.3.4:443, hand-written |
| VLESS | `vless/request-domain.bin` | Spec request header for example.com:443, hand-written |
| VLESS | `vless/mux-request.bin` | Spec mux command request, hand-written |
| VLESS | `vless/uot-frame.bin` | UoT length-prefixed frame, hand-written |
| VMess | `vmess/request.bin` | `encode_request`, fixed UUID/secrets/timestamp/padding |
| VMess | `vmess/response.bin` | `encode_response` over the fixed request |
| VMess | `vmess/chunk.bin` | `ChunkEncoder`, fixed body key/IV/masking/padding |
| Mux.Cool | `mux/new-tcp.meta` | `encode_new_meta`, fixed session/target |
| Mux.Cool | `mux/new-tcp.frame` | `encode_header` plus `hello mux` |
| Mux.Cool | `mux/keep-udp.meta` | `encode_keep_meta`, fixed per-packet target |
| Mux.Cool | `mux/end.meta` | `encode_end_meta` |
| Mux.Cool | `mux/keepalive.meta` | `KEEPALIVE_META` |

Differential interop results against reference implementations are recorded in
[`../../../../docs/protocols/interop.md`](../../../../docs/protocols/interop.md); the
fixtures above do not depend on those binaries being present.
