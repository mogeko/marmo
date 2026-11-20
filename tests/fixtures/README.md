# Test and fuzz fixtures

Every fixture here is synthetic. It was constructed for this repository from
the public protocol specifications recorded in `docs/protocols/`; nothing is a
capture of real traffic. The fixtures contain no credentials, real UUIDs, or
private keys. `tls/cert.pem` is a deliberately invalid certificate block used
to exercise the PEM decoder, not a usable certificate.

Fixtures are embedded by `tests/fuzz.zig` at compile time and run as the
deterministic corpus smoke test in `zig build test`. Long fuzz runs use the
same targets with generated inputs:

```sh
zig build fuzz -Dfuzz-iterations=2000 -Dfuzz-seed=4660
```

| Directory | Files | Purpose |
| --- | --- | --- |
| `tls/` | `client_hello.bin`, `client_hello_record.bin`, `record_appdata.bin`, `cert.pem` | Handshake parser, record framing, truncated AEAD record, PEM decoder |
| `vless/` | `request_ipv4.bin`, `xudp_new.bin` | VLESS request header and XUDP New frame |
| `trojan/` | `auth_line.bin`, `request_ipv4.bin`, `udp_packet.bin` | Trojan authentication line, CONNECT request, UDP frame |
| `shadowsocks2022/` | `tcp_request.bin`, `udp_packet.bin` | Malformed/random AEAD inputs for the request and datagram decoders |
| `socks5/` | `greeting.bin`, `connect_ipv4.bin`, `udp_request.bin` | Greeting, CONNECT address, UDP request header |
| `http/` | `connect.txt`, `forward.txt` | CONNECT and absolute-form forward request heads |
| `config/` | `valid.json`, `malformed.json` | JSON parser and validator smoke inputs |

License: the fixtures are original works generated for this repository and are
covered by the repository's MIT OR Apache-2.0 license (ADR-0020).
