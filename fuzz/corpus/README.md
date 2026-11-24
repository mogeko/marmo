# Corpus provenance

Seeds under `corpus/<target>/` are synthetic. They are either hand-written from
a public specification, produced by a deterministic encoder with fixed keys and
timestamps, or shared with the golden fixtures under
`crates/marmo-proto/tests/fixtures/`.

| Target | Seeds | Origin |
| --- | --- | --- |
| `http` | `connect`, `forward`, `response` | RFC 9112 heads, hand-written |
| `socks5` | `greeting`, `connect`, `udp`, `fixture-*` | RFC 1928, hand-written |
| `ss2022_tcp` | `request-*`, `response-*`, `chunk-*`, `fixture-seed` | Encoder-produced with fixed PSK/salt/timestamp |
| `ss2022_udp` | `packet-*`, `fixture-seed` | Encoder-produced with fixed PSK/session/packet id |
| `trojan` | `auth`, `request`, `udp`, `fixture-*` | Spec hand-written, plus the golden fixtures |
| `vless` | `request`, `response`, `mux`, `uot`, `fixture-request` | Spec hand-written and encoder-produced |
| `vmess` | `request`, `response`, `chunk`, `mux`, `fixture-*` | Encoder-produced with fixed keys/timestamps, plus hand-written metadata and the golden fixtures |
| `mux` | `new-tcp`, `keep-udp`, `end`, `keepalive`, `new-tcp.frame` | Golden fixtures under `crates/marmo-proto/tests/fixtures/mux/` |
| `sniff` | `tls-sni`, `http-host`, `h2-authority` | Spec-derived synthetic prefixes |

None is a capture of real traffic. libFuzzer may write minimised inputs into a
corpus directory during a run; do not commit those.

The differential interop records live in
[`../../docs/protocols/interop.md`](../../docs/protocols/interop.md).
