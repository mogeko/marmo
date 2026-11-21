# Decoder fuzz targets

`cargo-fuzz` targets for the `marmo-proto` decoders. Nightly only; the library
stays on stable.

```sh
cargo +nightly fuzz run ss2022_tcp -- -runs=20000 -max_len=4096
cargo +nightly fuzz run http -- -runs=20000 -max_len=8192
cargo +nightly fuzz run ss2022_udp -- -runs=20000 -max_len=4096
cargo +nightly fuzz run socks5 -- -runs=20000 -max_len=4096
cargo +nightly fuzz run trojan -- -runs=20000 -max_len=4096
cargo +nightly fuzz run vless -- -runs=20000 -max_len=4096
cargo +nightly fuzz run xudp -- -runs=20000 -max_len=4096
```

Long runs use the same targets with wall-clock limits, e.g.
`cargo +nightly fuzz run ss2022_tcp -- -max_total_time=300 -max_len=8192`.

The crate is outside the root workspace so `cargo test --workspace` and the
MSRV job never require nightly. CI runs a bounded smoke pass on PRs that change
a codec or the fuzz crate; long runs are manual (`workflow_dispatch` or local)
because a `schedule` would only run from the repository default branch.

## Targets

| Target | Decoders |
| --- | --- |
| `http` | request head, absolute-form target, CONNECT response head |
| `ss2022_tcp` | client request (whole and fixed/variable), server response, length/payload chunks |
| `ss2022_udp` | UDP packet in both directions, packet-id replay window |
| `socks5` | greeting, request, UDP datagram |
| `trojan` | authentication prefix, request headers, UDP frame headers |
| `vless` | request headers, response header, UoT length, address parsing |
| `xudp` | New/Keep/End/Keepalive metadata |

The SS2022 targets take the first byte as the method selector (bit 0: 0 =
`2022-blake3-aes-128-gcm`, 1 = `2022-blake3-aes-256-gcm`); the rest is the wire
input.

## Corpus

`corpus/<target>/` contains synthetic seeds:

- encoder-produced greetings, requests, responses, chunks, UDP packets, and
  XUDP metadata with fixed keys and timestamps;
- the synthetic Zig fixtures from `tests/fixtures/` (`zig-*`).

None is a capture of real traffic. libFuzzer writes newly minimised inputs
into the corpus directory during a run; do not commit those.
