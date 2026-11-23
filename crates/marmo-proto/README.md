# marmo-proto

Wire codecs for the proxy protocols that [marmo] speaks.

`marmo-proto` turns bounded byte slices into typed messages and back. It does
no I/O, starts no runtime, and never blocks: every decoder takes a complete or
partial buffer, checks it before reading, and returns a typed error instead of
panicking. That is what makes each codec fuzzable in isolation.

## Modules

| Module | Contents |
| --- | --- |
| `http` | HTTP/1.1 request head, CONNECT response, absolute-form target, forward head |
| `socks5` | RFC 1928 greeting, request, reply, and UDP datagram codec |
| `shadowsocks` | Shadowsocks 2022 AEAD seal/open, key derivation, address codec, UDP packets, replay window |
| `trojan` | Password hash, request header, and UDP frames |
| `vless` | UUID, request and response headers, UoT frames, and address codec |
| `vmess` | AEAD request/response headers, chunk framing, and key schedule |
| `mux` | Mux.Cool metadata and frame headers for VMess and VLESS |

Crypto is delegated to `aes-gcm`, `chacha20poly1305`, `blake3`, `sha2`,
`sha3` (SHAKE128), `hmac`, and `md-5`; `subtle` handles constant-time
comparisons and secrets are zeroized on drop.

## Example

```rust
use marmo_proto::socks5::{Command, Greeting, Request};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let greeting = Greeting::parse(&[0x05, 0x01, 0x00])?;
    assert!(greeting.accepts_no_auth());

    // CONNECT 127.0.0.1:443
    let request = Request::parse(&[
        0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xbb,
    ])?;
    assert_eq!(request.command, Command::Connect);
    assert_eq!(request.destination.to_string(), "127.0.0.1:443");
    Ok(())
}
```

Address fields reuse the validated types from [`marmo-net`], so a destination
parsed by a codec can be routed without re-parsing a string.

## Rules

- No I/O, no tokio, no global state.
- Every decoder bounds-checks before indexing and returns a `#[non_exhaustive]`
  `thiserror` enum.
- Untrusted input never causes a panic, an unbounded read, or an unbounded
  allocation.
- Every decoder has a golden fixture in `tests/fixtures/` and a fuzz target in
  the repository's `fuzz/` directory.

## License

Licensed under either of [MIT] or [Apache-2.0] at your option.

[marmo]: https://github.com/mogeko/marmo
[`marmo-net`]: https://crates.io/crates/marmo-net
[MIT]: https://github.com/mogeko/marmo/blob/master/LICENSE-MIT
[Apache-2.0]: https://github.com/mogeko/marmo/blob/master/LICENSE-APACHE
