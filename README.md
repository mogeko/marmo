# marmo

An embeddable Rust library for TCP/UDP proxying: L4/L7 inbounds, multiple
proxy protocols, rule-based routing, and latency-aware outbound selection.

**Version:** 0.0.3 (unreleased; API may change between minor versions.)

## Features

- Inbounds: SOCKS5 (CONNECT and UDP ASSOCIATE), HTTP CONNECT and forward
  proxying, Shadowsocks 2022, Trojan, VLESS, and VMess (AEAD, TCP/UDP,
  Mux.Cool termination).
- Outbounds: direct, HTTP CONNECT, Shadowsocks 2022, Trojan, VLESS, VMess,
  and selectors with manual, round-robin, random, fallback, and least-latency
  strategies.
- Transports: TCP, TLS 1.3 (`rustls`), WebSocket (`ws-net`), and HTTP/2 (`h2`).
  VLESS supports TCP, simple UoT, XUDP, and Mux.Cool; VMess supports TCP,
  direct UDP, and Mux.Cool. `mux: true` enables client-side pooling for both,
  over TCP, TLS, WebSocket, and HTTP/2.
- Routing: exact and suffix domains, IP CIDR, destination port, and network.
- Limits: global connection cap plus handshake, idle, and half-close timeouts.
- Metrics: connection, byte, timeout, UDP-session, and health-probe counters
  with an optional `MetricsSink`.
- Strict JSON configuration, schema version 2. TLS credentials are inline PEM.

## Workspace

| Crate             | Purpose                                                                  |
| ----------------- | ------------------------------------------------------------------------ |
| `marmo`           | Public facade: `Instance`, config, routing, inbounds, outbounds, metrics |
| `marmo-proto`     | HTTP/1, SOCKS5, SS2022, Trojan, VLESS, VMess, Mux; no I/O          |
| `marmo-net`       | `Endpoint`, CIDR, and `Network`                                          |
| `marmo-transport` | Stream traits, TLS/WS/H2 layers, and the relay                           |

## Example

```rust
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = marmo::Config::from_json(r#"{
      "inbounds": [
        { "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:1080" }
      ],
      "outbounds": [
        { "tag": "direct", "protocol": "direct" }
      ],
      "route": { "final": "direct" }
    }"#)?;

    let instance = marmo::Instance::builder(config)
        .shutdown_grace(Duration::from_secs(10))
        .build()?;

    instance.serve().await?;
    Ok(())
}
```

Runnable examples live in [`crates/marmo/examples/`](crates/marmo/examples/):

```sh
cargo run -p marmo --example socks5 -- 127.0.0.1:1080
cargo run -p marmo --example vless -- client 127.0.0.1:1080 127.0.0.1:443 UUID tcp /
cargo run -p marmo --example vmess -- client 127.0.0.1:1080 127.0.0.1:8443 UUID tcp
```

## Development

MSRV is Rust 1.87. The workspace uses edition 2024.

```sh
cargo test --workspace --locked
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo +nightly fuzz build
```

Protocol tests are in `crates/*/tests/`, unit tests beside the code, and fuzz
targets in [`fuzz/`](fuzz/). CI runs Linux, macOS, and Windows, the MSRV job,
the dependency audit, and a bounded fuzz smoke.

See [docs/architecture.md](docs/architecture.md) for the design,
[docs/roadmap.md](docs/roadmap.md) for the dependency-ordered phases, and
[docs/decisions/](docs/decisions/) for the ADR record. Workspace rules are in
[crates/README.md](crates/README.md).

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at
your option.
