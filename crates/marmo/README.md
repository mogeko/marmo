# marmo

An embeddable Rust library for TCP/UDP proxying: L4/L7 inbounds, multiple proxy
protocols, rule-based routing, and latency-aware outbound selection.

`marmo` is the facade crate. `Config` is the strict JSON schema and `Instance`
is the composition root: build, bind, serve, then shut down. The library never
creates or shuts down a runtime and never installs process-level signal
handlers; you supply the tokio context.

**Version 0.0.3.** The API may change between minor versions while the crate is
pre-1.0.

## Features

- **Inbounds:** SOCKS5 (CONNECT and UDP ASSOCIATE), HTTP CONNECT and forward
  proxying, Shadowsocks 2022, Trojan, VLESS, and VMess (AEAD, TCP/UDP,
  Mux.Cool termination).
- **Outbounds:** direct, HTTP CONNECT, Shadowsocks 2022, Trojan, VLESS, VMess,
  and selectors with manual, round-robin, random, fallback, and least-latency
  strategies plus health probes.
- **Transports:** TCP, TLS 1.3 (`rustls`), WebSocket (`ws-net`), and HTTP/2
  (`h2`). VLESS supports TCP, simple UoT, and XUDP; VMess supports TCP, direct
  UDP, and Mux.Cool termination, both over TCP, TLS, WebSocket, and HTTP/2.
- **Routing:** exact and suffix domains, IP CIDR, destination port, and network.
- **Limits:** global connection cap plus handshake, idle, and half-close
  timeouts.
- **Metrics:** connection, byte, timeout, UDP-session, and health-probe counters
  with an optional `MetricsSink`.

## Example

```rust
use std::time::Duration;

#[tokio::main(flavor = "current_thread")]
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

`serve` runs until shutdown. Use `serve_with_shutdown` with a future such as
your own `CancellationToken::cancelled()`; take `Instance::handle` before
`serve` for the shutdown trigger and metric snapshots.

## Configuration

Configuration is schema version 2 and is parsed strictly: unknown fields, a
wrong version, and out-of-range values are errors reported with a JSON path.
TLS credentials are inline PEM. See the
[configuration reference](https://github.com/mogeko/marmo/blob/master/docs/architecture.md)
for the full schema.

Runnable examples live in
[`crates/marmo/examples/`](https://github.com/mogeko/marmo/tree/master/crates/marmo/examples):

```sh
cargo run -p marmo --example socks5 -- 127.0.0.1:1080
cargo run -p marmo --example vless -- client 127.0.0.1:1080 127.0.0.1:443 UUID tcp /
```

## Workspace

| Crate | Role |
| --- | --- |
| `marmo` | This crate: public facade |
| [`marmo-proto`](https://crates.io/crates/marmo-proto) | Wire codecs; no I/O, no tokio |
| [`marmo-net`](https://crates.io/crates/marmo-net) | Endpoints, CIDR, and network types |
| [`marmo-transport`](https://crates.io/crates/marmo-transport) | Streams, TLS/WS/H2 layers, relay |

## License

Licensed under either of [MIT] or [Apache-2.0] at your option.

[MIT]: https://github.com/mogeko/marmo/blob/master/LICENSE-MIT
[Apache-2.0]: https://github.com/mogeko/marmo/blob/master/LICENSE-APACHE
