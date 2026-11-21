# marmo-transport

Stream traits, transport layers, and the bidirectional relay used by [marmo].

A transport layer wraps a stream and returns a stream, so the proxy core never
sees TLS records, WebSocket frames, or HTTP/2 DATA frames. Layers are built from
config at startup and applied in order, which keeps the hot path to plain byte
copies over [`BoxStream`].

## Items

| Item | Purpose |
| --- | --- |
| `AsyncStream`, `BoxStream` | Duplex, ordered bytes with half-close support |
| `Layer`, `LayerError` | Object-safe layer applied to client and server streams |
| `tls` | TLS 1.3 client and server on `rustls` with platform verification |
| `ws` | WebSocket client and server on `ws-net`, including permessage-deflate |
| `h2` | HTTP/2 client and server on `h2` |
| `relay` | Bidirectional copy with byte counters, idle deadline, and half-close grace |

The concrete adapters are `TlsClient`/`TlsServer`, `WsClient`/`WsServer`, and
`H2Client`/`H2Server`. TLS, HTTP/2, and WebSocket come from upstream crates;
nothing is forked.

## Example

```rust
use marmo_transport::{BoxStream, RelayOptions, relay};

// `client` and `remote` are the two ends of one proxied connection.
async fn bridge(
    client: BoxStream,
    remote: BoxStream,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let stats = relay(client, remote, RelayOptions::default()).await?;
    Ok(stats.client_to_remote + stats.remote_to_client)
}
```

`relay` reports bytes in each direction even when the future is dropped on
shutdown, idle timeout, or half-close. For counters that outlive the call, use
`relay_with_counters` and keep the `RelayCounters` handle.

## Rules

- `AsyncStream` is a bound over `AsyncRead + AsyncWrite`, not a bespoke vtable;
  any tokio stream works.
- Unsafe is denied by default; a block needs a written justification and a
  safety comment.
- No feature flag selects a backend or transport implementation.
- TLS credentials are passed as inline PEM or DER; the crate never reads files.

## License

Licensed under either of [MIT] or [Apache-2.0] at your option.

[marmo]: https://github.com/mogeko/marmo
[`BoxStream`]: https://docs.rs/marmo-transport/latest/marmo_transport/type.BoxStream.html
[MIT]: https://github.com/mogeko/marmo/blob/master/LICENSE-MIT
[Apache-2.0]: https://github.com/mogeko/marmo/blob/master/LICENSE-APACHE
