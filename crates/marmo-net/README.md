# marmo-net

Address and network primitives for [marmo], an embeddable TCP/UDP proxy
library.

`marmo-net` sits at the bottom of the workspace dependency graph. It parses and
validates destinations, CIDR blocks, and the TCP/UDP selector used by routing.
It performs no I/O, starts no runtime, and knows nothing about proxy protocols.

## Types

| Type | Purpose |
| --- | --- |
| `Endpoint` | A host and port: `example.com:443`, `1.2.3.4:443`, `[::1]:443` |
| `Host` | An IP literal or a validated domain |
| `DomainName` | A DNS name checked against the 253-byte wire limit |
| `Cidr` | An IPv4 or IPv6 prefix with `contains` |
| `Network` | `Tcp` or `Udp` |

## Example

```rust
use marmo_net::{Cidr, Endpoint};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint: Endpoint = "example.com:443".parse()?;
    assert_eq!(endpoint.domain(), Some("example.com"));
    assert_eq!(endpoint.port(), 443);

    let private = Cidr::parse("10.0.0.0/8")?;
    assert!(private.contains("10.1.2.3".parse()?));
    assert!(!private.contains("192.168.1.1".parse()?));
    Ok(())
}
```

IPv6 literals must be bracketed (`[::1]:443`); an unbracketed address is
rejected because the port separator would be ambiguous. A host that is not a
valid IPv4 literal is validated as a domain, so `localhost:8080` parses as a
domain rather than failing.

Parsing is strict: a domain cannot be empty, exceed 253 bytes, contain
whitespace or control characters, or contain characters that are illegal in an
authority (`/`, `?`, `#`, `@`, `[`, `]`, `:`). Internationalized names are
accepted as UTF-8; IDNA conversion belongs to the resolver.

## Feature flags

| Feature | Default | Effect |
| --- | --- | --- |
| `serde` | off | `Serialize`/`Deserialize` for `Network` |

## Workspace

| Crate | Role |
| --- | --- |
| `marmo-net` | This crate: addresses and network types |
| [`marmo-proto`](https://crates.io/crates/marmo-proto) | Wire codecs; depends on this crate for address parsing |
| [`marmo-transport`](https://crates.io/crates/marmo-transport) | Streams, TLS/WS/H2 layers, relay |
| [`marmo`](https://crates.io/crates/marmo) | Facade: config, routing, inbounds, outbounds |

## License

Licensed under either of [MIT] or [Apache-2.0] at your option.

[marmo]: https://github.com/mogeko/marmo
[MIT]: https://github.com/mogeko/marmo/blob/master/LICENSE-MIT
[Apache-2.0]: https://github.com/mogeko/marmo/blob/master/LICENSE-APACHE
