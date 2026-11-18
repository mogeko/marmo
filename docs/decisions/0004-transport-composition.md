# ADR-0004: Transport composition

- Status: Accepted (2026-11-18)
- Date: 2026-11-18
- Deciders: @mogeko
- Related: ADR-0001, ADR-0002, ADR-0003, ADR-0007

## Context

Proxy protocols are not single wire formats; they are stacks. VLESS or VMess
can run over TCP, TLS, WebSocket, HTTP/2, or gRPC; Trojan always terminates TLS;
TUIC and Hysteria2 require QUIC. Inbounds mirror the same stacks. UDP can be
native (Shadowsocks, TUIC) or tunneled over a stream with per-protocol framing
(VLESS/VMess/Trojan).

Hard-coding one function per protocol/transport combination would duplicate
handshakes and make new transports invasive.

## Decision

Compose transports as nested dialers.

```
Outbound
  -> protocol dialer        (auth/header, returns a tunnel)
    -> transport dialer     (tls | ws | h2 | quic | tcp)
      -> base dialer        (tcp | udp)
```

- A transport implements `Dialer` and wraps another `Dialer`; it returns a
  `Stream` (or `PacketConn` for datagram transports).
- Transport parameters (SNI, ALPN, Host header, path) are supplied at dial time
  from the outbound config, never from globals.
- Inbound stacks mirror the composition with listener wrappers.
- UDP-over-stream framing belongs to the protocol codec, not the transport:
  length-prefixed datagrams with a documented maximum and explicit
  fragmentation policy.
- Sniffing sits above transports and below routing; it buffers consumed bytes
  for replay.

Initial transport set, in dependency order: TCP, TLS (client via
`std.crypto.tls.Client`), WebSocket, HTTP/2, QUIC. Each is implemented in-tree
per ADR-0007; the phase plan gates when it becomes available.

## Alternatives

1. **Per-protocol dial functions** (`dialVlessTlsWs`). Simple initially, but
   combinations grow multiplicatively and share no handshake code.
2. **Transport as a config enum inside each outbound.** Same duplication, plus
   protocol code learns about sockets.
3. **External proxy core** (embed sing-box/Xray). Rejected: license and control.

## Consequences

- Dial order must be validated at config time; cycles and duplicate layers are
  rejected.
- Each layer adds buffering and latency; document recommended buffer sizes and
  avoid double buffering in the relay.
- TLS-in-TLS is allowed but costs; no special casing.
- A protocol that needs early data (VMess/VLESS) must expose the handshake
  boundary so zero-RTT-style optimizations remain possible later.
- QUIC is not a `Stream` over a single socket but a multiplexed endpoint;
  phase 3 needs a `QuicEndpoint` abstraction with per-stream `Stream` adapters.

## Approval

- [x] Accepted 2026-11-18 as recommended.
