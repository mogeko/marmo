# Protocol notes

One file per proxy protocol, named after the lower-case protocol
(`shadowsocks.md`, `vless.md`, ...). Create it when implementation starts, not
before.

Record:

- The specification or documentation used, with the revision or date consulted.
- Known ambiguities and how real clients behave.
- Cipher/auth details and the exact key schedule.
- TCP and UDP framing, including the maximum datagram size.
- Where captured fixtures live (`tests/fixtures/<protocol>/`) and their
  provenance and license.
- Interop results against self-hosted reference implementations.

Rules:

- Do not paste code from GPL/AGPL/MPL projects. Specs and behavior notes only
  (ADR-0009).
- Never commit credentials, UUIDs, private keys, or captures of real traffic.
- If behavior is inferred rather than specified, say so explicitly.

## Current files

| File | Status |
| --- | --- |
| [shadowsocks.md](shadowsocks.md) | Live: SS2022 spec, key schedule, limits, interop |
| [trojan.md](trojan.md) | Live: TLS framing, UDP, fallback, interop |
| [vless.md](vless.md) | Live: TCP/UoT/XUDP framing, transport object, limits |

These notes are language-neutral: they describe the wire protocol, not the Zig
or Rust implementation. The implementation status lives in
[`../architecture.md`](../architecture.md) §12.

## Archived transport notes

The in-tree TLS, HTTP/2, and WebSocket implementations are deleted under
ADR-0018 and replaced by `rustls`, `h2`, and `ws-net`. Their
implementation notes are archived:

- [tls.md](../archive/protocols/tls.md)
- [http2.md](../archive/protocols/http2.md)
- [websocket.md](../archive/protocols/websocket.md)

Transport choices and versions are recorded in
[`../architecture.md`](../architecture.md) §13. Do not recreate a protocol note
for a crate we do not implement; the crate's own documentation is the source.
