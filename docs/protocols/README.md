# Protocol notes

One file per proxy protocol, named after the lower-case protocol
(`shadowsocks.md`, `vless.md`, ...).

Record:

- The specification or documentation used, with the revision or date consulted.
- Known ambiguities and how real clients behave.
- Cipher/auth details and the exact key schedule.
- TCP and UDP framing, including the maximum datagram size.
- Synthetic test vectors used by unit tests and the fuzz corpus.
- Interop results against self-hosted reference implementations.

Rules:

- Do not paste code from GPL/AGPL/MPL projects. Specs and behavior notes only
  (ADR-0009).
- Never commit credentials, UUIDs, private keys, or captures of real traffic.
- If behavior is inferred rather than specified, say so explicitly.
- These notes are language-neutral: they describe the wire protocol, not the
  Rust implementation. Implementation status lives in
  [`../architecture.md`](../architecture.md) §12.

## Current files

| File | Status |
| --- | --- |
| [shadowsocks.md](shadowsocks.md) | Live: SS2022 spec, key schedule, limits, interop |
| [trojan.md](trojan.md) | Live: TLS framing, UDP, fallback, interop |
| [vless.md](vless.md) | Live: TCP/UoT/XUDP/Mux.Cool framing, transport object, limits |
| [vmess.md](vmess.md) | Live: AEAD schedule, chunks, UDP, Mux.Cool, interop |

TLS, HTTP/2, and WebSocket are provided by `rustls`, `h2`, and `ws-net`; their
own documentation is the source for parser behavior. See
[`../architecture.md`](../architecture.md) §13.
