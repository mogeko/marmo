# Shadowsocks 2022

Source: [SIP022 AEAD-2022 Ciphers](https://github.com/shadowsocks/shadowsocks-org/blob/main/docs/doc/sip022.md)
(retrieved 2026-11-18, revision on `main` at that date).

## Implemented

- Methods: `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`.
- TCP request and response streams.
- PSK is base64 in config and decoded to a fixed-length key at startup.
- Session subkey:
  `BLAKE3 derive_key(context="shadowsocks 2022 session subkey",
  key_material=PSK || salt)`.
- 12-byte little-endian nonce counter, one counter per direction.
- Request stream: salt, encrypted fixed header (type 0, timestamp, variable
  length), encrypted variable header (ATYP/address/port, padding length,
  padding, initial payload), then encrypted length/payload chunks.
- Response stream: salt, encrypted fixed header (type 1, timestamp, request
  salt, first payload length), first payload chunk, then length/payload chunks.
- Server checks timestamps within 30 seconds and rejects replayed request salts
  for 60 seconds with a bounded in-memory cache.
- Request padding is 1..64 bytes; the server rejects a request with neither
  padding nor initial payload.
- AES-128/256-GCM uses `std.crypto.aead.aes_gcm`; no handwritten primitives.

## Not implemented yet

- UDP (separate header, session IDs, packet IDs, sliding window, server session
  table).
- Optional ChaCha20-Poly1305 methods.
- Anti-probing behavior on malformed TCP headers (the spec's "do not reveal
  consumed byte count" requirement).
- Interoperability tests against a reference implementation. Current tests are
  self-interop over loopback and must not be treated as proof of wire
  compatibility.

## Tests

- Unit: method/key parsing, AEAD chunk roundtrip, address codec.
- Integration: SOCKS5 -> Shadowsocks 2022 TCP outbound -> Shadowsocks 2022
  inbound -> direct TCP echo, over loopback.
- Fixtures: none yet. Add captured reference transcripts before claiming
  interop.
