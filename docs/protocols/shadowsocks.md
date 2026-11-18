# Shadowsocks 2022

Source: [SIP022 AEAD-2022 Ciphers](https://github.com/shadowsocks/shadowsocks-org/blob/main/docs/doc/sip022.md)
(retrieved 2026-11-18, revision on `main` at that date).

## Implemented

- Methods: `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`.
- TCP request and response streams.
- UDP client and server sessions.
- PSK is base64 in config and decoded to a fixed-length key at startup.
- Session subkey:
  `BLAKE3 derive_key(context="shadowsocks 2022 session subkey",
  key_material=PSK || salt)`.
- 12-byte little-endian nonce counter, one counter per TCP direction.
- Request stream: salt, encrypted fixed header (type 0, timestamp, variable
  length), encrypted variable header (ATYP/address/port, padding length,
  padding, initial payload), then encrypted length/payload chunks.
- Response stream: salt, encrypted fixed header (type 1, timestamp, request
  salt, first payload length), first payload chunk, then length/payload chunks.
- UDP packet: AES-block-encrypted separate header (session ID, packet ID),
  AEAD body encrypted with the session subkey and the separate-header nonce.
- UDP server: bounded session table keyed by client session ID, per-session
  outbound UDP socket and reply task, last-seen client address, 60-second idle
  eviction, and a sliding replay window.
- UDP client: one client session ID and packet counter per association,
  server-session tracking, and response replay window.
- Server checks timestamps within 30 seconds and rejects replayed request salts
  for 60 seconds with a bounded in-memory cache.
- Request padding is 1..64 bytes; the server rejects a request with neither
  padding nor initial payload.
- AES-128/256-GCM uses `std.crypto.aead.aes_gcm`; no handwritten primitives.

## Limits and known gaps

- Optional ChaCha20-Poly1305 methods are not implemented; config rejects them.
- Anti-probing behavior on malformed TCP headers (the spec's "do not reveal
  consumed byte count" requirement) is not implemented.
- Interoperability tests against a reference implementation are not present.
  Current tests are self-interop over loopback.
- The UDP server routes only to a `direct` outbound. Routing a Shadowsocks UDP
  inbound through another outbound would need a per-session outbound
  `PacketConn`, which is not wired yet.
- The UDP client tracks one current server session; packets from older server
  sessions are not retained.
- UDP padding is zero; the spec allows configurable padding policies.
- The UDP server session table is capped at 128 sessions and drops new sessions
  when full rather than evicting active ones.

## Tests

- Unit: method/key parsing, AEAD chunk roundtrip, address codec, sliding window.
- Integration: SOCKS5 -> Shadowsocks 2022 TCP outbound -> Shadowsocks 2022
  inbound -> direct TCP echo.
- Integration: SOCKS5 UDP ASSOCIATE -> Shadowsocks 2022 UDP outbound ->
  Shadowsocks 2022 UDP server -> direct UDP echo.
- Fixtures: none yet. Add captured reference transcripts before claiming
  interop.
