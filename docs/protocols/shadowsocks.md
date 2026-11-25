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
  outbound UDP socket and reply task, last-seen client address, idle eviction
  (never shorter than 60 seconds), and a sliding replay window.
- UDP client: one client session ID and packet counter per association,
  server-session tracking, and response replay window.
- Server checks timestamps within 30 seconds for TCP requests and UDP packets.
  TCP request salts are rejected for 60 seconds with a bounded in-memory cache;
  UDP packets outside the timestamp window are dropped before any session or
  replay-window state is created. The UDP client applies the same timestamp
  check to server packets.
- Request padding is 1..64 bytes; the server rejects a request with neither
  padding nor initial payload.
- AES-128/256-GCM uses the `aes-gcm` crate; BLAKE3 uses `blake3`. No handwritten primitives.

## Limits and known gaps

- Optional ChaCha20-Poly1305 methods are not implemented; config rejects them.
- Anti-probing behavior on malformed TCP headers (the spec's "do not reveal
  consumed byte count" requirement) is not implemented.
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
- Reference interop: verified locally against shadowsocks-rust 1.25.0, TCP/UDP
  in both directions; the harness is intentionally not committed.
- Golden SS2022 TCP/UDP fixtures live in
  `crates/marmo-proto/tests/fixtures/shadowsocks/`; synthetic malformed request
  and datagram bytes live in `fuzz/corpus/ss2022_*`. The mutation targets feed
  raw ciphertext, so most mutations stop at the AEAD open; the encoder-produced
  seeds reach the post-auth address/padding/length parsers. Authenticated-input
  fuzzing remains future work and the encoders/decoders also have unit and
  fixture round-trip tests.
- Differential results against shadowsocks-rust are recorded in
  [`interop.md`](interop.md).
- Fuzz targets: `ss2022_tcp` and `ss2022_udp` under `cargo +nightly fuzz run`.
  The bounded corpus smoke runs in the `Fuzz` workflow. See
  `docs/security/audit.md`.
- Add captured reference transcripts for offline CI when their provenance and
  license can be recorded.
