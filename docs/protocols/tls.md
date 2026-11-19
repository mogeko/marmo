# TLS 1.3

Sources consult: [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)
(TLS 1.3), [RFC 8448](https://www.rfc-editor.org/rfc/rfc8448) (example
handshake traces), and the Zig 0.17.1 `std.crypto.tls.Client` API for the
client half. The server half is implemented in `packages/tls13` (ADR-0007,
ADR-0010).

## Implemented scope

- TLS 1.3 only (`supported_versions` must advertise `0x0304`).
- Cipher suite `TLS_AES_128_GCM_SHA256` (`0x1301`).
- Key exchange group `x25519` (`0x001d`), signature
  `ecdsa_secp256r1_sha256` (`0x0403`).
- Server handshake: ClientHello, ServerHello, middlebox-compatibility CCS,
  EncryptedExtensions, Certificate, CertificateVerify, Finished, client
  Finished verification, and `close_notify`.
- Record protection: AES-128-GCM, 12-byte per-direction nonce XORed with a
  64-bit sequence number, 16-byte tag, maximum plaintext 16 KiB, maximum
  ciphertext 16 KiB + 256.
- Key schedule: HKDF-SHA256 with `HKDF-Expand-Label`, transcript hashes, and
  constant-time Finished comparison.
- Certificate/key loading from PEM `CERTIFICATE` blocks or DER, and a PKCS#8
  or SEC1 ECDSA P-256 private key. The leaf must be P-256 and match the key.

No client authentication, PSK, session tickets, HelloRetryRequest, ALPN
selection, 0-RTT, or KeyUpdate is implemented. A post-handshake KeyUpdate is
rejected as a protocol violation rather than silently ignored.

## Key schedule checks

The labels used are `derived`, `c hs traffic`, `s hs traffic`, `finished`,
`c ap traffic`, `s ap traffic`, `key`, and `iv`. Transcript input is the
handshake message bytes including the 4-byte handshake header; CCS is not part
of the transcript. `std.crypto.tls.Client` supplies the client side, so the
same schedule is checked in both directions by the loopback integration test.

## Fixtures

`tests/fixtures/tls/` contains synthetic inputs constructed from the RFC wire
layout: a ClientHello, a plaintext record containing it, a truncated encrypted
application-data record, and an invalid PEM block. There are no captured
traces and no private keys. Provenance and license are recorded in
`tests/fixtures/README.md`.

## Fuzz targets

`zig build fuzz` exercises `tls_client_hello`, `tls_client_hello_mutated`,
`tls_record_read`, `tls_record_open`, `tls_record_open_valid`,
`tls_record_seal`, `tls_server_handshake`, `tls_server_handshake_mutated`,
`tls_credentials`, and `tls_key_schedule`. The short corpus smoke runs in
`zig build test`; see `docs/security/audit.md`.

## Known gaps

- No KeyUpdate, client auth, PSK/tickets, ALPN, or 0-RTT.
- No post-handshake end-to-end fuzz target: the record codec and handshake
  parser are fuzzed separately, but an authenticated post-handshake stream
  (KeyUpdate, empty records, alert handling) is covered by unit/integration
  tests only.
- No external cryptographic review. The implementation uses `std.crypto`
  primitives only; it does not implement AES, GCM, SHA-256, HKDF, or X25519 by
  hand.
