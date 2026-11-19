# Changelog

## 0.0.1 - 2026-11-19

- Initial release of the first-party TLS package.
- TLS client API over `std.Io.Reader`/`Writer`, with lazy system CA loading.
- In-tree TLS 1.3 server: X25519, AES-128-GCM/SHA-256, ECDSA P-256
  certificates, UUID-agnostic transport API, and `close_notify`.
- `readSome` helper for proxy-style partial reads.
- Package tests for handshake failure, option validation, and a full
  client/server loopback exchange with runtime-generated test certificates.
