# Changelog

## Unreleased

### Added

- ALPN negotiation on the client and server. `Options.alpn_protocols`,
  `ServerOptions.alpn_protocols`, and `negotiatedProtocol()` are available on
  both roles; a non-empty server list with no overlap fails the handshake
  (ADR-0012).
- In-tree TLS 1.3 client with X25519, AES-128-GCM/SHA-256, and ECDSA
  P-256/P-384, Ed25519, and RSA server-certificate verification. It replaces
  `std.crypto.tls.Client`, which cannot send ALPN. The client now rejects
  TLS 1.2-only servers and rejects post-handshake KeyUpdate.
- Package tests for ALPN selection and the client/server handshake path.

### Fixed

- `readSome` now waits for a complete TLS record instead of returning 0 when a
  record is split across reads. Peers that close after sending a record could
  otherwise lose the final application data; found during trojan-gfw UDP
  interop. Added a regression test.

## 0.0.1 - 2026-11-19

- Initial release of the first-party TLS package.
- TLS client API over `std.Io.Reader`/`Writer`, with lazy system CA loading.
- In-tree TLS 1.3 server: X25519, AES-128-GCM/SHA-256, ECDSA P-256
  certificates, UUID-agnostic transport API, and `close_notify`.
- `readSome` helper for proxy-style partial reads.
- Package tests for handshake failure, option validation, and a full
  client/server loopback exchange with runtime-generated test certificates.
