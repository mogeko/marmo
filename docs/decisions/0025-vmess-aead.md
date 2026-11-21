# ADR-0025: VMess AEAD, UDP, and Mux.Cool

- Status: Accepted (2026-11-22, expanded from AEAD/TCP-only on request)
- Date: 2026-11-22
- Deciders: @mogeko
- Related: ADR-0009, ADR-0016, ADR-0018, ADR-0022, ADR-0023

## Context

Roadmap P2-7 ("VMess codec and inbound/outbound") is the only deferred Phase 2
item. The Phase 2 gate requires either implementing it or recording an ADR that
moves it out of Phase 2. `docs/architecture.md` §12 lists VMess as future and
states that "legacy CFB is not planned"; ADR-0016 rejects the `transport`
object on every protocol except VLESS. VMess remains deployed by Xray and
V2Ray peers, so the current tree can serve none of them.

VMess has two incompatible header-authentication generations:

- the deprecated MD5 + AES-128-CFB header, which has no integrity protection
  and was explicitly excluded from the roadmap; and
- VMess AEAD: an AES-128-ECB "encrypted auth ID", an AEAD-encrypted instruction
  length, and an AEAD-encrypted instruction, with the body carried as masked
  chunks under AES-128-GCM or ChaCha20-Poly1305.

The protocol details used here are the V2Fly developer specification
(<https://www.v2fly.org/developer/protocols/vmess.html>) and the VMess AEAD
design note (<https://github.com/v2fly/v2fly-github-io/issues/20>), consulted
2026-11-22. The AEAD instruction contains a 16-bit chunk counter, a 16-bit
header length, and a four-bit padding count, so every buffer and counter needs
an explicit bound. Request commands are TCP (`0x01`), UDP (`0x02`), and Mux
(`0x03`, synthetic `v1.mux.cool` target); the Mux command carries Mux.Cool
frames for many logical TCP/UDP sessions over one physical stream.

## Decision (recommended)

Implement VMess AEAD with TCP, direct UDP, and server-side Mux.Cool
termination, behind the existing strict config.

### Codec

Add `marmo_proto::vmess`, a pure codec with no I/O, no tokio, and no ambient
clock or RNG:

- `CmdKey` is derived from the configured UUID
  (`MD5(uuid ++ "c48619fe-8f02-49e0-b9e9-edf763e17e21")`) and is redacted in
  `Debug` and zeroized on drop. MD5 appears only in this spec-mandated key
  derivation; it is not an authentication primitive.
- Request encoding takes caller-generated secrets (connection nonce, body key,
  body IV, response auth value, auth-ID random, padding) so tests and fuzzing
  are deterministic. The `marmo` layer generates them with `getrandom`.
- Request decoding takes `CmdKey` and `now_unix` as arguments; the codec never
  reads the clock.
- The encrypted auth ID is validated by decrypting the single 16-byte AES block,
  checking the CRC32 IEEE field, and accepting a timestamp within 120 seconds of
  `now_unix`. No candidate loop, no fallback, no response on failure.
- The instruction length and instruction are opened with AES-128-GCM using the
  derived key/nonce and `EAuID` as associated data. The instruction length is
  rejected above 317 bytes before any allocation or decryption.
- Body ciphers are AES-128-GCM (`0x03`) and ChaCha20-Poly1305 (`0x04`). Legacy
  CFB (`0x01`), None (`0x05`), Zero (`0x06`), and unknown values are rejected
  with a typed error.
- The standard chunked body is implemented with chunk masking (`M`) and global
  padding (`P`). Basic format (`S` off), the authenticated-length experiment
  (`A`), and unknown option bits are rejected; the deprecated reuse bit (`R`) is
  ignored because it does not change framing. If reference clients are observed
  to enable `A` by default, support is added inside P2-7 and recorded in the
  protocol note.
- The chunk counter is 16 bits. A direction is closed after 65,536 chunks
  (about 1 GiB at the maximum chunk size) so a nonce can never repeat under the
  same key.
- The response header is a four-byte plaintext (response auth value, zero
  option, zero command, zero command length) sealed behind the derived response
  key/IV.

### UDP

The UDP command carries one datagram per chunk: the request header names the
target, the client writes one chunk per datagram, and the server answers with
one chunk per datagram. Empty chunks are skipped. Targets do not change within
a direct UDP association; the outbound rejects a different `send_to` target,
matching VLESS simple UoT.

### Mux.Cool

The Mux command carries a Mux.Cool byte stream inside the VMess chunked body,
addressed to the synthetic `v1.mux.cool` target:

- The inbound terminates `New`, `Keep`, `End`, and `KeepAlive` frames for TCP
  and UDP sessions. Metadata is 4 bytes plus an optional target (network, port,
  address), data is at most 64 KiB per frame, and session IDs are nonzero.
- Session state is bounded: 128 sessions per physical connection, a 16-frame
  per-session uplink queue, and one owned task per session. A duplicate or
  zero session id, a frame larger than the bound, or a full queue closes the
  physical connection or the offending session.
- A UDP session may change its destination on a `Keep` frame; replies carry
  the source target so the client can demultiplex. TCP sessions use the target
  from `New` and relay bytes.
- The outbound uses direct UDP (`0x02`), which every reference server accepts.
  Client-side Mux.Cool pooling is not enabled: it is an optional performance
  feature, not a wire-compatibility requirement, and is tracked separately.

### Limits

Fixed constants, not configuration: inbound header 375 bytes, instruction
317 bytes, chunk plaintext 16,305 bytes, chunk padding 63 bytes, auth-ID window
120 seconds, replay-filter capacity 4,096 entries per inbound, 128 Mux.Cool
sessions per physical connection, 64 KiB Mux.Cool frame data.

### Replay handling

A VMess inbound keeps a bounded replay filter keyed by the encrypted auth ID:
120-second retention, oldest-first eviction, check-and-insert under one short
`std::sync::Mutex` acquire during the handshake, and insertion only after the
auth ID authenticates. This blocks replay of a captured request within the
window. `SessionHistory` (reference-implementation reuse tracking keyed by body
key/IV) is not implemented; a client that reuses its own key material only
harms its own session.

### Transport and configuration

VMess uses the ADR-0016 `transport` object with `tcp`, `ws`, and `h2`, in the
same layer order as VLESS. This supersedes ADR-0016's "rejected on every other
inbound/outbound protocol" clause for VMess only.

- Inbound: `protocol: "vmess"`, `uuid` required, `tls` optional for `tcp` and
  required for `ws`/`h2`; ALPN rules are the same as VLESS.
- Outbound: `server` and `uuid` required, `tls` optional for `tcp`/`ws` and
  required for `h2`, plus `security: "aes-128-gcm"` (default) or
  `"chacha20-poly1305"`. `auto`, `none`, `zero`, and `aes-128-cfb` are
  rejected at validation, as are `alter_id`, `xudp`, `method`, `password`, and
  `fallback`.
- One UUID per listener, matching the current VLESS inbound. Multi-user
  inbounds are out of scope.

### Dependencies

Reuse what the workspace already pins: `aes` 0.9 for the AES-128-ECB auth ID,
`aes-gcm` 0.11 for the header and body AEAD, `sha2` 0.10 for the response
key/IV derivation, and `subtle`/`zeroize` for comparisons and key hygiene. The
existing `getrandom` in `marmo` generates nonces, keys, and IVs.

Four new RustCrypto crates are unavoidable because the protocol fixes the
algorithm and the tree has no equivalent:

- `md-5` 0.10 for the CmdKey derivation. The TLS provider (`aws-lc-rs` 1.19)
  exposes no MD5, and writing MD5 by hand is forbidden.
- `sha3` 0.10 for SHAKE128 chunk masking. `aws-lc-rs` exposes SHA3-256 but no
  extendable-output function, and `sha2` has no SHAKE.
- `hmac` 0.12 for the iterated HMAC-SHA256 KDF. `aws-lc-rs` has HMAC, but
  depending on it directly would put the C-backed TLS provider underneath the
  independently published, pure-Rust `marmo-proto`; the RustCrypto wrapper
  reuses the pinned `sha2` and has no build script.
- `chacha20poly1305` 0.11 for the second body cipher. ADR-0018 already names
  it as an accepted primitive, and 0.11 shares `aead` 0.6 with `aes-gcm` 0.11.

The EAuID CRC32 IEEE and the instruction FNV-1a checksum are 12-byte and
317-byte non-cryptographic checksums. They are implemented in-tree (no
`unsafe`) instead of adding `crc32fast`, whose SIMD build script and `unsafe`
would require an ADR-0018 review for a once-per-connection operation. Both are
pinned with published check vectors and covered by the decoder fuzz target.

All new crates are Apache-2.0/MIT and have no build script; `cargo audit` and
the copyleft/license check run on the dependency-changing PR.

## Alternatives

1. **Stay deferred and record VMess as out of scope.** Cheapest, and the
   roadmap's Phase 2 gate would be satisfied. It leaves Xray/V2Ray peers
   unusable and keeps the support matrix claiming a protocol the library cannot
   speak. Rejected because the request is to implement it.
2. **Implement the MD5/CFB header and None/Zero bodies as well.** Maximises
   compatibility with obsolete clients. It reintroduces an unauthenticated
   header, a downgrade path, and a second framing generation for peers that
   should upgrade, contradicting the existing "legacy CFB is not planned" line.
   Rejected.
3. **Implement AEAD and TCP only.** Less work and a smaller surface, but it
   rejects Xray clients with mux enabled and cannot carry VMess UDP. Rejected
   when the decider asked for UDP and Mux.Cool.
4. **Skip the replay filter.** Less state and no handshake lock, but a captured
   request can be replayed for two minutes. Rejected; the filter is bounded and
   costs five constants.
5. **Allow body `None` for a "fast" mode.** Saves two AEAD tags per chunk and
   removes nothing else. It silently turns VMess into an authenticated but
   unencrypted tunnel and creates a second performance profile. Rejected.
6. **Take every primitive from `aws-lc-rs`, the TLS provider.** Fewer crates
   and one crypto backend. It still needs `md-5` and `sha3` because the provider
   has no MD5 and no SHAKE128, and it puts the C toolchain and `unsafe` under
   the standalone `marmo-proto` crate, breaking its pure-Rust boundary.
   Rejected.
7. **Support AES-128-GCM only.** Drops `chacha20poly1305`, but the inbound must
   accept whatever an authenticated client sends; rejecting ChaCha20 clients
   (common on ARM and with `security: auto`) is a wire-level incompatibility,
   not a simplification. Rejected.
8. **Client-side Mux.Cool pooling.** Multiplexes TCP and UDP over one outbound
   connection. It is a performance optimisation with its own connection
   ownership, pooling, and cancellation design; direct UDP already interoperates
   with every reference server. Deferred.

## Consequences

- The support matrix gains `VMess | TCP/TLS/WS/H2 | TCP yes | UDP yes |
  inbound yes | outbound yes | supported`. The inbound also terminates
  Mux.Cool; the outbound uses direct UDP.
- The transport object is shared with VLESS; no arbitrary VMess header, alterId,
  dynamic port, or legacy CFB option is exposed.
- New public codec API in `marmo-proto`; config gains the `vmess` protocol and
  the outbound `security` field. Schema version stays 2 because the additions
  are strict and additive.
- `docs/architecture.md` §4.1, §12, §13, §19, `docs/roadmap.md` (P2-7, gate,
  graph, critical path), `docs/protocols/vmess.md`, `docs/protocols/README.md`,
  `docs/security/audit.md`, `README.md`, `CHANGELOG.md`, `Cargo.toml`, and
  `Cargo.lock` change in the implementation PR. `AGENTS.md` already describes
  the protocol set generically and does not change.
- Estimated work: 8-10 days for codec, wiring, unit/integration/fuzz tests,
  reference interop against Xray 26.11.9 in both directions, and docs.
- Tested by: codec vectors (KDF, auth ID, headers, chunks) frozen from a
  spec-derived generator; loopback TCP/TLS/WS/H2 in both directions; direct
  UDP and Mux.Cool TCP/UDP sessions; replay, tamper, truncation, session-limit,
  and chunk-limit cases; a `vmess` fuzz target with corpus; and recorded Xray
  interop in the protocol note.

## Approval

- [x] Accept the recommendation (AEAD, TCP, direct UDP, server-side Mux.Cool,
      AES-128-GCM and ChaCha20-Poly1305, bounded replay filter).
- [ ] Accept with client-side Mux.Cool pooling as well: ...
