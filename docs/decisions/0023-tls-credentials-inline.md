# ADR-0023: TLS credentials as inline configuration

- Status: Accepted (2026-11-21)
- Date: 2026-11-21
- Deciders: @mogeko
- Related: ADR-0008, ADR-0012, ADR-0018, ADR-0019

## Context

The Zig v1 schema stores TLS credentials as file paths. The fields
`inbounds[].tls.certificate`, `private_key`, and `client_ca`, and
`outbounds[].tls.client_certificate` and `client_private_key`, are documented
as `PEM or DER ... file` in `src/config/config.zig`; the Zig tree reads them
through `src/transport/tls_credentials.zig` during instance startup.

The Rust implementation keeps `Config` pure: the same fields carry the PEM or
DER bytes themselves, and `marmo-transport` parses them from the string. The
embedder reads files and embeds the content; the examples already do this in
`crates/marmo/examples/common/mod.rs`.

R4 review found three problems with leaving this divergence implicit:

1. **Silent misparse.** A Zig v1 config with
   `"certificate": "/etc/marmo/server.pem"` parses successfully, then fails in
   `bind()` with `invalid certificate`. The error does not say that the field
   changed from a path to content, and a path whose bytes happened to look like
   DER could be accepted as garbage.
2. **Contradictory design text.** `docs/architecture.md` says both that
   "file reading is the embedder's job" (§14.4) and that credentials are
   loaded in `bind()` with `spawn_blocking` (§5 and §14.4). ADR-0012 also
   records Zig-era file loading. No Rust-era ADR records the actual choice.
3. **DER through JSON is not safe.** A JSON string is Unicode; arbitrary DER
   bytes are not. Treating the UTF-8 bytes of a JSON string as DER corrupts
   any byte at or above `0x80`. Only PEM text is safe in a JSON string.

The decision must also preserve the reason the Rust tree moved to inline
content: `build()` and `bind()` should stay free of filesystem I/O, should not
block the executor with file reads, and should work in embedders that do not
have a filesystem or that keep credentials in a secret store. The library
already limits a configuration document to 4 MiB, so inline credentials cannot
grow without bound.

## Decision (recommended)

The Rust configuration schema carries inline TLS credentials, and the library
never reads credential files.

- **Schema version 2.** Change `version` to `2`; a document with `"version": 1`
  is rejected with an error that names the TLS credential change. The default
  version for an omitted field becomes `2`. The Rust tree is unreleased, so
  this is the point to make the break explicit rather than ship a schema whose
  fields mean something different from Zig v1.
- **Inline PEM only in JSON.** `inbound.tls.certificate`,
  `inbound.tls.private_key`, `inbound.tls.client_ca`,
  `outbound.tls.client_certificate`, and `outbound.tls.client_private_key`
  contain PEM text (`-----BEGIN ...-----`). A value without a PEM header is
  rejected during configuration validation with a message explaining that a
  file path is not accepted. DER is not accepted through a JSON string; if DER
  support is needed later, add an explicit base64 form rather than guessing.
- **No filesystem I/O in the library.** `Config::from_json`, `build()`, and
  `bind()` never open a credential path, never call `std::fs`, and never use
  `spawn_blocking` for credentials. `bind()` still performs socket I/O.
  Embedders read files or fetch secrets with their own policy and pass the
  content in the configuration.
- **The transport API may still accept DER bytes programmatically.** The
  restriction above is a configuration-schema rule. `marmo-transport` may keep
  a byte-oriented constructor for callers that hold DER in memory; it must not
  be reachable through a JSON string.
- **Config is sensitive.** Because private keys and passwords now live in the
  configuration document, secret-bearing types must redact `Debug` output and
  zeroize on drop. `Tls`, `InboundTls`, and the options structs must not print
  key material. This becomes a required part of the same R4 hardening work.
- **Documentation and fixtures.** Update `docs/architecture.md` §5 and §14.4,
  `docs/protocols/vless.md`, the examples, and every test config to version 2
  and inline PEM. The examples continue to read files themselves.
- **Superseded clauses.** This supersedes the "Rust schema stays compatible
  with the Zig v1 schema" and "Credentials are loaded in `bind()` with
  `spawn_blocking`" clauses of `docs/architecture.md` §14.4, and the Zig-era
  file-loading note in ADR-0012 for the Rust tree. ADR-0012's TLS wire
  decisions remain in force.

## Alternatives

1. **Keep file paths and load them in `bind()` (Zig behaviour).** Preserves v1
   compatibility, but puts blocking file I/O back into `bind()`, requires
   `spawn_blocking`, turns a configuration typo into a bind-time error, adds
   path-resolution and TOCTOU concerns, and removes the embedder's control over
   where secrets live. Rejected: the Rust tree is library-first and should not
   own secret storage.
2. **Auto-detect a path or inline content.** A value containing
   `-----BEGIN` is inline; anything else is a path. Ambiguous for malformed
   input, reintroduces filesystem I/O, and makes the schema dependent on
   content sniffing. Rejected.
3. **Keep version 1 and only document the divergence.** Smallest diff, but a
   Zig v1 config still parses and fails late, and the schema version no longer
   identifies the semantics. Rejected: the version field exists to make this
   kind of change explicit.
4. **Inline base64 DER.** Unambiguous and compact, but adds a second encoding,
   a new validation path, and conversion code for no current user. Deferred;
   PEM is ASCII, already used by the examples and interop fixtures, and keeps
   the diff small.
5. **A tagged object (`{ "inline": "..." }` or `{ "path": "..." }`).** Makes the
   source explicit, but expands every credential field, still needs path I/O if
   `path` is allowed, and breaks the existing flat schema more than a version
   bump. Rejected for parity.
6. **Keep the transport's `&str` DER fallback and document it.** Tempting to
   avoid touching the adapter, but it is exactly the Unicode corruption named
   above. Rejected; use PEM in config and a byte-oriented API for programmatic
   DER if needed.

## Consequences

Positive:

- `build()` and `bind()` stay free of filesystem I/O and executor blocking;
  behaviour is the same on every platform and in sandboxed embedders.
- A configuration document is self-contained: the same bytes are validated,
  tested, and used, with no path that can change between validation and use.
- A Zig v1 document fails fast with an actionable version error instead of a
  late certificate error.
- Tests and examples already use inline PEM, so the migration is mostly a
  version field and validation change.

Negative:

- Private keys live in the configuration document and in `Config` memory.
  `Debug` redaction, zeroization, and "never log the config" become mandatory.
- Embedders must read files themselves. A file path in a config is now an
  error, not a convenience.
- Version 2 rejects every existing v1 document, including documents that do
  not use TLS. This is intentional fail-closed behaviour, but it needs a
  migration note in the release documentation.
- Configuration size grows with the certificate chain and key; the existing
  4 MiB cap remains the outer bound.

Testing and observation:

- A v1 config is rejected with an error that names version 2 and the credential
  change.
- A v2 config with inline PEM is accepted; a string that looks like a path is
  rejected by validation.
- No crate calls `std::fs` for credentials; a grep or a test-only audit can
  enforce this.
- Examples read PEM files and embed them; `cargo run --example vless` still
  works.
- TLS tests continue to use the fixture PEM strings through `include_str!`.
- The R4 hardening tests assert that `Debug` for every credential-bearing type
  does not contain the key material.

Rollback: restore version 1 and file-path loading in `bind()`. This requires
`spawn_blocking`, the Zig path-resolution behaviour, and the corresponding
architecture text.

## Approval

- [x] Accept the recommendation (schema version 2, inline PEM only, no
      filesystem I/O in the library, redacted and zeroized config secrets).
- [ ] Choose an alternative: keep v1 paths, auto-detect, tagged object, or
      another approach.
