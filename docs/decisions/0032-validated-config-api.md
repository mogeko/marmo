# ADR-0032: Validated configuration and runtime limits

- Status: Accepted (2026-11-24)
- Date: 2026-11-24
- Deciders: @mogeko
- Related: ADR-0008, ADR-0017, ADR-0028, ADR-0029, ADR-0030

## Context

`Config` is currently both the strict JSON document and the public Rust
construction type. Its fields are public and reference schema types such as
`Inbound`, `Outbound`, `Route`, `Rule`, `Tls`, and `Limits`
(`crates/marmo/src/config.rs`). `Config::from_json` validates the document, but
a caller can build the same struct literally and hold a configuration that has
never passed validation. `InstanceBuilder::build` therefore validates again,
and every embedder must remember to call `validate` when constructing
configuration by hand.

The public names are also ambiguous:

- the configuration type `Limits` (seconds in JSON) and the runtime type
  `marmo::Limits` (`Duration`) have the same name;
- `Config::limits` is a configuration field, while `Config::limits()` returns a
  runtime value;
- `ConfigLimits` is currently needed as an alias, which makes the public API
  depend on a workaround.

The project is pre-1.0 and does not promise API stability. Keeping the raw
schema structs public protects no compatibility requirement and leaves invalid
states representable.

The JSON schema is version 2 and is the operational configuration interface.
Changing its syntax would add migration work without improving the in-memory
invariant. The decision below keeps schema version 2 unchanged.

## Decision (recommended)

Make a validated `Config` the only public configuration type, and separate
configuration limits from runtime limits.

### Public types

```rust
pub struct Config(/* private Arc<ConfigInner> */);

impl Config {
    pub fn from_json(text: &str) -> Result<Self, ConfigError>;
    pub fn builder() -> ConfigBuilder;

    pub fn limits(&self) -> RuntimeLimits;
    pub fn inbounds(&self) -> &[Inbound];
    pub fn outbounds(&self) -> &[Outbound];
    pub fn route(&self) -> &Route;
    pub fn dns(&self) -> Option<&Dns>;
    pub fn process(&self) -> &Process;
}

pub struct ConfigBuilder { /* private */ }

impl ConfigBuilder {
    pub fn new() -> Self;
    pub fn limits(self, limits: Limits) -> Self;
    pub fn process(self, process: Process) -> Self;
    pub fn dns(self, dns: Option<Dns>) -> Self;
    pub fn inbound(self, inbound: Inbound) -> Self;
    pub fn outbound(self, outbound: Outbound) -> Self;
    pub fn route(self, route: Route) -> Self;
    pub fn build(self) -> Result<Config, ConfigError>;
}
```

- The serde DTO moves to a crate-private `RawConfig` with the current JSON
  shape. `Config::from_json` is the only JSON parser, and it validates before
  returning.
- `ConfigBuilder::build` is the only programmatic constructor. It performs the
  same semantic validation as `Config::from_json`; there is no second validation
  pass inside `InstanceBuilder`.
- `Config` exposes read-only accessors. Its fields are private, so an invalid
  configuration cannot be created by field assignment.
- `InstanceBuilder::build` accepts `Config` directly and does not revalidate.

### Typed schema values

`Inbound` and `Outbound` become protocol-tagged enums instead of bags of
optional fields. For example:

```rust
pub enum Inbound {
    Socks5 { tag: String, listen: Endpoint },
    Http { tag: String, listen: Endpoint },
    Shadowsocks {
        tag: String,
        listen: Endpoint,
        method: SsMethod,
        password: SecretString,
    },
    Trojan {
        tag: String,
        listen: Endpoint,
        password: SecretString,
        tls: InboundTls,
        fallback: Option<Endpoint>,
        sniffing: Option<Sniffing>,
    },
    Vless { /* protocol-specific fields */ },
    Vmess { /* protocol-specific fields */ },
}
```

- Endpoints are parsed into `Endpoint`; ports are validated at construction.
- Credentials use a small local `SecretString` wrapper: owned bytes, redacted
  `Debug`, and zeroize-on-drop. This ADR does not add a new crypto or secrets
  dependency; it also does not expose a raw `Zeroizing<String>` whose derived
  `Debug` would print the secret.
- `Route`, `Rule`, and selector configuration use typed actions and targets, so
  an outbound tag is resolved during compilation rather than stored as an
  unchecked string at runtime.
- `RawConfig` keeps the existing version 2 field names and defaults. The JSON
  schema and accepted documents do not change.

### Limits naming

- `Limits` is the JSON-facing configuration type (seconds and bounds).
- `RuntimeLimits` is the validated runtime type (`Duration`, `Option<Duration>`).
- `Config::limits()` returns `RuntimeLimits`.
- `ConfigLimits` is removed; no compatibility alias is retained.
- `InstanceBuilder::shutdown_grace` continues to override the runtime drain
  deadline, not the JSON limits.

### Errors

`ConfigError` remains the single validation error type. It continues to carry
the JSON path (`inbounds[0].port`) for `from_json`, and builder failures use the
same path-like field names (`inbounds[0].listen`). No `Result<(), String>` or
`anyhow` enters the public API.

## Alternatives

1. **Keep the current public DTO and require `Config::validate`.** This is the
   current state. It leaves invalid states representable, duplicates validation
   between builder and `InstanceBuilder`, and keeps the `Limits` naming
   ambiguity. Rejected.
2. **Use `#[serde(tag = "protocol")]` directly on the public config and change
   the JSON shape.** It would make serde and the public API share one enum, but
   it changes the version 2 document syntax (`inbounds[].protocol` plus flat
   fields) and forces a schema migration for no runtime benefit. Rejected.
3. **Introduce only a `ValidConfig` newtype and keep the public DTO.**
   `ValidConfig(Config)` would prevent `InstanceBuilder` from accepting an
   unvalidated value, but callers could still build `Config` with invalid field
   combinations and the DTO would remain a second, unchecked API. Rejected as
   a half-measure.
4. **Keep `ConfigLimits` as a permanent alias.** It avoids one renaming in the
   short term but leaves two `Limits` meanings in the public surface. The
   project has no compatibility promise, so the alias should not become
   permanent. Rejected.

## Consequences

Positive:

- A `Config` value is valid by construction; `InstanceBuilder` has one
  invariant instead of two validation paths.
- Protocol-specific invalid combinations are rejected by the type, not by a
  1,900-line validation file.
- `Limits` and `RuntimeLimits` name different concepts unambiguously.
- Embedders can construct configuration programmatically without JSON strings.

Negative:

- This is a breaking public API change. Existing examples, tests, and docs must
  move to `Config::from_json`, `ConfigBuilder`, typed `Inbound`/`Outbound`, and
  `RuntimeLimits`.
- `RawConfig` remains a second representation internally; it must be kept in
  lockstep with the public builder and JSON schema.
- Typed endpoints and credentials move conversion errors from instance build to
  config construction, which changes some error timing.
- `Router` construction and public read-only accessors need to be reconciled so
  a compiled router only accepts a validated `Config`.

Tests and observation:

- `tests/api.rs` must build a complete configuration through `ConfigBuilder`
  and through `Config::from_json`, and both must produce equivalent runtime
  values.
- Invalid combinations (missing TLS, wrong protocol fields, duplicate tags,
  bad route targets) must fail at `ConfigBuilder::build` and at
  `Config::from_json`.
- Existing integration tests and examples must pass after updating to the new
  types.
- A `trybuild`-style compile test is recommended to prove that the raw schema
  fields are not publicly constructible.

## Approval

- [x] Accept the recommendation (opaque validated `Config`, `ConfigBuilder`,
  typed `Inbound`/`Outbound`, `Limits`/`RuntimeLimits` split).
- [ ] Choose an alternative: keep the current public DTO and validation path.
- [ ] Choose a different limits naming scheme: ...
- [ ] Reject this API change.
