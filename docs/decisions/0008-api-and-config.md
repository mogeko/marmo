# ADR-0008: Public API, configuration, and errors

- Status: Accepted (2026-11-18)
- Date: 2026-11-18
- Deciders: @mogeko
- Related: ADR-0001, ADR-0003, ADR-0007

## Context

The library must be embeddable, testable, and hard to misconfigure. Config
arrives from users and is the main source of invalid states (bad ports, missing
credentials, cycles, transports not yet implemented). Runtime failures must be
distinguishable from configuration failures, and secrets must not leak into
logs.

Zig has no stable ABI and the project is pre-1.0, so committing to a C ABI now
would constrain the design for little benefit.

## Decision

A small lifecycle API, strict JSON config, and typed errors.

```zig
var diagnostic: marmo.Diagnostic = .{};
defer diagnostic.deinit();

var instance = marmo.Instance.init(gpa, io, config, &diagnostic) catch |err| {
    std.log.err("config: {f}", .{diagnostic});
    return err;
};
defer instance.deinit();
try instance.start();
try instance.wait();   // blocks until stop() or a fatal listener error
try instance.stop();   // idempotent
```

- `Instance.init` parses and validates config, compiles rules, and allocates
  long-lived state. It performs no network I/O; on failure it returns
  `error.InvalidConfig` and fills the caller-provided `Diagnostic` with a config
  path.
- `start` binds listeners and starts health checks. Partial failure rolls back
  everything already started.
- Config is JSON parsed with `std.json` in strict mode: unknown fields are
  errors, duplicate keys are errors, and defaults are documented.
- Config is versioned (`"version": 1`) and validated before any bind.
- Errors: typed error sets at API boundaries (`error.InvalidConfig`,
  `error.UnsupportedTransport`, `error.BindFailed`, ...). No `anyerror` in
  public signatures. Diagnostics carry a message, a config path, and an optional
  cause, and are freed by the caller.
- Secrets (passwords, UUIDs, private keys, tokens) use a wrapper type whose
  formatter prints `[redacted]`; config dumps and logs must use it.
- Logging is injected: a `Logger` interface with a default `std.log`
  implementation; no global log level mutation.
- No CLI, daemon, or `app` layer in this repository. The library never installs
  signal handlers or owns the process lifecycle; embedders create the runtime
  and decide when to wait and stop.
- No C ABI in v1. Semver applies to the Zig module; pre-1.0 minor versions may
  break.

## Alternatives

1. **C ABI now.** Broad language embedding, but painful with Zig generics,
   allocators, and `std.Io`; defer until the API stabilizes.
2. **YAML/TOML config.** Friendlier comments, but requires third-party parsers
   and expands the dependency surface. JSON is already in `std`.
3. **Builder-only API** (no config file). Good for embedders, but downstream
   applications and tests still need a serialized format; provide both.
4. **Lenient parsing** (ignore unknown fields). Rejected: typos silently
   disable rules or security settings.
5. **Hot reload in v1.** Deferred; atomic snapshot replacement is designed for
   but not exposed until Phase 2.

## Consequences

- Strict parsing will break configs when fields are renamed; version and
  migration notes are required.
- Diagnostics add allocation; they are only built on error paths.
- The lifecycle must be safe to call from any thread, with documented behavior
  for concurrent `stop`.
- Tests can construct `Config` directly without JSON; both paths must validate
  identically (single validator, not duplicated logic).
- Secret redaction must be enforced by types, not by reviewer discipline.

## Approval

- [x] Accepted 2026-11-18 as recommended.
