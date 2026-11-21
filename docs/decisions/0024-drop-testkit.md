# ADR-0024: Drop the unused testkit crate

- Status: Proposed
- Date: 2026-11-21
- Deciders: @mogeko
- Related: ADR-0019

## Context

ADR-0019 defines a five-crate workspace: `marmo`, `marmo-proto`,
`marmo-net`, `marmo-transport`, and `marmo-testkit`. The testkit was intended
for fake streams, fixture loading, and loopback helpers shared by tests.

In the current tree, `marmo-testkit` contains one helper, `stream_pair`, which
wraps `tokio::io::duplex`. After the release-packaging fix, no crate depends on
it:

- `marmo-transport` no longer dev-depends on it, because `cargo package`
  resolves dev-dependencies against crates.io and `marmo-testkit` is
  `publish = false`.
- The integration tests and unit tests use `tokio::io::duplex` directly.
- `marmo-proto` and `marmo-net` need no testkit helpers.

Keeping the crate adds a workspace member, a lockfile package, a release note,
and documentation that claims helpers the crate does not yet provide. It does
not provide a stable external API because it is never published.

## Decision (recommended)

Remove `marmo-testkit` from the workspace.

- Delete `crates/marmo-testkit/` and its workspace dependency entry.
- The workspace becomes four published crates: `marmo`, `marmo-proto`,
  `marmo-net`, and `marmo-transport`.
- Shared test helpers stay in `#[cfg(test)]` modules beside the code that uses
  them. A helper that is genuinely shared across crates can be introduced
  later with a concrete use and its own packaging decision.
- Update `Cargo.toml`, `Cargo.lock`, `README.md`, `AGENTS.md`,
  `crates/README.md`, `docs/architecture.md`, and the release notes in the same
  change.

This supersedes only ADR-0019's fifth-crate clause. The rest of ADR-0019
(four published crates, dependency direction, `forbid(unsafe_code)`, no backend
features, lockstep versions) remains in force.

## Alternatives

1. **Keep the crate unused.** No immediate work, but it stays dead weight, and
   the workspace and release docs keep claiming a test utility with no
   consumers. Rejected.
2. **Keep it and use it through a path-only dev-dependency.** This restores the
   helper but keeps a workspace member whose only consumer is tests. It also
   needs a packaging rule that dev-dependencies on unpublished path crates are
   not checked by `cargo package`. Rejected until several crates share real
   helpers.
3. **Merge the helper into `marmo-net`.** The helper is tokio-specific while
   `marmo-net` is a protocol-free address crate; this would add tokio and a test
   concern to a crate that should stay small. Rejected.
4. **Keep it as a published crate.** A one-function crate is not a useful
   public API, and publishing it adds a release and semver surface. Rejected.
5. **Keep it as a hidden workspace-only crate.** This is option 1 with extra
   rules; it still has no consumers. Rejected.

## Consequences

Positive:

- One fewer workspace member, lockfile package, and release-order entry.
- The test helpers live next to their tests, so their dependencies and limits
  stay local.
- The crate list in the README, AGENTS, architecture, and release notes becomes
  accurate.

Negative:

- A future shared test helper must be reintroduced deliberately instead of
  being available by default.
- Existing links to `marmo-testkit` in documentation are removed.

Testing and observation:

- `cargo test --workspace --locked`, `cargo clippy --workspace --all-targets
  -- -D warnings`, and `cargo +1.87.0 test --workspace --locked` stay green
  after the deletion.
- `cargo package -p marmo-net` and `cargo package -p marmo-transport` still
  work, and the release order becomes `marmo-net` → `marmo-proto` /
  `marmo-transport` → `marmo`.
- Every remaining `marmo-testkit` reference is removed from the current docs;
  ADR-0019 stays as history with its fifth-crate clause marked superseded in
  the index.

## Approval

- [ ] Accept the recommendation: delete `marmo-testkit` and keep shared helpers
      in local test modules.
- [ ] Choose an alternative: keep the crate, publish it, or merge its helper
      elsewhere.
