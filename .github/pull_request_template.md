## Change

<!-- One logical boundary. What changes and why? -->

## Evidence

<!-- Commands and results: cargo test, fuzz target/duration, interop peers,
     benchmark delta. Paste the relevant lines, not "passes". -->

## Review guide

<!-- Where to look, what is mechanical, what is generated, what is out of scope.
     Review by path: `git diff -- crates/marmo-proto`. -->

## Invariants touched

<!-- Bounds, cancellation safety, half-close, secret handling, config strictness,
     no unbounded spawn, no blocking on the executor. -->

## Rollback

<!-- Revert this commit; no data migration, no protocol break, or the exact
     mitigation. -->

## Checklist

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`
- [ ] `cargo test --workspace --locked`
- [ ] `cargo audit` and a `cargo tree --format '{l}'` license review (dependency changes)
- [ ] No `todo!()` or `unimplemented!()` on a reachable path
- [ ] Public items documented; `docs/architecture.md` updated if a boundary moved
