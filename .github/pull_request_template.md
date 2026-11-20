## Slice

<!-- One behavioral boundary. Name the phase prefix in the title, e.g. "r2c: SOCKS5 inbound". -->

## Parity rows closed

<!-- Link the rows in docs/rust-migration.md Appendix A. A row is not closed
     without its test, fixture, interop, or fuzz evidence. -->

## Evidence

<!-- Commands and results: cargo test, fuzz target/duration, interop peers,
     criterion delta. Paste the relevant lines, not "passes". -->

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
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace --locked`
- [ ] `cargo audit` and a `cargo tree --format '{l}'` license review (dependency changes)
- [ ] No `todo!()` or `unimplemented!()` on a reachable path
- [ ] Public items documented; docs/architecture.md updated if a boundary moved
