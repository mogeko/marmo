# ADR-0009: Licensing and protocol interoperability

- Status: Accepted (2026-11-18)
- Date: 2026-11-18
- Deciders: @mogeko
- Related: ADR-0002, ADR-0007

## Context

The repository is licensed LGPL-2.1. The closest implementations in this space
have incompatible or differently structured licenses: sing-box is GPL-3.0,
v2ray/Xray are MPL-2.0/GPL variants, and some protocol descriptions exist only
in community documentation or reverse-engineering notes. Protocol behavior is
not copyrightable, but code, test vectors, and documentation are.

Proxy protocol work also carries an interoperability obligation: a decoder that
is "almost right" silently fails against real clients and can be a security
hole. The library will parse untrusted bytes before authentication.

## Decision

Keep LGPL-2.1 and treat protocol work as clean-room, spec-driven engineering.

- Implement from public protocol specifications or published documentation, not
  by porting code from GPL/AGPL/MPL projects.
- Record per-protocol sources, ambiguities, and interop notes in
  `docs/protocols/<protocol>.md`; link the exact revision used.
- Add captured byte fixtures and test vectors under `tests/fixtures/<protocol>/`
  with provenance and license notes. Do not copy vectors from a GPL project
  without permission.
- Interop tests run against fixtures or self-hosted reference servers in CI;
  never against live third-party servers.
- Fuzz every decoder (`zig build fuzz` once available); malformed input returns
  an error and never panics or allocates unboundedly.
- Rule-set data (GEOIP/GEOSITE) is user-supplied or built by a separate tool
  with its own license documentation; do not vendor data of unclear origin.
- Document LGPL-2.1 static-linking obligations in `README.md` before any
  release; downstream users must be able to relink.
- Relicensing (for example to MIT/Apache-2.0) is a separate decision by the
  copyright holder and is not implied by this ADR.

## Alternatives

1. **Relicense to MIT/Apache-2.0.** Simpler for embedders and static linking,
   but the user has already chosen LGPL-2.1; changing it now affects all
   contributors. Out of scope unless explicitly requested.
2. **Port from an existing GPL implementation.** Faster protocol bring-up, but
   incompatible with LGPL-2.1 distribution. Rejected.
3. **Depend on a reference library per protocol.** Adds many dependencies and
   license obligations, and conflicts with the no-backend policy (ADR-0007).

## Consequences

- Protocol bring-up is slower and requires reading specs carefully.
- Security review and fuzzing are part of the definition of done, not extras.
- Documentation must distinguish verified behavior from guesses; unresolved
  ambiguities are recorded in `docs/protocols/`.
- License headers and third-party notices must be audited before release.
- Contributors must not paste code from incompatible projects; review should
  ask for the source of any protocol logic.

## Approval

- [x] Accepted 2026-11-18 as recommended.
