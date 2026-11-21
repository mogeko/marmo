# ADR-0020: License change

- Status: Accepted (2026-11-21)
- Date: 2026-11-21
- Deciders: @mogeko
- Related: ADR-0009, ADR-0018

## Context

The repository is LGPL-2.1 (ADR-0009). The Rust ecosystem is predominantly
MIT OR Apache-2.0, and the LGPL-2.1-only license is incompatible with
Apache-2.0-only code under the FSF reading (LGPL-2.1 is built on GPL-2.0).
Static linking obligations also make the library harder to embed than a
permissive license would.

The decider has allowed the license to change. The copyright history has two
commit authors (`T3 Code` and `Zheng Junyi`), so relicensing requires
confirmation from both.

## Decision (recommended)

Relicense the project to **MIT OR Apache-2.0**, effective with the next
release.

- `LICENSE-MIT` and `LICENSE-APACHE` are added; `LICENSE` points to both, as is
  conventional in Rust.
- `Cargo.toml` uses `license = "MIT OR Apache-2.0"`; no per-file SPDX headers
  are required.
- Contributions are accepted under the same dual license (inbound =
  outbound).
- Releases published before the change remain LGPL-2.1; the change is not
  retroactive.
- The clean-room rule in ADR-0009 stays: protocol work is implemented from
  specifications, GPL/AGPL/MPL code is never ported, and fixture provenance is
  recorded.
- `cargo-deny` allows MIT, Apache-2.0, ISC, BSD-2/3-Clause, Unlicense, and
  CC0; it denies GPL, AGPL, and MPL. Apache-2.0-only runtime dependencies
  become acceptable.
- Both copyright holders confirm the relicensing in writing before the change
  is merged.

## Alternatives

1. **Keep LGPL-2.1 and restrict dependencies to permissive-only crates.**
   Avoids the relicensing process, but excludes Apache-2.0-only crates, keeps
   static-linking friction, and diverges from Rust convention. Rejected given
   the decider's permission to change.
2. **Relicense to LGPL-3.0-or-later.** Keeps copyleft, is Apache-2.0
   compatible, and fixes the immediate incompatibility. Rejected because the
   goal is easier embedding, and copyleft is the friction being removed.
3. **MPL-2.0.** File-level copyleft, compatible with Apache-2.0, but adds
   notice obligations without a stated goal. Rejected.
4. **Dual-license under MIT and LGPL-2.1.** Keeps a copyleft option, but
   LGPL-2.1 still conflicts with Apache-2.0-only crates and adds a choice
   embedders must reason about. Rejected.
5. **MIT only.** The simplest text and the lowest compliance surface, and it
   remains compatible with GPLv2. Rejected as the default because it gives up
   the express patent grant and the Apache-2.0 option that some contributors
   and adopters require. Acceptable if minimalism is valued more than those
   two properties; switching is a one-ADR change before acceptance.
6. **Apache-2.0 only.** Provides the patent grant but is incompatible with
   GPLv2-only projects, which is a larger exclusion than MIT-only. Rejected.

## Consequences

- Embedding and static linking become simpler; downstream users no longer need
  to provide relinking mechanisms.
- The project gives up copyleft protection. This is an accepted trade.
- The change needs both copyright holders' written confirmation; without it,
  the decision cannot be applied.
- `README.md`, `Cargo.toml`, `NOTICE`, and the CI license gate are updated in
  the same change. The old `LICENSE` text is removed only after the
  confirmation is recorded in this ADR.
- Dependency choice widens (Apache-2.0-only crates are allowed), but GPL,
  AGPL, and MPL remain forbidden.

## Approval

- [x] Accept the recommendation (MIT OR Apache-2.0), with both copyright
      holders confirming.
- [ ] Choose MIT only.
- [ ] Choose LGPL-3.0-or-later instead.
- [ ] Keep LGPL-2.1.

Accepted 2026-11-21 as recommended. The relicensing commit records the
copyright confirmation and replaces the license files.

## Amendment (2026-11-21)

The license gate no longer uses `cargo-deny`. CI runs a `cargo tree` check that
rejects GPL/AGPL/MPL, and dependency-changing PRs record a license review. The
dual-license choice and the allowlist (MIT, Apache-2.0, ISC, BSD, Unlicense,
CC0, Unicode-3.0, CDLA-Permissive-2.0) are unchanged.

## Amendment (2026-11-21)

The root `LICENSE` pointer was removed after the cutover. The license text is
in `LICENSE-MIT` and `LICENSE-APACHE`; the `Cargo.toml` license metadata is
unchanged.
