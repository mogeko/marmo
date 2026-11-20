---
name: Architecture Decision Records
description: Propose, record, accept, or supersede a marmo architecture decision. Use before changing layers, protocols, transports, routing, config, dependencies, or anything that conflicts with docs/architecture.md.
---

# Architecture Decision Records

marmo is design-first. An ADR records one decision. The user decides; the agent
proposes. A `Proposed` ADR is not approval to implement.

## When to use

- Adding or removing a protocol, transport, dependency, or build feature.
- Changing a layer boundary, public interface, config schema, or error model.
- Resolving an ambiguity in `docs/architecture.md`.
- Any request that would contradict an accepted ADR.

Do not use an ADR for ordinary refactors, bug fixes, or formatting.

## Rules

1. One decision per ADR. Keep it short and concrete.
2. Never implement a `Proposed` ADR. Ask the user and wait.
3. Accepted ADRs are immutable: change one by writing a new ADR that supersedes
   it, never by editing history. A decider-requested clarification may be
   appended as an explicit `## Amendment` section with the date; do not rewrite
   the original decision silently.
4. Write in English. Use the repository template at
   `docs/decisions/0000-template.md`.
5. Protocol work must stay clean-room (ADR-0009): specs, not ported code.
6. After acceptance, reconcile `docs/architecture.md` and the index. Do not
   leave conflicting prose.
7. Never put ADR details in `AGENTS.md`; link to the decision instead.

## Workflow

1. Check for an existing ADR on the topic. Read `docs/decisions/README.md` and
   `docs/architecture.md`.
2. Create the file (from the repo root):

   ```sh
   .agents/skills/adr/scripts/new-adr.sh <kebab-slug> "Short title"
   ```

   It picks the next `NNNN` and fills the date. Or copy the template manually.
3. Fill `Context`: constraints that matter (language and toolchain, `std`
   gaps, license policy, dependency policy, platforms) and the concrete
   problem.
4. List at least two alternatives with why they lose. State a recommendation
   under `Decision (recommended)`.
5. Add the row to `docs/decisions/README.md` with status `Proposed`.
6. Tell the user the options and the recommendation. Wait for a decision.
7. On acceptance: set `Status: Accepted`, tick the chosen option, add the ADR to
   the architecture index, and update affected sections of
   `docs/architecture.md`.
8. On rejection: set `Status: Rejected`, record why, and propose the next step.

## Quality bar

- The decision names interfaces, modules, limits, defaults, and the phase it
  applies to.
- Consequences include negative ones and how the decision will be tested.
- No vague words ("fast", "robust", "modern") without a measurement or a
  concrete behavior.
- If a claim depends on `std` behavior, verify it against the pinned Zig version
  first.
