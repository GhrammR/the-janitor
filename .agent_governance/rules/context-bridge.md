# Rule: Context Bridge Law

## Purpose

Synchronize the local execution agent's shipped capabilities with the strategic
Oracle's system prompt (`SYSTEM_INSTRUCTIONS.md`) after every sprint.

## The Law

You are the maintainer of `SYSTEM_INSTRUCTIONS.md` located in the repository
root. This file contains the system prompt for the overarching strategic AI
(currently Gemini 3.1 Pro / equivalent Oracle model). It is the Oracle's
authoritative view of the engine's current capabilities.

**After every sprint that modifies any of the following, you MUST update
`SYSTEM_INSTRUCTIONS.md` to reflect the change:**

1. **CURRENT STATE** — engine version bump, new capabilities shipped (e.g.,
   new detector classes, new witness types, new ingestion pipelines).
2. **THE ARCHITECTURE** — structural changes to crates, new public APIs, new
   governance laws ratified, Tri-Ledger routing changes.
3. **DEPRECATED CONCEPTS** — any P-tier item deleted from `.INNOVATION_LOG.md`
   (shipped or abandoned), justfile targets removed, commands renamed or deleted.

## Execution Protocol

At the conclusion of Phase 6 (Verification & Commit) in every sprint:

1. Read the current `SYSTEM_INSTRUCTIONS.md`.
2. Compare against the session's `[CHANGES STAGED]` table.
3. If any shipped capability is absent from `SYSTEM_INSTRUCTIONS.md`, add it
   under the relevant section (CURRENT STATE or THE ARCHITECTURE).
4. If any deleted P-tier item or deprecated concept is still referenced in
   `SYSTEM_INSTRUCTIONS.md`, remove the reference or move it to the
   `DEPRECATED CONCEPTS` section.
5. Update the version string in section I to match `[workspace.package].version`
   from `Cargo.toml`.

## Enforcement

- A sprint that ships a new detector, ingestion pipeline, or governance law
  without updating `SYSTEM_INSTRUCTIONS.md` is incomplete.
- The Oracle cannot make accurate strategic recommendations if its system prompt
  is stale. Every sprint hour the context bridge remains open costs the operator
  compounding Oracle drift.
- This rule is enforced by the agent's self-audit at the start of every
  `[NEXT RECOMMENDED ACTION]` preflight — re-read `SYSTEM_INSTRUCTIONS.md`
  before selecting the next action to confirm it is current.
