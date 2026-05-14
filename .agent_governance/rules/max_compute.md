# Rule: GPT-5.5 Max Compute Protocol

When the operator invokes `[ACTIVATE MAX COMPUTE]`, the agent must halt
standard engineering tasks and switch into a bounded, architecture-first audit
of `.INNOVATION_LOG.md` and the engine implementation.

## Scope Lock

The audit MUST focus strictly on these four domains:

1. Cryptographic Invariants
2. Formal Verification Translation
3. Cross-Language Memory Safety
4. AI-Agent Deception

Max Compute sprints MAY include target hunting and specific feature
implementation alongside the deep architectural audit, provided memory limits
are respected. Releases remain prohibited while the protocol is active.

## Output Contract

The agent MUST produce detailed Rust/Z3 mathematical blueprints for the four
domains above and append the resulting frontier architecture to
`.INNOVATION_LOG.md`. Never overwrite roadmap history.

Each blueprint must name:

- the missing invariant or proof boundary,
- the Rust module to extend,
- the Z3 / Kani / IFDS model required,
- the deterministic true-positive fixture,
- the deterministic true-negative fixture,
- and the commercial unlock achieved by closing the gap.

## Resource Discipline

The 8GB Law remains active. Max Compute is a reasoning mode, not a license to
introduce heavyweight runtimes, JVM tooling, local LLM hosting, or memory-bloated
analysis passes.

## Crossroads Waiting Phase

When a Max Compute sprint is blocked by a missing tool, missing secret,
environment policy, or release/deploy ambiguity, the agent MUST enter a
non-terminal waiting phase instead of ending the directive.

This phase is governed by `.agent_governance/rules/crossroads.md` and
`.agent_governance/skills/crossroads-waiting/SKILL.md`.

The waiting phase protocol is:

1. Ask exactly one multiple-choice crossroads question with choices:
   `A) install/enable dependency now`,
   `B) proceed with bounded fallback and clearly mark reduced assurance`, and
   `C) pause and wait for operator intervention`.
2. Treat the crossroads as an interim execution checkpoint, not the final
   governed response.
3. Preserve all local state, staged changes, and command context.
4. After the operator selects A, B, or C, resume the same directive from the
   blocked phase and record the selected path in `docs/CHANGELOG.md`.
5. If the host environment exposes a native interactive permission or choice
   popup, use that popup so the prompt continues automatically after selection.
   Include any external-app recovery commands in the popup body. If no such UI
   is available in the current mode, log that fact and emit the question as a
   non-terminal plain-text fallback; resume immediately when the operator
   replies with the selected option.
