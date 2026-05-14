# Crossroads Waiting Skill

Use this skill when a directive hits a missing dependency, locked secret,
signing-key handoff, dirty deployment workspace, or policy ambiguity that
requires the operator to choose the next path.

## Workflow

1. Read `.agent_governance/rules/crossroads.md`.
2. Preserve the current branch, staged index, command output, and unresolved
   phase context.
3. Use the host's native interactive choice or permission popup when available,
   so execution waits and resumes after the operator clicks a choice. Include
   the blocker, recommended default option, recommendation rationale, and any
   external-app command/action the operator must complete in the popup body.
4. If no native popup is available in the current mode, state that explicitly
   and emit exactly one plain-text A/B/C checkpoint with identical semantics.
   This is still a non-terminal waiting phase, not a governed final report.
5. After the operator chooses, continue the same directive from the blocked
   phase.
6. Append the chosen path and resumed outcome to `docs/CHANGELOG.md`.

## Required Choices

- `A) install/enable dependency now`
- `B) proceed with bounded fallback and clearly mark reduced assurance`
- `C) pause and wait for operator intervention`

Always mark one option as recommended and explain why.

## Prohibitions

- Do not skip dependency installation silently.
- Do not convert a crossroads into a final response.
- Do not wipe unrelated dirty worktree state.
- Do not retry a failed signed commit with `--no-gpg-sign`.
- Do not omit outside-app recovery commands from the popup or fallback
  checkpoint when the operator must authenticate, unlock, install, or approve
  something outside the agent runtime.
