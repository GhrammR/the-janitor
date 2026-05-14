# Crossroads Waiting Skill

Use this skill when a directive hits a missing dependency, locked secret,
signing-key handoff, dirty deployment workspace, or policy ambiguity that
requires the operator to choose the next path.

## Workflow

1. Read `.agent_governance/rules/crossroads.md`.
2. Preserve the current branch, staged index, command output, and unresolved
   phase context.
3. Prefer the host's interactive choice UI if available, so execution waits and
   resumes after the operator clicks a choice.
4. If no interactive UI is available, ask exactly one A/B/C question and stop
   without a final governed report.
5. After the operator chooses, continue the same directive from the blocked
   phase.
6. Append the chosen path and resumed outcome to `docs/CHANGELOG.md`.

## Required Choices

- `A) install/enable dependency now`
- `B) proceed with bounded fallback and clearly mark reduced assurance`
- `C) pause and wait for operator intervention`

## Prohibitions

- Do not skip dependency installation silently.
- Do not convert a crossroads into a final response.
- Do not wipe unrelated dirty worktree state.
- Do not retry a failed signed commit with `--no-gpg-sign`.
