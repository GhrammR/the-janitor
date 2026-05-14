# /crossroads

Enter the governed Crossroads Waiting phase for an operator-only blocker.

## Procedure

1. Load `.agent_governance/skills/crossroads-waiting/SKILL.md`.
2. State the blocker in one sentence.
3. Ask exactly one A/B/C choice through the host native popup when available.
   Put any outside-app recovery command/action in the popup body.
4. Preserve local state while waiting.
5. Resume the original directive after the operator chooses.
6. Record the selected path in `docs/CHANGELOG.md`.

## Choices

- `A) install/enable dependency now`
- `B) proceed with bounded fallback and clearly mark reduced assurance`
- `C) pause and wait for operator intervention`

Always mark the recommended default option and why.
