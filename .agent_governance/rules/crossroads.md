# Crossroads Waiting Rule

Use this rule when execution is blocked by a missing dependency, missing
secret, locked signing key, dirty deploy workspace, ambiguous policy decision,
or any other operator-only choice.

## Non-Terminal Wait

A crossroads is an execution checkpoint, not a final response. The agent MUST
preserve local state and resume the same directive after the operator chooses a
path.

If the host exposes an interactive choice UI, the agent MUST use it so the run
waits in-place and continues automatically after the operator clicks a choice.
If no interactive choice UI is available, emit exactly one multiple-choice
question and no final report; resume immediately when the operator replies with
the selected letter.

When the blocker is a permission, signing-key, or external-login handoff, the
preferred implementation is the same mid-prompt waiting phase as a permissions
popup: request the enabling action, leave the command/session pending, and
resume the directive when the operator completes it. Do not skip release,
deploy, or signing steps merely because the key or session is currently locked.

## Choice Contract

Ask exactly one question with these choices unless a narrower governance rule
defines more specific labels:

- `A) install/enable dependency now`
- `B) proceed with bounded fallback and clearly mark reduced assurance`
- `C) pause and wait for operator intervention`

Do not ask a free-form question when one of these choices can unblock the run.
Do not silently choose a reduced-assurance path.

## State Contract

- Preserve staged files, branch name, command context, and proof artifacts.
- Record the chosen path in `docs/CHANGELOG.md` before final reporting.
- If the block involves GPG signing, follow
  `.agent_governance/rules/integrity.md` and ask one concrete unlock question
  before retrying the signed commit: `Is the GPG signing key unlocked for the
  next 8 hours?` Resume immediately after the operator confirms the cache is
  valid.
- If the block involves a deploy workspace with unrelated dirty files, do not
  clean or revert them without operator choice.
