# Crossroads Waiting Rule

Use this rule when execution is blocked by a missing dependency, missing
secret, locked signing key, dirty deploy workspace, ambiguous policy decision,
or any other operator-only choice.

## Non-Terminal Wait

A crossroads is an execution checkpoint, not a final response. The agent MUST
preserve local state and resume the same directive after the operator chooses a
path.

If the host exposes a native interactive choice or permission UI, the agent
MUST use that popup. The popup body must include the blocker, the recommended
default option, why it is recommended, and any external-app command or action
the operator must complete before clicking. The run waits in-place and resumes
automatically after the operator clicks a choice.

If the host does not expose a native popup in the current mode, the agent MUST
log that the popup was unavailable and emulate the same A/B/C checkpoint in
plain text with identical semantics. This fallback is still non-terminal: it is
not a governed final report, it preserves all state, and the next operator
message resumes the same directive from the blocked phase.

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
Always mark one option as recommended and state the reason in the popup or
fallback checkpoint.

## State Contract

- Preserve staged files, branch name, command context, and proof artifacts.
- Record the chosen path in `docs/CHANGELOG.md` before final reporting.
- If the block involves GPG signing, follow
  `.agent_governance/rules/integrity.md` and ask one concrete unlock question
  before retrying the signed commit: `Is the GPG signing key unlocked for the
  next 8 hours?` Resume immediately after the operator confirms the cache is
  valid.
- If the block involves Fly.io deployment, run `flyctl auth whoami` before any
  deploy. If authentication is missing or expired, trigger this Crossroads
  checkpoint immediately. Option A must include the exact recovery command
  `flyctl auth login`, the expected healthy output from `flyctl auth whoami`,
  and whether a native popup was actually shown.
- If the block involves a deploy workspace with unrelated dirty files, do not
  clean or revert them without operator choice.
