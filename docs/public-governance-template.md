# Public Governance Template

Use this template when publishing a sanitized subset of internal governance.
It is intentionally safe for public release: it describes principles and
controls, but omits detector thresholds, campaign targets, decoy seeds, and
internal response heuristics.

## 1. Governance Scope

- Repositories covered
- CI systems covered
- Public policy owner
- Security disclosure contact

## 2. Security Principles

- Default-deny workflow permissions
- SHA-pinned third-party actions
- Runner-side analysis; no source upload
- Reproducible release verification
- Minimum-privilege automation tokens

## 3. Data Handling Boundary

- What data is processed locally
- What metadata leaves the runner
- What is never transmitted
- Optional integrations and their data classes

## 4. CI Enforcement Controls

| Control | Public description | Evidence link |
| --- | --- | --- |
| Workflow lint | YAML validation, actionlint, SHA-pin checks | link |
| Code scanning | CodeQL / Scorecard / dependency review | link |
| Release provenance | Signed assets and verification command | link |

## 5. Workflow Permission Policy

State the rule in public:

- Workflow-level permissions are read-only by default.
- Any write-scoped job must carry an inline rationale comment.
- Each write scope must be mapped to a concrete GitHub resource mutation.

Do **not** publish:

- secret names
- bypass conditions
- internal branch naming conventions
- enforcement thresholds

## 6. Compliance Boundary

- What is certified today
- What is monitored continuously
- What remains roadmap only

## 7. What Is Deliberately Omitted

- Detector thresholds and scoring weights
- Internal campaign ledgers or target lists
- Decoy seeds, deception content, or honeypot logic
- Incident-response timing heuristics beyond the public disclosure policy
- Any rule text that would materially help an attacker shape a bypass
