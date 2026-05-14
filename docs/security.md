# Security Posture

This page records the current public trust boundary, the evidence behind public
claims, and the accepted-risk rationale for the GitHub workflow permissions used
by this repository. For private vulnerability intake and coordinated
disclosure, use the repository security policy in
[`SECURITY.md`](https://github.com/janitor-security/the-janitor/blob/main/SECURITY.md).

## Current Data Boundary

- Core analysis runs locally or on the customer's GitHub Actions runner.
- Janitor Sentinel does **not** receive source code, file paths, or symbol names.
- The Governor receives score metadata, fingerprints, and attestation material only.
- Optional outbound traffic is limited to configured integrations such as
  `update-wisdom`, Governor reporting, Jira sync, or webhooks.

## Security Rationale

The public posture is intentionally limited to the guarantees customers and
researchers need to reason about deployment risk:

- Trust decisions are derived from local source, manifests, and workflow
  configuration rather than cloud-hosted inference.
- Evidence generation is reproducible: the same repository state and policy set
  produce the same result.
- Release and documentation publication are separate from scan execution so the
  public website does not become part of the analysis trust boundary.

## Website Deployment Canonical Path

The canonical public website path is MkDocs, not hand-maintained static HTML.
`mkdocs.yml` includes this page as `Security Posture: security.md`, and
`.github/workflows/pages.yml` builds the site with `python3 -m mkdocs build
--strict` before deploying the generated `site/` artifact to GitHub Pages.

Static HTML under `site/` is treated as generated output only. Source-of-truth
security copy lives in this file plus the repository intake policy in
[`SECURITY.md`](https://github.com/janitor-security/the-janitor/blob/main/SECURITY.md).

## Evidence Links

| Control | Evidence |
| --- | --- |
| Workflow linting | [workflow-lint.yml](https://github.com/janitor-security/the-janitor/blob/main/.github/workflows/workflow-lint.yml) |
| Code scanning upload path | [codeql.yml](https://github.com/janitor-security/the-janitor/blob/main/.github/workflows/codeql.yml), [scorecard.yml](https://github.com/janitor-security/the-janitor/blob/main/.github/workflows/scorecard.yml) |
| Release verification | [Releases](https://github.com/janitor-security/the-janitor/releases), `janitor verify-asset` |
| Dependency backlog | [Open Dependabot PRs](https://github.com/janitor-security/the-janitor/pulls?q=is%3Apr+is%3Aopen+author%3Aapp%2Fdependabot) |
| CI health | [GitHub Actions](https://github.com/janitor-security/the-janitor/actions) |

## Workflow Permission Rationale

Workflow-level policy is `contents: read` by default. Elevated scopes are granted
only at job level and only where the workflow function cannot complete without them.

| Workflow | Elevated scopes | Reducible? | Required-by-design rationale |
| --- | --- | --- | --- |
| `janitor.yml` | `contents: write` | No | Commits the generated integrity badge back to `main` after a successful self-scan. |
| `cisa-kev-sync.yml` | `contents: write`, `pull-requests: write` | No | Creates the sync branch and opens the weekly KEV pull request. |
| `dependency-review.yml` | `pull-requests: write` | No | Posts the dependency summary comment to the pull request. |
| `health-signal.yml` | `issues: write`, `actions: read` | No | Opens, comments on, and closes the deduplicated outage tracker based on workflow history. |
| `pages.yml` | `pages: write`, `id-token: write` | No | GitHub Pages deployment requires OIDC plus the Pages publish scope. |
| `scorecard.yml` | `security-events: write`, `id-token: write`, `actions: read` | No | Uploads SARIF into code scanning and uses Scorecard's OIDC/provenance path. |
| `codeql.yml` | `security-events: write`, `actions: read` | No | Uploads CodeQL SARIF and reads workflow metadata for CodeQL orchestration. |

Accepted risk: any job with a write-scoped `GITHUB_TOKEN` can mutate the GitHub
resource it targets if the workflow is compromised. This repository constrains
that risk by keeping write scopes job-local, SHA-pinning actions, and keeping
workflow-level permissions read-only.

## Governance Split

The public governance surface is deliberately narrower than the internal
governance surface.

### Public

- Trust boundary description
- Security rationale
- High-level governance template and disclosure posture

### Private

- Detector thresholds and scoring cutoffs
- Decoy seeds and reconnaissance-fingerprinting material
- Bypass heuristics and suppression rules that would materially aid evasion
- Incident playbooks and operator-only response procedures

This split keeps customers informed without publishing the exact thresholds or
counter-adversarial mechanics that would weaken the platform.

## Compliance Status

- **Available today**: SHA-pinned workflows, workflow linting, CodeQL, Scorecard,
  Dependabot, release asset verification, Dual-PQC CBOM generation, SLSA build provenance.
- **Not certified today**: SOC 2 Type II, FedRAMP authorization.
- **Roadmap**: SOC 2 Type II preparation and FedRAMP Moderate pursuit remain roadmap items, not completed certifications.

## Evaluation Signals

Enterprise and grant reviewers should evaluate Janitor against measurable
security signals rather than a standalone proposal page:

- Zero-upload PR gate evidence from the composite action and Governor Check Run.
- Deterministic proof witnesses for authenticated authorization, vector-store
  tenant isolation, and AI-agent tool-intent violations.
- Reproducible release artifacts, signed CBOMs, and workflow-permission rationale.
- Air-gap posture: local analysis, bounded outbound metadata, and offline audit
  evidence paths.

## Reporting and Navigation

- Repository reporting policy:
  [`SECURITY.md`](https://github.com/janitor-security/the-janitor/blob/main/SECURITY.md)
- Public architecture background: [Architecture](architecture.md)
- Deployment and operator setup: [Setup](setup.md)
- Privacy questions: [privacy@thejanitor.app](mailto:privacy@thejanitor.app)
- Enterprise pilots, grants, and security reviews:
  [security@thejanitor.app](mailto:security@thejanitor.app)
