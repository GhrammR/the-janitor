# Security Posture

This page records the current public trust boundary, the evidence behind public
claims, and the accepted-risk rationale for the GitHub workflow permissions used
by this repository.

## Current Data Boundary

- Core analysis runs locally or on the customer's GitHub Actions runner.
- Janitor Sentinel does **not** receive source code, file paths, or symbol names.
- The Governor receives score metadata, fingerprints, and attestation material only.
- Optional outbound traffic is limited to configured integrations such as
  `update-wisdom`, Governor reporting, Jira sync, or webhooks.

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

## Compliance Status

- **Available today**: SHA-pinned workflows, workflow linting, CodeQL, Scorecard,
  Dependabot, release asset verification, Dual-PQC CBOM generation, SLSA build provenance.
- **Not certified today**: SOC 2 Type II, FedRAMP authorization.
- **Roadmap**: SOC 2 Type II preparation and FedRAMP Moderate pursuit remain roadmap items, not completed certifications.

## Contact Paths

- Security disclosure: [security@thejanitor.app](mailto:security@thejanitor.app)
- Privacy questions: [privacy@thejanitor.app](mailto:privacy@thejanitor.app)
- Enterprise pilots, grants, and security reviews: [security@thejanitor.app](mailto:security@thejanitor.app)
