# Pricing FAQ

---

## Why no per-seat pricing?

Because The Janitor is not metered as a cloud code-analysis service.

Every scan, bounce, and audit runs **locally on your hardware** or on your own
GitHub Actions runner. Optional control-plane features exist (`update-wisdom`,
Governor reporting, webhooks), but those are organization-level integrations,
not per-developer usage meters. The binary sits on your machine; it reads your
repository; core analysis stays local.

Per-seat pricing makes sense for SaaS products that provision server-side
resources per user. We do not. One token, one organization, unlimited developers
and CI runners.

---

## What is the Sovereign / Air-Gap Tier?

The Sovereign / Air-Gap Tier is the procurement path for organizations operating
under **IL5, IL6, FedRAMP High, or equivalent classified-adjacent environments**
where code must never traverse a network boundary — including to a vendor's
license server. The Janitor is **not** FedRAMP-authorized today; this tier is
for organizations that need an offline deployment model while conducting their
own accreditation or enclave-specific review.

**What it includes:**

- **Dual-PQC CBOMs** — CycloneDX v1.6 Cryptography Bills of Materials signed with
  both ML-DSA-65 (FIPS 204) and SLH-DSA-SHAKE-192s (FIPS 205) for long-horizon
  cryptographic assurance.
- **SLSA Level 4 Reproducible Builds** — bit-for-bit deterministic release
  binaries verified via Docker-based dual-build comparison.
- **Jira ASPM Sync** — fingerprint-based deduplication with credential preflight;
  graceful degradation to local-only mode when credentials are absent.
- **Native SCM Publishing** — GitLab and Azure DevOps commit-status verdicts
  auto-detected from CI environment variables.
- **Wasm BYOR Rule Mounting** — bring your own private governance modules;
  pin them with BLAKE3 (`janitor wasm-pin`) and enforce integrity at load time.
- **Offline Replayable Decision Capsules** — tamper-evident audit capsules
  (`janitor export-intel-capsule`) that can be replayed for incident response
  without network access.
- **Air-Gap Intel Transfers** — BLAKE3 + Ed25519 offline wisdom feed
  verification; classified networks receive a signed capsule, not a live pull.
- **SOC 2 readiness mapping materials** on request. No completed SOC 2 Type II
  attestation is claimed today.
- **Dedicated SLA** — 4-hour emergency rotation SLA for confirmed compromises.

**Starting price**: $49,900 / year.

Contact: [sales@thejanitor.app](mailto:sales@thejanitor.app)

Security reviews, pilot deployments, and grant diligence:
[security@thejanitor.app](mailto:security@thejanitor.app)

Pilot evaluation package:

- 30-day proof-backed PR gate trial on one representative repository.
- Authenticated authorization and AI-agent deception witness report.
- Signed CBOM and release verification artifact bundle.
- Weekly KPI review: blocked unsafe PRs, false-positive rate, proof-complete
  findings, and time-to-triage.

---

## Is Open Source use free?

Yes. Permanently.

The Free tier has no time limit, no line-of-code cap, and no account requirement.
`janitor scan`, `janitor clean`, `janitor dedup`, `janitor bounce`, `janitor
dashboard`, and `janitor report` are fully available at zero cost — forever.

What the Free tier does not include is the cryptographic chain of custody
(PQC-signed audit logs, CI/CD compliance attestation, Janitor Sentinel GitHub
App). Those capabilities are what regulators and auditors pay for. The enforcement
engine itself is open.

If you are a public OSS project and need Sentinel for PR gate automation, email
[sales@thejanitor.app](mailto:sales@thejanitor.app) — OSS sponsorship is
evaluated case by case.
