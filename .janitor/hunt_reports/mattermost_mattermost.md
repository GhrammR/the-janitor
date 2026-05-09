# Hunt Report: mattermost/mattermost

**Date**: 2026-05-08
**Engine**: v10.2.0-rc.2
**Format**: bugcrowd
**Status**: 1 CANDIDATE finding, 4 LOW_YIELD findings

---

**Summary Title:** TLS verification bypass in S3 file store backend
**VRT Category:** Server Security Misconfiguration > Insecure Transport
**Affected Package / Component:** **github.com/mattermost/mattermost/server/v8** go1.25.9 (`go.mod`)
**Vulnerability Details:**
`InsecureSkipVerify: true` detected at `server/platform/shared/filestore/s3store.go:163`. Server certificate chain and hostname verification is explicitly disabled in the S3 storage backend, allowing a network-adjacent attacker to intercept TLS sessions.
**Business Impact:** If enabled in a production deployment, a MITM attacker on the network path between the Mattermost server and the S3 endpoint can intercept or modify file uploads and downloads, including attachments in private channels.
**Candidate Ledger Gap:** Manual verification required: determine whether `InsecureSkipVerify` is guarded by a configuration flag (e.g. `SkipTLSVerify bool` in site config) and whether that flag is accessible to non-admin users. If the flag is admin-only and off by default, approval is <10%.
**Vulnerability Reproduction:**
```text
grep -n InsecureSkipVerify /tmp/mattermost/server/platform/shared/filestore/s3store.go
# Confirm line 163 sets InsecureSkipVerify: true unconditionally or via a config bool.
# If config-gated, check SystemConsole > File Storage > Enable TLS Skip Verify.
```

---

## Triage Summary (LOW_YIELD items)

| Finding | File | Reason for LOW_YIELD |
|---------|------|----------------------|
| security:git_ref_dependency | webapp/channels/package.json | `marked` is pinned to a commit SHA — this IS a pinned ref, not unpinned |
| security:ics_default_credential | api/v4/source/introduction.yaml:79 | API documentation YAML, not a deployed credential |
| security:model_weight_backdoor | svg_images_components/*.tsx, states.ts | False positive on static SVG/utility TypeScript files |
| security:eval_injection | server/scripts/ldap-check.sh:88 | scripts/ path — deployment script, not remotely reachable |
