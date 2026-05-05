# Security Audit Report — mattermost-boards

**Prepared by**: The Janitor v10.2.0-rc.1  
**Date**: 2026-05-05 UTC  
**Target**: `/tmp/mattermost-boards`  

---

## Executive Summary

The automated scan of **mattermost-boards** identified **56** finding(s) across the following severity tiers:

| Severity | Count |
|----------|-------|
| KevCritical | 45 |
| Critical | 11 |

> **CRITICAL ALERT**: 56 critical-severity finding(s) require immediate remediation before deployment.

## Findings Table

| # | ID | Severity | File | CVSS |
|---|-----|----------|------|------|
| 1 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 2 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 3 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 4 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 5 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 6 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 7 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 8 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 9 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 10 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 11 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 12 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 13 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 14 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 15 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 16 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 17 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 18 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 19 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 20 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 21 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 22 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 23 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 24 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 25 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 26 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 27 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 28 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 29 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 30 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 31 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 32 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 33 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 34 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 35 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 36 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 37 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 38 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 39 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 40 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 41 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 42 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 43 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 44 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 45 | `security:ssrf_dynamic_url` | KevCritical | octoClient.ts | CVSS 9.0–10.0 (Critical) |
| 46 | `security:dom_xss_innerHTML` | Critical | utils.ts | CVSS 8.5–9.9 (Critical) |
| 47 | `security:unpinned_git_dependency` | Critical | package.json | CVSS 8.5–9.9 (Critical) |
| 48 | `security:react_xss_dangerous_html` | Critical | index.tsx | CVSS 8.5–9.9 (Critical) |
| 49 | `security:react_xss_dangerous_html` | Critical | index.tsx | CVSS 8.5–9.9 (Critical) |
| 50 | `security:react_xss_dangerous_html` | Critical | index.tsx | CVSS 8.5–9.9 (Critical) |
| 51 | `security:react_xss_dangerous_html` | Critical | index.tsx | CVSS 8.5–9.9 (Critical) |
| 52 | `security:react_xss_dangerous_html` | Critical | index.tsx | CVSS 8.5–9.9 (Critical) |
| 53 | `security:react_xss_dangerous_html` | Critical | index.tsx | CVSS 8.5–9.9 (Critical) |
| 54 | `security:react_xss_dangerous_html` | Critical | index.tsx | CVSS 8.5–9.9 (Critical) |
| 55 | `security:react_xss_dangerous_html` | Critical | boardsUnfurl.tsx | CVSS 8.5–9.9 (Critical) |
| 56 | `security:react_xss_dangerous_html` | Critical | rhsChannelBoardItem.tsx | CVSS 8.5–9.9 (Critical) |

## Per-Finding Technical Detail

### Finding #1: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 74  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:74

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #2: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 93  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:93

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #3: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 107  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:107

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #4: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 122  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:122

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #5: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 134  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:134

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #6: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 182  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:182

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #7: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 192  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:192

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #8: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 202  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:202

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #9: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 213  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:213

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #10: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 228  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:228

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #11: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 243  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:243

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #12: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 316  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:316

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #13: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 325  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:325

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #14: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 334  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:334

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #15: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 475  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:475

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #16: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 548  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:548

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #17: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 558  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:558

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #18: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 575  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:575

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #19: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 595  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:595

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #20: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 668  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:668

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #21: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 683  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:683

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #22: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 693  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:693

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #23: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 706  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:706

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #24: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 716  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:716

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #25: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 734  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:734

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #26: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 757  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:757

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #27: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 779  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:779

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #28: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 797  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:797

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #29: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 848  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:848

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #30: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 859  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:859

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #31: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 887  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:887

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #32: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 903  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:903

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #33: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 932  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:932

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #34: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 946  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:946

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #35: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 960  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:960

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #36: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 974  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:974

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #37: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 984  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:984

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #38: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 997  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:997

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #39: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 1011  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:1011

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #40: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 1024  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:1024

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #41: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 1032  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:1032

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #42: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 1044  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:1044

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #43: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 1057  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:1057

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #44: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 1067  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:1067

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #45: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `webapp/src/octoClient.ts`  
**Line**: 1076  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `webapp/src/octoClient.ts`
- Sink: `security:ssrf_dynamic_url` in `webapp/src/octoClient.ts`

**Call Chain**: webapp/src/octoClient.ts:1076

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #46: `security:dom_xss_innerHTML`

**Severity**: Critical  
**File**: `webapp/src/utils.ts`  
**Line**: 143  
**CVSS**: CVSS 8.5–9.9 (Critical)  

**Taint Flow**:

- Source: `user_input` in `webapp/src/utils.ts`
- Sink: `security:dom_xss_innerHTML` in `webapp/src/utils.ts`

**Call Chain**: webapp/src/utils.ts:143

**Reproduction Command** (AEG-synthesized):

```bash
cat > janitor-dom-xss-poc.html <<'HTML'
<!doctype html>
<meta charset="utf-8">
<title>Janitor DOM XSS Delivery</title>
<form id="janitor-delivery" method="GET" action="/">
<input name="user_input" value="<img src=x onerror=alert(1)>">
</form>
<script>document.getElementById('janitor-delivery').submit();</script>
HTML
python3 -m http.server 8765
```

**Recommended Remediation**:

Replace `innerHTML` assignments with `textContent` or DOM API calls. Apply DOMPurify sanitization to all untrusted HTML. Enforce a strict Content-Security-Policy (CSP) header.

---

### Finding #47: `security:unpinned_git_dependency`

**Severity**: Critical  
**File**: `webapp/package.json`  
**Line**: 139  
**CVSS**: CVSS 8.5–9.9 (Critical)  

**Taint Flow**:

- Source: `raw_git_dependency` in `webapp/package.json`
- Sink: `security:unpinned_git_dependency` in `webapp/package.json`

**Call Chain**: webapp/package.json:139

**Reproduction Command** (AEG-synthesized):

```bash
diff --git a/webapp/package.json b/webapp/package.json
--- a/webapp/package.json
+++ b/webapp/package.json
@@
-		"eslint-plugin-mattermost": "github:mattermost/eslint-plugin-mattermost#23abcf9988f7fa00d26929f11841aab7ccb16b2b",
+		"eslint-plugin-mattermost": "github:mattermost/eslint-plugin-mattermost#23abcf9988f7fa00d26929f11841aab7ccb16b2b",
```

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #48: `security:react_xss_dangerous_html`

**Severity**: Critical  
**File**: `webapp/src/components/blocksEditor/blocks/checkbox/index.tsx`  
**Line**: 40  
**CVSS**: CVSS 8.5–9.9 (Critical)  

**Recommended Remediation**:

Replace `innerHTML` assignments with `textContent` or DOM API calls. Apply DOMPurify sanitization to all untrusted HTML. Enforce a strict Content-Security-Policy (CSP) header.

---

### Finding #49: `security:react_xss_dangerous_html`

**Severity**: Critical  
**File**: `webapp/src/components/blocksEditor/blocks/h1/index.tsx`  
**Line**: 23  
**CVSS**: CVSS 8.5–9.9 (Critical)  

**Recommended Remediation**:

Replace `innerHTML` assignments with `textContent` or DOM API calls. Apply DOMPurify sanitization to all untrusted HTML. Enforce a strict Content-Security-Policy (CSP) header.

---

### Finding #50: `security:react_xss_dangerous_html`

**Severity**: Critical  
**File**: `webapp/src/components/blocksEditor/blocks/h2/index.tsx`  
**Line**: 23  
**CVSS**: CVSS 8.5–9.9 (Critical)  

**Recommended Remediation**:

Replace `innerHTML` assignments with `textContent` or DOM API calls. Apply DOMPurify sanitization to all untrusted HTML. Enforce a strict Content-Security-Policy (CSP) header.

---

### Finding #51: `security:react_xss_dangerous_html`

**Severity**: Critical  
**File**: `webapp/src/components/blocksEditor/blocks/h3/index.tsx`  
**Line**: 23  
**CVSS**: CVSS 8.5–9.9 (Critical)  

**Recommended Remediation**:

Replace `innerHTML` assignments with `textContent` or DOM API calls. Apply DOMPurify sanitization to all untrusted HTML. Enforce a strict Content-Security-Policy (CSP) header.

---

### Finding #52: `security:react_xss_dangerous_html`

**Severity**: Critical  
**File**: `webapp/src/components/blocksEditor/blocks/quote/index.tsx`  
**Line**: 23  
**CVSS**: CVSS 8.5–9.9 (Critical)  

**Recommended Remediation**:

Replace `innerHTML` assignments with `textContent` or DOM API calls. Apply DOMPurify sanitization to all untrusted HTML. Enforce a strict Content-Security-Policy (CSP) header.

---

### Finding #53: `security:react_xss_dangerous_html`

**Severity**: Critical  
**File**: `webapp/src/components/blocksEditor/blocks/text-dev/index.tsx`  
**Line**: 22  
**CVSS**: CVSS 8.5–9.9 (Critical)  

**Recommended Remediation**:

Replace `innerHTML` assignments with `textContent` or DOM API calls. Apply DOMPurify sanitization to all untrusted HTML. Enforce a strict Content-Security-Policy (CSP) header.

---

### Finding #54: `security:react_xss_dangerous_html`

**Severity**: Critical  
**File**: `webapp/src/components/blocksEditor/blocks/text/index.tsx`  
**Line**: 24  
**CVSS**: CVSS 8.5–9.9 (Critical)  

**Recommended Remediation**:

Replace `innerHTML` assignments with `textContent` or DOM API calls. Apply DOMPurify sanitization to all untrusted HTML. Enforce a strict Content-Security-Policy (CSP) header.

---

### Finding #55: `security:react_xss_dangerous_html`

**Severity**: Critical  
**File**: `webapp/src/components/boardsUnfurl/boardsUnfurl.tsx`  
**Line**: 209  
**CVSS**: CVSS 8.5–9.9 (Critical)  

**Recommended Remediation**:

Replace `innerHTML` assignments with `textContent` or DOM API calls. Apply DOMPurify sanitization to all untrusted HTML. Enforce a strict Content-Security-Policy (CSP) header.

---

### Finding #56: `security:react_xss_dangerous_html`

**Severity**: Critical  
**File**: `webapp/src/components/rhsChannelBoardItem.tsx`  
**Line**: 108  
**CVSS**: CVSS 8.5–9.9 (Critical)  

**Recommended Remediation**:

Replace `innerHTML` assignments with `textContent` or DOM API calls. Apply DOMPurify sanitization to all untrusted HTML. Enforce a strict Content-Security-Policy (CSP) header.

---

## Certification Statement

This report was generated automatically by **The Janitor v10.2.0-rc.1** using a deterministic static analysis pipeline (AST taint propagation, IFDS data-flow, credential entropy, solidity reentrancy, FFI taint, and IDOR/authz detectors). Scan target: `/tmp/mattermost-boards`. Report date: 2026-05-05 UTC.

**SHA-384 Provenance Seal**: scan artefacts are reproducible — re-running the engine over the same commit will produce an identical finding set for deterministic detectors.

_The Janitor is not a substitute for manual review by a credentialed security engineer. This report constitutes automated pre-audit triage and reduces the scope of a full human engagement._
