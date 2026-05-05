# Security Audit Report — ts-immutable-sdk

**Prepared by**: The Janitor v10.2.0-rc.1  
**Date**: 2026-05-05 UTC  
**Target**: `/tmp/ts-immutable-sdk`  

---

## Executive Summary

The automated scan of **ts-immutable-sdk** identified **60** finding(s) across the following severity tiers:

| Severity | Count |
|----------|-------|
| KevCritical | 58 |
| Critical | 2 |

> **CRITICAL ALERT**: 60 critical-severity finding(s) require immediate remediation before deployment.

## Findings Table

| # | ID | Severity | File | CVSS |
|---|-----|----------|------|------|
| 1 | `security:ssrf_dynamic_url` | KevCritical | config.ts | CVSS 9.0–10.0 (Critical) |
| 2 | `security:ssrf_dynamic_url` | KevCritical | Auth.ts | CVSS 9.0–10.0 (Critical) |
| 3 | `security:ssrf_dynamic_url` | KevCritical | availability.ts | CVSS 9.0–10.0 (Critical) |
| 4 | `security:ssrf_dynamic_url` | KevCritical | useTransakIframe.ts | CVSS 9.0–10.0 (Critical) |
| 5 | `security:ssrf_dynamic_url` | KevCritical | gmpRecovery.ts | CVSS 9.0–10.0 (Critical) |
| 6 | `security:ssrf_dynamic_url` | KevCritical | request.ts | CVSS 9.0–10.0 (Critical) |
| 7 | `security:ssrf_dynamic_url` | KevCritical | relayerClient.ts | CVSS 9.0–10.0 (Critical) |
| 8 | `security:dom_xss_innerHTML` | Critical | embeddedLoginPromptOverlay.ts | CVSS 8.5–9.9 (Critical) |
| 9 | `security:oauth_account_fusion_pretakeover` | KevCritical | callback.tsx | CVSS 9.0–10.0 (Critical) |
| 10 | `security:oauth_account_fusion_pretakeover` | KevCritical | callback.tsx | CVSS 9.0–10.0 (Critical) |
| 11 | `security:oauth_account_fusion_pretakeover` | KevCritical | callback.tsx | CVSS 9.0–10.0 (Critical) |
| 12 | `security:oauth_account_fusion_pretakeover` | KevCritical | callback.tsx | CVSS 9.0–10.0 (Critical) |
| 13 | `security:oauth_account_fusion_pretakeover` | KevCritical | callback.tsx | CVSS 9.0–10.0 (Critical) |
| 14 | `security:oauth_account_fusion_pretakeover` | KevCritical | hooks.tsx | CVSS 9.0–10.0 (Critical) |
| 15 | `security:oauth_account_fusion_pretakeover` | KevCritical | hooks.tsx | CVSS 9.0–10.0 (Critical) |
| 16 | `security:oauth_account_fusion_pretakeover` | KevCritical | hooks.tsx | CVSS 9.0–10.0 (Critical) |
| 17 | `security:oauth_account_fusion_pretakeover` | KevCritical | hooks.tsx | CVSS 9.0–10.0 (Critical) |
| 18 | `security:oauth_account_fusion_pretakeover` | KevCritical | hooks.tsx | CVSS 9.0–10.0 (Critical) |
| 19 | `security:oauth_account_fusion_pretakeover` | KevCritical | hooks.tsx | CVSS 9.0–10.0 (Critical) |
| 20 | `security:oauth_account_fusion_pretakeover` | KevCritical | hooks.tsx | CVSS 9.0–10.0 (Critical) |
| 21 | `security:oauth_account_fusion_pretakeover` | KevCritical | hooks.tsx | CVSS 9.0–10.0 (Critical) |
| 22 | `security:oauth_account_fusion_pretakeover` | KevCritical | hooks.tsx | CVSS 9.0–10.0 (Critical) |
| 23 | `security:oauth_account_fusion_pretakeover` | KevCritical | hooks.tsx | CVSS 9.0–10.0 (Critical) |
| 24 | `security:oauth_account_fusion_pretakeover` | KevCritical | hooks.tsx | CVSS 9.0–10.0 (Critical) |
| 25 | `security:oauth_account_fusion_pretakeover` | KevCritical | idTokenStorage.ts | CVSS 9.0–10.0 (Critical) |
| 26 | `security:oauth_account_fusion_pretakeover` | KevCritical | config.ts | CVSS 9.0–10.0 (Critical) |
| 27 | `security:oauth_account_fusion_pretakeover` | KevCritical | config.ts | CVSS 9.0–10.0 (Critical) |
| 28 | `security:oauth_account_fusion_pretakeover` | KevCritical | config.ts | CVSS 9.0–10.0 (Critical) |
| 29 | `security:oauth_account_fusion_pretakeover` | KevCritical | config.ts | CVSS 9.0–10.0 (Critical) |
| 30 | `security:oauth_account_fusion_pretakeover` | KevCritical | config.ts | CVSS 9.0–10.0 (Critical) |
| 31 | `security:oauth_account_fusion_pretakeover` | KevCritical | config.ts | CVSS 9.0–10.0 (Critical) |
| 32 | `security:oauth_account_fusion_pretakeover` | KevCritical | config.ts | CVSS 9.0–10.0 (Critical) |
| 33 | `security:oauth_account_fusion_pretakeover` | KevCritical | constants.ts | CVSS 9.0–10.0 (Critical) |
| 34 | `security:oauth_account_fusion_pretakeover` | KevCritical | constants.ts | CVSS 9.0–10.0 (Critical) |
| 35 | `security:oauth_account_fusion_pretakeover` | KevCritical | constants.ts | CVSS 9.0–10.0 (Critical) |
| 36 | `security:oauth_account_fusion_pretakeover` | KevCritical | index.ts | CVSS 9.0–10.0 (Critical) |
| 37 | `security:oauth_account_fusion_pretakeover` | KevCritical | index.ts | CVSS 9.0–10.0 (Critical) |
| 38 | `security:oauth_account_fusion_pretakeover` | KevCritical | index.ts | CVSS 9.0–10.0 (Critical) |
| 39 | `security:oauth_account_fusion_pretakeover` | KevCritical | index.ts | CVSS 9.0–10.0 (Critical) |
| 40 | `security:oauth_account_fusion_pretakeover` | KevCritical | index.ts | CVSS 9.0–10.0 (Critical) |
| 41 | `security:oauth_account_fusion_pretakeover` | KevCritical | index.ts | CVSS 9.0–10.0 (Critical) |
| 42 | `security:oauth_account_fusion_pretakeover` | KevCritical | index.ts | CVSS 9.0–10.0 (Critical) |
| 43 | `security:oauth_account_fusion_pretakeover` | KevCritical | index.ts | CVSS 9.0–10.0 (Critical) |
| 44 | `security:oauth_account_fusion_pretakeover` | KevCritical | index.ts | CVSS 9.0–10.0 (Critical) |
| 45 | `security:oauth_account_fusion_pretakeover` | KevCritical | index.ts | CVSS 9.0–10.0 (Critical) |
| 46 | `security:oauth_account_fusion_pretakeover` | KevCritical | index.ts | CVSS 9.0–10.0 (Critical) |
| 47 | `security:oauth_account_fusion_pretakeover` | KevCritical | index.ts | CVSS 9.0–10.0 (Critical) |
| 48 | `security:oauth_account_fusion_pretakeover` | KevCritical | index.ts | CVSS 9.0–10.0 (Critical) |
| 49 | `security:oauth_account_fusion_pretakeover` | KevCritical | index.ts | CVSS 9.0–10.0 (Critical) |
| 50 | `security:oauth_account_fusion_pretakeover` | KevCritical | Auth.ts | CVSS 9.0–10.0 (Critical) |
| 51 | `security:oauth_account_fusion_pretakeover` | KevCritical | index.ts | CVSS 9.0–10.0 (Critical) |
| 52 | `security:oauth_account_fusion_pretakeover` | KevCritical | index.ts | CVSS 9.0–10.0 (Critical) |
| 53 | `security:oauth_account_fusion_pretakeover` | KevCritical | standalone.ts | CVSS 9.0–10.0 (Critical) |
| 54 | `security:oauth_account_fusion_pretakeover` | KevCritical | types.ts | CVSS 9.0–10.0 (Critical) |
| 55 | `security:oauth_account_fusion_pretakeover` | KevCritical | BaseWidgetRoot.ts | CVSS 9.0–10.0 (Critical) |
| 56 | `security:oauth_account_fusion_pretakeover` | KevCritical | BaseWidgetRoot.ts | CVSS 9.0–10.0 (Critical) |
| 57 | `security:oauth_account_fusion_pretakeover` | KevCritical | connectWallet.ts | CVSS 9.0–10.0 (Critical) |
| 58 | `security:oauth_account_fusion_pretakeover` | KevCritical | types.ts | CVSS 9.0–10.0 (Critical) |
| 59 | `security:oauth_account_fusion_pretakeover` | KevCritical | registerZkEvmUser.ts | CVSS 9.0–10.0 (Critical) |
| 60 | `security:non_constant_time_comparison` | Critical | idTokenStorage.ts | CVSS 8.5–9.9 (Critical) |

## Per-Finding Technical Detail

### Finding #1: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `packages/auth-next-server/src/config.ts`  
**Line**: 38  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `packages/auth-next-server/src/config.ts`
- Sink: `security:ssrf_dynamic_url` in `packages/auth-next-server/src/config.ts`

**Call Chain**: packages/auth-next-server/src/config.ts:38

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #2: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `packages/auth/src/Auth.ts`  
**Line**: 677  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `packages/auth/src/Auth.ts`
- Sink: `security:ssrf_dynamic_url` in `packages/auth/src/Auth.ts`

**Call Chain**: packages/auth/src/Auth.ts:677

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #3: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `packages/checkout/sdk/src/availability/availability.ts`  
**Line**: 25  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `packages/checkout/sdk/src/availability/availability.ts`
- Sink: `security:ssrf_dynamic_url` in `packages/checkout/sdk/src/availability/availability.ts`

**Call Chain**: packages/checkout/sdk/src/availability/availability.ts:25

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #4: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `packages/checkout/widgets-lib/src/components/Transak/useTransakIframe.ts`  
**Line**: 106  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `packages/checkout/widgets-lib/src/components/Transak/useTransakIframe.ts`
- Sink: `security:ssrf_dynamic_url` in `packages/checkout/widgets-lib/src/components/Transak/useTransakIframe.ts`

**Call Chain**: packages/checkout/widgets-lib/src/components/Transak/useTransakIframe.ts:106

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #5: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `packages/internal/bridge/sdk/src/lib/gmpRecovery.ts`  
**Line**: 35  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `packages/internal/bridge/sdk/src/lib/gmpRecovery.ts`
- Sink: `security:ssrf_dynamic_url` in `packages/internal/bridge/sdk/src/lib/gmpRecovery.ts`

**Call Chain**: packages/internal/bridge/sdk/src/lib/gmpRecovery.ts:35

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #6: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `packages/internal/metrics/src/utils/request.ts`  
**Line**: 19  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `packages/internal/metrics/src/utils/request.ts`
- Sink: `security:ssrf_dynamic_url` in `packages/internal/metrics/src/utils/request.ts`

**Call Chain**: packages/internal/metrics/src/utils/request.ts:19

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #7: `security:ssrf_dynamic_url`

**Severity**: KevCritical  
**File**: `packages/wallet/src/zkEvm/relayerClient.ts`  
**Line**: 136  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Taint Flow**:

- Source: `url` in `packages/wallet/src/zkEvm/relayerClient.ts`
- Sink: `security:ssrf_dynamic_url` in `packages/wallet/src/zkEvm/relayerClient.ts`

**Call Chain**: packages/wallet/src/zkEvm/relayerClient.ts:136

**Reproduction Command** (AEG-synthesized):

```bash
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

**Recommended Remediation**:

Validate and allowlist all server-side HTTP request destinations. Block RFC-1918 / link-local address ranges at the HTTP client layer. Disable automatic redirect following.

---

### Finding #8: `security:dom_xss_innerHTML`

**Severity**: Critical  
**File**: `packages/auth/src/overlay/embeddedLoginPromptOverlay.ts`  
**Line**: 25  
**CVSS**: CVSS 8.5–9.9 (Critical)  

**Taint Flow**:

- Source: `user_input` in `packages/auth/src/overlay/embeddedLoginPromptOverlay.ts`
- Sink: `security:dom_xss_innerHTML` in `packages/auth/src/overlay/embeddedLoginPromptOverlay.ts`

**Call Chain**: packages/auth/src/overlay/embeddedLoginPromptOverlay.ts:25

**Reproduction Command** (AEG-synthesized):

```bash
cat > janitor-dom-xss-poc.html <<'HTML'
<!doctype html>
<meta charset="utf-8">
<title>Janitor DOM XSS Delivery</title>
<form id="janitor-delivery" method="GET" action="<vulnerable-client-route>">
<input name="user_input" value="<img src=x onerror=alert(1)>">
</form>
<script>document.getElementById('janitor-delivery').submit();</script>
HTML
python3 -m http.server 8765
```

**Recommended Remediation**:

Replace `innerHTML` assignments with `textContent` or DOM API calls. Apply DOMPurify sanitization to all untrusted HTML. Enforce a strict Content-Security-Policy (CSP) header.

---

### Finding #9: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-client/src/callback.tsx`  
**Line**: 77  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #10: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-client/src/callback.tsx`  
**Line**: 95  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #11: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-client/src/callback.tsx`  
**Line**: 160  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #12: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-client/src/callback.tsx`  
**Line**: 176  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #13: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-client/src/callback.tsx`  
**Line**: 179  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #14: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-client/src/hooks.tsx`  
**Line**: 189  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #15: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-client/src/hooks.tsx`  
**Line**: 261  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #16: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-client/src/hooks.tsx`  
**Line**: 408  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #17: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-client/src/hooks.tsx`  
**Line**: 481  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #18: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-client/src/hooks.tsx`  
**Line**: 503  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #19: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-client/src/hooks.tsx`  
**Line**: 506  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #20: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-client/src/hooks.tsx`  
**Line**: 512  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #21: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-client/src/hooks.tsx`  
**Line**: 599  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #22: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-client/src/hooks.tsx`  
**Line**: 618  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #23: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-client/src/hooks.tsx`  
**Line**: 689  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #24: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-client/src/hooks.tsx`  
**Line**: 700  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #25: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-client/src/idTokenStorage.ts`  
**Line**: 4  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #26: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-server/src/config.ts`  
**Line**: 1  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #27: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-server/src/config.ts`  
**Line**: 4  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #28: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-server/src/config.ts`  
**Line**: 84  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #29: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-server/src/config.ts`  
**Line**: 87  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #30: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-server/src/config.ts`  
**Line**: 93  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #31: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-server/src/config.ts`  
**Line**: 96  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #32: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-server/src/config.ts`  
**Line**: 102  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #33: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-server/src/constants.ts`  
**Line**: 21  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #34: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-server/src/constants.ts`  
**Line**: 26  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #35: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-server/src/constants.ts`  
**Line**: 55  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #36: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-server/src/index.ts`  
**Line**: 13  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #37: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-server/src/index.ts`  
**Line**: 15  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #38: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-server/src/index.ts`  
**Line**: 29  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #39: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-server/src/index.ts`  
**Line**: 30  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #40: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-server/src/index.ts`  
**Line**: 34  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #41: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-server/src/index.ts`  
**Line**: 134  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #42: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-server/src/index.ts`  
**Line**: 144  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #43: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-server/src/index.ts`  
**Line**: 183  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #44: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-server/src/index.ts`  
**Line**: 233  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #45: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-server/src/index.ts`  
**Line**: 270  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #46: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-server/src/index.ts`  
**Line**: 302  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #47: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-server/src/index.ts`  
**Line**: 346  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #48: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-server/src/index.ts`  
**Line**: 390  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #49: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth-next-server/src/index.ts`  
**Line**: 484  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #50: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth/src/Auth.ts`  
**Line**: 794  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #51: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth/src/index.ts`  
**Line**: 40  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #52: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth/src/index.ts`  
**Line**: 54  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #53: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth/src/login/standalone.ts`  
**Line**: 4  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #54: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/auth/src/types.ts`  
**Line**: 161  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #55: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/checkout/widgets-lib/src/widgets/BaseWidgetRoot.ts`  
**Line**: 62  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #56: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/checkout/widgets-lib/src/widgets/BaseWidgetRoot.ts`  
**Line**: 221  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #57: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/wallet/src/connectWallet.ts`  
**Line**: 170  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #58: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/wallet/src/types.ts`  
**Line**: 255  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #59: `security:oauth_account_fusion_pretakeover`

**Severity**: KevCritical  
**File**: `packages/wallet/src/zkEvm/user/registerZkEvmUser.ts`  
**Line**: 75  
**CVSS**: CVSS 9.0–10.0 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

### Finding #60: `security:non_constant_time_comparison`

**Severity**: Critical  
**File**: `packages/auth-next-client/src/idTokenStorage.ts`  
**Line**: 5  
**CVSS**: CVSS 8.5–9.9 (Critical)  

**Recommended Remediation**:

Review the flagged code path with a credentialed security engineer. Apply the principle of least privilege and validate all external inputs at trust boundaries.

---

## Certification Statement

This report was generated automatically by **The Janitor v10.2.0-rc.1** using a deterministic static analysis pipeline (AST taint propagation, IFDS data-flow, credential entropy, solidity reentrancy, FFI taint, and IDOR/authz detectors). Scan target: `/tmp/ts-immutable-sdk`. Report date: 2026-05-05 UTC.

**SHA-384 Provenance Seal**: scan artefacts are reproducible — re-running the engine over the same commit will produce an identical finding set for deterministic detectors.

_The Janitor is not a substitute for manual review by a credentialed security engineer. This report constitutes automated pre-audit triage and reduces the scope of a full human engagement._
