#!/usr/bin/env bash
# Hermetic secretless-gate contract test for action.yml.
#
# Proves the local-only (Dependabot / secretless) mode of the composite action:
#   1. Exits 0 when the mock janitor emits gate_passed:true  (TP)
#   2. Exits non-zero when gate_passed:false                  (TN rejected)
#   3. Exits non-zero when the bounce output contains no JSON (TN malformed)
#
# No network dependency.  No Governor URL.  No repository secrets required.
# Tests the exact shell logic from action.yml Step 5 ("Execute Stateless Firewall").
set -euo pipefail

PASS=0
FAIL=0
TMPDIR_PARENT=$(mktemp -d)
trap 'rm -rf "${TMPDIR_PARENT}"' EXIT

# ── Helper: run the secretless gate logic inline ──────────────────────────────
# Mirrors the GOVERNOR-absent branch of action.yml Step 5 verbatim.
run_secretless_gate() {
    local janitor_bin="$1"
    local patch_file="$2"
    local timeout_seconds=5
    local bounce_args=(bounce . --patch "${patch_file}" --pr-number 999 --head-sha "abc123")

    BOUNCE_OUT=$(timeout "${timeout_seconds}s" "${janitor_bin}" "${bounce_args[@]}" --format json 2>/dev/null || true)
    BOUNCE_JSON=$(printf '%s\n' "${BOUNCE_OUT}" | sed -n '/^{/,/^}/p')
    if [ -z "${BOUNCE_JSON}" ]; then
        return 1
    fi
    if [ "$(printf '%s\n' "${BOUNCE_JSON}" | jq -er '.gate_passed')" != "true" ]; then
        return 1
    fi
    return 0
}

# ── Test fixture: benign patch ────────────────────────────────────────────────
FIXTURE_PATCH="${TMPDIR_PARENT}/fixture.patch"
cat > "${FIXTURE_PATCH}" <<'PATCH'
diff --git a/src/lib.rs b/src/lib.rs
index 1234abc..deadbee 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,4 @@
 pub fn add(a: i32, b: i32) -> i32 {
+    // deterministic test helper
     a + b
 }
PATCH

# ── Test 1 (TP): gate_passed true → exit 0 ───────────────────────────────────
STUB_PASS="${TMPDIR_PARENT}/janitor_pass"
cat > "${STUB_PASS}" <<'STUB'
#!/usr/bin/env bash
echo '{
  "gate_passed": true,
  "slop_score": 0,
  "antipatterns": 0
}'
STUB
chmod +x "${STUB_PASS}"

if run_secretless_gate "${STUB_PASS}" "${FIXTURE_PATCH}"; then
    echo "PASS: gate_passed=true exits 0"
    PASS=$((PASS + 1))
else
    echo "FAIL: gate_passed=true should exit 0 but exited non-zero"
    FAIL=$((FAIL + 1))
fi

# ── Test 2 (TN): gate_passed false → exit non-zero ───────────────────────────
STUB_FAIL="${TMPDIR_PARENT}/janitor_fail"
cat > "${STUB_FAIL}" <<'STUB'
#!/usr/bin/env bash
echo '{
  "gate_passed": false,
  "slop_score": 42,
  "antipatterns": 3
}'
STUB
chmod +x "${STUB_FAIL}"

if run_secretless_gate "${STUB_FAIL}" "${FIXTURE_PATCH}"; then
    echo "FAIL: gate_passed=false should exit non-zero but exited 0"
    FAIL=$((FAIL + 1))
else
    echo "PASS: gate_passed=false exits non-zero"
    PASS=$((PASS + 1))
fi

# ── Test 3 (TN): malformed output → exit non-zero (fail-closed) ──────────────
STUB_MALFORMED="${TMPDIR_PARENT}/janitor_malformed"
cat > "${STUB_MALFORMED}" <<'STUB'
#!/usr/bin/env bash
echo "ERROR: unexpected panic at src/main.rs:42"
echo "slop_score=99"
STUB
chmod +x "${STUB_MALFORMED}"

if run_secretless_gate "${STUB_MALFORMED}" "${FIXTURE_PATCH}"; then
    echo "FAIL: malformed output should fail-closed but exited 0"
    FAIL=$((FAIL + 1))
else
    echo "PASS: malformed output fails closed (exit non-zero)"
    PASS=$((PASS + 1))
fi

# ── Test 4 (TN): empty output → exit non-zero (fail-closed) ──────────────────
STUB_EMPTY="${TMPDIR_PARENT}/janitor_empty"
cat > "${STUB_EMPTY}" <<'STUB'
#!/usr/bin/env bash
# Simulate a binary that produces no output (e.g. timeout killed it)
:
STUB
chmod +x "${STUB_EMPTY}"

if run_secretless_gate "${STUB_EMPTY}" "${FIXTURE_PATCH}"; then
    echo "FAIL: empty output should fail-closed but exited 0"
    FAIL=$((FAIL + 1))
else
    echo "PASS: empty output fails closed (exit non-zero)"
    PASS=$((PASS + 1))
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "${FAIL}" -gt 0 ]; then
    exit 1
fi
exit 0
