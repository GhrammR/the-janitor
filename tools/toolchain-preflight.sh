#!/usr/bin/env bash
set -euo pipefail

TOOL_ROOT="${JANITOR_TOOL_ROOT:-${HOME}/.local/share/janitor-tools}"
LOCAL_BIN="${JANITOR_LOCAL_BIN:-${HOME}/.local/bin}"

failures=0

report_fail() {
  printf 'toolchain-preflight:error:%s\n' "$1" >&2
  failures=1
}

reject_tmp_path() {
  local tool="$1"
  local path="$2"
  if [[ "${path}" == /tmp/* ]]; then
    report_fail "${tool} resolves to temporary path ${path}; install it durably before continuing."
  fi
}

require_executable() {
  local tool="$1"
  local stable_path="$2"
  local remediation="$3"
  local resolved
  resolved="$(command -v "${tool}" 2>/dev/null || true)"
  if [[ -z "${resolved}" && -x "${stable_path}" ]]; then
    resolved="${stable_path}"
  fi
  if [[ -z "${resolved}" ]]; then
    report_fail "${tool} missing. Remediation: ${remediation}"
    return
  fi
  reject_tmp_path "${tool}" "${resolved}"
  printf 'toolchain-preflight:ok:%s:%s\n' "${tool}" "${resolved}"
}

if ! cargo kani --version >/dev/null 2>&1; then
  report_fail "kani missing. Remediation: cargo install --locked kani-verifier && cargo kani setup"
else
  kani_bin="$(command -v cargo-kani 2>/dev/null || true)"
  if [[ -n "${kani_bin}" ]]; then
    reject_tmp_path "cargo-kani" "${kani_bin}"
    printf 'toolchain-preflight:ok:kani:%s\n' "${kani_bin}"
  else
    printf 'toolchain-preflight:ok:kani:cargo-subcommand\n'
  fi
fi

require_executable \
  "z3" \
  "${TOOL_ROOT}/z3-venv/bin/z3" \
  "python3 -m venv ${TOOL_ROOT}/z3-venv && ${TOOL_ROOT}/z3-venv/bin/python -m pip install --upgrade pip z3-solver && ln -sf ${TOOL_ROOT}/z3-venv/bin/z3 ${LOCAL_BIN}/z3"

require_executable \
  "shellcheck" \
  "${LOCAL_BIN}/shellcheck" \
  "install ShellCheck 0.10.0 or newer into ${LOCAL_BIN}/shellcheck; do not use /tmp-only binaries"

if [[ "${failures}" -ne 0 ]]; then
  exit 1
fi
