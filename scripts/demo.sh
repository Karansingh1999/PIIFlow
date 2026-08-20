#!/usr/bin/env bash
set -u

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

out_dir=".tmp/demo"
mkdir -p "$out_dir"

if [ -z "${UV_CACHE_DIR:-}" ]; then
  export UV_CACHE_DIR="$root/.uv-cache"
fi

uv_bin="${UV:-uv}"
if ! command -v "$uv_bin" >/dev/null 2>&1; then
  printf "uv was not found on PATH. Install uv or set UV to the uv executable path.\n" >&2
  exit 1
fi

run_case() {
  name="$1"
  expected="$2"
  shift 2

  printf "\n== %s ==\n" "$name"
  if "$@"; then
    status=0
  else
    status=$?
  fi

  printf "exit code: %s (expected %s)\n" "$status" "$expected"
  if [ "$status" -ne "$expected" ]; then
    printf "unexpected exit code for %s\n" "$name" >&2
    exit 1
  fi
}

run_case "safe application" 0 \
  "$uv_bin" run piiflow scan examples/safe_app

run_case "vulnerable application" 1 \
  "$uv_bin" run piiflow scan examples/vulnerable_app

run_case "compliant redacted email policy flow" 0 \
  "$uv_bin" run piiflow scan examples/policy_apps/redacted_email.py \
    --policy examples/policies/sanitized_email.yml

run_case "wrong sanitizer policy violation" 1 \
  "$uv_bin" run piiflow scan examples/policy_apps/wrong_email_sanitizer.py \
    --policy examples/policies/sanitized_email.yml

run_case "local financial allow rule" 0 \
  "$uv_bin" run piiflow scan examples/policy_apps/local_financial.py \
    --config examples/policy_apps/local_rules.yml \
    --policy examples/policies/local_model.yml

run_case "JSON output" 0 \
  "$uv_bin" run piiflow scan examples/policy_apps/redacted_email.py \
    --policy examples/policies/sanitized_email.yml \
    --format json \
    --output "$out_dir/redacted_email.json"

printf "\nDemo complete. JSON output: %s\n" "$out_dir/redacted_email.json"
