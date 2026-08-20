# Reproducibility Guide

This guide describes how to reproduce the PIIFlow v0.3.0 checks from a clean
repository checkout. Commands are repository-relative and avoid local absolute
paths.

## Requirements

- Python 3.11 or newer.
- `uv`.
- A POSIX shell, PowerShell, or GitHub Actions runner.

Install `uv` if needed:

```bash
python -m pip install uv
```

On Windows PowerShell:

```powershell
py -m pip install uv
```

## Environment Setup

```bash
uv sync --extra dev
```

## Code Quality

```bash
uv run ruff format .
uv run ruff format --check .
uv run ruff check .
uv run mypy src/piiflow benchmarks
```

## Tests And Coverage

```bash
uv run pytest --cov=piiflow --cov-report=term-missing --cov-fail-under=90
```

Expected v0.3.0 result: 104 tests pass with 92.05% coverage. Coverage may vary
slightly if the toolchain changes, but the configured gate is 90%.

## Examples

Expected exit codes:

```bash
uv run piiflow scan examples/safe_app
uv run piiflow scan examples/vulnerable_app
uv run piiflow scan examples/policy_apps/redacted_email.py --policy examples/policies/sanitized_email.yml
uv run piiflow scan examples/policy_apps/wrong_email_sanitizer.py --policy examples/policies/sanitized_email.yml
uv run piiflow scan examples/policy_apps/local_financial.py --config examples/policy_apps/local_rules.yml --policy examples/policies/local_model.yml
```

Expected codes:

- safe application: `0`
- vulnerable application: `1`
- compliant redacted-email policy flow: `0`
- wrong-sanitizer policy flow: `1`
- local financial-data allow rule: `0`

Run the scripted demo:

```bash
scripts/demo.sh
```

On Windows PowerShell:

```powershell
.\scripts\demo.ps1
```

If local execution policy blocks script execution:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\demo.ps1
```

## Original Benchmark

```bash
uv run python benchmarks/run.py --partition all --system all
```

Expected `piiflow` metrics on the frozen 90-case benchmark:

- Precision: `0.9545454545454546`
- Recall: `0.84`
- F1: `0.8936170212765958`
- Accuracy: `0.8888888888888888`
- TP: `42`
- FP: `2`
- TN: `38`
- FN: `8`

Expected hashes:

- Manifest:
  `2335f30a119652db32aca3163e4b1a4d91a1e2bb8331cec51d247cd444ee51c7`
- Content:
  `a34c9817f0da31aaf4bd8a9590796614c62cbf33137b6486c3192d794f361f94`

Verify hashes from generated metrics:

```bash
python -c "import json; m=json.load(open('benchmarks/results/metrics.json')); assert m['metadata']['manifest_hash']=='2335f30a119652db32aca3163e4b1a4d91a1e2bb8331cec51d247cd444ee51c7'; assert m['metadata']['benchmark_content_hash']=='a34c9817f0da31aaf4bd8a9590796614c62cbf33137b6486c3192d794f361f94'"
```

## Policy Benchmark

```bash
uv run python benchmarks/run_policy.py --system all
```

Expected policy benchmark size: 36 cases, with 24 in-scope cases, 12 challenge
cases, 20 violations, and 16 compliant flows.

Expected `policy_blind` metrics:

- Precision: `0.5555555555555556`
- Recall: `1.0`
- F1: `0.7142857142857143`
- Accuracy: `0.5555555555555556`

Expected `piiflow_policy` metrics:

- Precision: `1.0`
- Recall: `1.0`
- F1: `1.0`
- Accuracy: `1.0`
- TP: `20`
- FP: `0`
- TN: `16`
- FN: `0`

Expected hashes:

- Manifest:
  `694cf6af4faa5cf7e002a57d650ee3e6ad7aa1204b9d0db0f2c96edcc20a3511`
- Content:
  `be63a102eff6f4c89100221f153f713dda74475662c5783c257d46efd2eddc66`

Verify hashes from generated metrics:

```bash
python -c "import json; m=json.load(open('benchmarks/results/phase2b2_policy/metrics.json')); assert m['metadata']['manifest_hash']=='694cf6af4faa5cf7e002a57d650ee3e6ad7aa1204b9d0db0f2c96edcc20a3511'; assert m['metadata']['policy_content_hash']=='be63a102eff6f4c89100221f153f713dda74475662c5783c257d46efd2eddc66'"
```

## Determinism Check

```bash
uv run python benchmarks/run_policy.py --system all --output-directory benchmarks/results/policy_determinism_a
uv run python benchmarks/run_policy.py --system all --output-directory benchmarks/results/policy_determinism_b
```

Compare `case_id`, `system`, predicted status, outcome, and predicted
categories. Runtime values are intentionally excluded from deterministic
comparison.

## Build

```bash
uv build
```

Expected artifacts:

- `dist/piiflow-0.3.0.tar.gz`
- `dist/piiflow-0.3.0-py3-none-any.whl`

## Wheel Smoke Test

Use a temporary environment outside packaged project content. On POSIX shells:

```bash
tmpenv="$(mktemp -d)"
uv venv "$tmpenv"
uv pip install --python "$tmpenv/bin/python" dist/piiflow-0.3.0-py3-none-any.whl
"$tmpenv/bin/piiflow" scan --help
"$tmpenv/bin/piiflow" scan examples/safe_app
"$tmpenv/bin/piiflow" scan examples/policy_apps/redacted_email.py --policy examples/policies/sanitized_email.yml
"$tmpenv/bin/python" -c "from piiflow.config import load_config; import piiflow; assert piiflow.__version__ == '0.3.0'; assert load_config().version == 1"
```

On PowerShell:

```powershell
$tmpenv = Join-Path ([System.IO.Path]::GetTempPath()) ("piiflow-wheel-" + [guid]::NewGuid())
uv venv $tmpenv
uv pip install --python (Join-Path $tmpenv "Scripts\python.exe") dist/piiflow-0.3.0-py3-none-any.whl
& (Join-Path $tmpenv "Scripts\piiflow.exe") scan --help
& (Join-Path $tmpenv "Scripts\piiflow.exe") scan examples/safe_app
& (Join-Path $tmpenv "Scripts\piiflow.exe") scan examples/policy_apps/redacted_email.py --policy examples/policies/sanitized_email.yml
& (Join-Path $tmpenv "Scripts\python.exe") -c "from piiflow.config import load_config; import piiflow; assert piiflow.__version__ == '0.3.0'; assert load_config().version == 1"
```

Malformed policy smoke:

```bash
printf "version: 1\ndefault_action: maybe\nrules: []\n" > /tmp/piiflow-bad-policy.yml
uv run piiflow scan examples/safe_app --policy /tmp/piiflow-bad-policy.yml
```

Expected exit code: `2`, with no traceback.

## Timing Variability

Benchmark runtimes are small and can vary by Python version, CPU, filesystem,
antivirus, and whether dependencies are already cached. Hashes and case outcomes
are the reproducibility targets; timings are secondary diagnostics.
