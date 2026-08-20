# Contributing

Thank you for improving PIIFlow. Keep changes scoped, tested, reproducible, and
honest about the analyzer's bounded semantics.

## Development Setup

```bash
uv sync --extra dev
```

PIIFlow supports Python 3.11 and newer. The analyzer scans source code statically;
do not add examples or tests that require API keys, network calls, or execution of
the target application.

## Quality Checks

Run these before opening a pull request:

```bash
uv run ruff format .
uv run ruff format --check .
uv run ruff check .
uv run mypy src/piiflow benchmarks
uv run pytest --cov=piiflow --cov-report=term-missing --cov-fail-under=90
uv run python benchmarks/run.py --partition all --system all
uv run python benchmarks/run_policy.py --system all
uv build
```

For a fast local loop, run the most relevant unit or integration tests first,
then run the full gate before submitting.

## Benchmark Integrity Rules

- Do not change benchmark labels to improve PIIFlow metrics.
- Do not remove difficult cases because the analyzer misses them.
- Do not add benchmark-specific logic to production code.
- Label changes are allowed only for objective source-code labeling mistakes.
- Original benchmark hashes and policy benchmark hashes should remain stable
  unless a benchmark change is intentional and explicitly reviewed.
- Generated reports should be reproducible from the benchmark runners.

## Adding Rules

Source, sink, and sanitizer rule changes should include:

- A focused test case.
- A short explanation of the modeled SDK or helper.
- Provider and trust-zone metadata for LLM sinks when applicable.
- Conservative defaults when a provider or trust boundary is not known.

Sanitizer rules should represent real, intentional removal or masking of the
specific sensitive category. Hashing and encoding are not sanitizers by default.

## Pull Request Checklist

- [ ] The change is scoped and does not add unrelated analyzer behavior.
- [ ] Tests were added or updated for behavior changes.
- [ ] Ruff, mypy, pytest coverage, benchmarks, and build pass.
- [ ] Benchmark labels were not changed to improve metrics.
- [ ] Documentation was updated for user-visible behavior.
- [ ] Examples use synthetic data only.
- [ ] No credentials, real PII, proprietary snippets, caches, virtual
      environments, or generated temporary files are included.
- [ ] Security-sensitive reports follow `SECURITY.md`.

## Responsible Disclosure

Please do not publish exploit details, private source code, real PII, credentials,
or private keys in public issues. Follow [SECURITY.md](SECURITY.md) for security
reporting guidance.
