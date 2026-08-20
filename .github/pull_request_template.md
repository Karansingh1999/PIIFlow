## Summary

Describe the change and why it is needed.

## Scope

- [ ] Analyzer behavior
- [ ] Rules
- [ ] Policy model
- [ ] Benchmarks
- [ ] Documentation
- [ ] Packaging or CI

## Verification

- [ ] `uv run ruff format --check .`
- [ ] `uv run ruff check .`
- [ ] `uv run mypy src/piiflow benchmarks`
- [ ] `uv run pytest --cov=piiflow --cov-report=term-missing --cov-fail-under=90`
- [ ] `uv run python benchmarks/run.py --partition all --system all`
- [ ] `uv run python benchmarks/run_policy.py --system all`
- [ ] `uv build`

## Benchmark Integrity

- [ ] I did not change benchmark labels to improve metrics.
- [ ] I did not add benchmark-specific logic to production code.
- [ ] Any benchmark content change is intentional and explained.

## Privacy And Security

- [ ] Examples and tests use synthetic data only.
- [ ] No credentials, real PII, private keys, caches, virtual environments, or temporary files are included.
