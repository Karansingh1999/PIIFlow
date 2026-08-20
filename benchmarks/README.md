# PIIFlow-Bench

PIIFlow-Bench is a reproducible benchmark for measuring privacy-flow detection in
synthetic Python LLM application snippets. It evaluates PIIFlow against labeled source
files, two intentionally weak transparent baselines, and a legacy-mode ablation.

The policy benchmark is separate. It measures whether detected sensitive flows are
classified as policy violations or compliant audit records under declared YAML policies.

## Design Principles

- Labels are written independently from analyzer predictions.
- Labels must not be changed merely to improve metrics.
- Difficult cases remain in the benchmark and are reported as failures when missed.
- Benchmark systems never receive expected labels.
- Benchmark code is never executed as application code; all systems analyze source
  statically.
- Results are generated from actual evaluation output.

## Partitions

- `in_scope`: behavior PIIFlow officially claims to support, including request
  sources, simple propagation, sanitizers, local helpers, async handlers, method binding,
  imports, and supported sink patterns.
- `challenge`: documented unsupported or partially supported behavior such as dynamic
  features, reflection, closures, generators, exception flow, decorators,
  framework-generated values, and stress cases around the bounds of structured state.

## Labeling Rules

A positive case contains at least one unsanitized privacy leak according to the case
source and description. A negative case contains no unsanitized privacy leak. Sanitized
flows are safe for binary evaluation. Labels record expected privacy categories and
expected unsanitized-finding bounds.

Labels must not be edited based on PIIFlow, lexical baseline, or direct-flow baseline
output. Label changes require an objective source-code labeling mistake and should be
reviewed in the manifest and case file together.

## Case Format

Each manifest record has a unique ID, relative path, partition, family, description,
expected label, finding bounds, and tags:

```yaml
id: in_scope_direct_json_email_001
path: cases/in_scope/in_scope_direct_json_email_001.py
partition: in_scope
family: direct_request_subscript
description: Direct email from request JSON reaches OpenAI Responses input.
expected:
  vulnerable: true
  categories:
    - EMAIL
  minimum_unsanitized_findings: 1
tags:
  - request_json
  - openai
  - email
```

Case paths may be a single Python file or a small directory when import behavior requires
multiple files.

## Baselines

- `lexical`: flags a case when a sensitive-name token and an LLM sink token co-occur in
  source text. It performs no data-flow analysis.
- `direct`: parses with `ast` and detects only request sources directly inside configured
  sink arguments. It performs no assignment, container, sanitizer, or interprocedural
  reasoning.
- `piiflow_legacy`: runs PIIFlow with structured state disabled, preserving the
  field-insensitive ablation behavior used for comparison with the Phase 2A analyzer.
- `piiflow`: runs the default structured PIIFlow analyzer.

The baselines are intentionally simple and are not state-of-the-art static analyzers.

## Metrics And Formulas

Primary case-level metrics use:

- Precision: `TP / (TP + FP)`
- Recall: `TP / (TP + FN)`
- F1: `2 * precision * recall / (precision + recall)`
- Accuracy: `(TP + TN) / total`
- Specificity: `TN / (TN + FP)`
- False-positive rate: `FP / (FP + TN)`
- False-negative rate: `FN / (FN + TP)`

Zero denominators produce `0.0` rather than an exception.

The evaluator also reports category-level precision/recall/F1, partition and family
metrics, sink-tag metrics, runtime summaries, errors, false-positive IDs,
false-negative IDs, category mismatches, unexpected findings, and finding-bound
violations.

## Reproduction

```bash
uv run python benchmarks/run.py --partition all --system all
uv run python benchmarks/run_policy.py --system all
```

Useful options:

```text
--manifest PATH
--partition all|in_scope|challenge
--system all|piiflow|piiflow_legacy|lexical|direct
--output-directory PATH
--fail-on-invalid-manifest
--limit N
--help
```

## Result Files

A complete run writes:

- `benchmarks/results/metrics.json`
- `benchmarks/results/report.md`
- `benchmarks/results/case_results.jsonl`

Metadata includes Python, platform, PIIFlow version, Git commit when available, manifest
version, manifest SHA-256, benchmark-content SHA-256, selected systems, and partition.

Phase 2B1 keeps the Phase 2A snapshot under `benchmarks/results/baseline_v0.1.0/` and
writes the structured comparison run under `benchmarks/results/phase2b1_structured/`.
The comparison report is `benchmarks/results/phase2b1_comparison.md`.

On the frozen 90-case benchmark, Phase 2B1 structured PIIFlow reported precision 0.955,
recall 0.840, F1 0.894, and accuracy 0.889 overall. In-scope precision, recall, and F1
remained 1.000. Challenge precision, recall, and F1 were 0.750, 0.429, and 0.545.
False positives removed: `challenge_collection_alias_safe_011` and
`challenge_dict_field_safe_001`. False negatives removed:
`challenge_attribute_storage_vulnerable_002` and `challenge_request_alias_vulnerable_003`.

## Policy Benchmark

The Phase 2B2 policy benchmark lives under `benchmarks/policy_cases/` with labels in
`benchmarks/policy_manifest.yml`. It does not modify the frozen 90-case flow benchmark.

Systems:

- `policy_blind`: treats every detected sensitive LLM flow as prohibited.
- `piiflow_policy`: evaluates the supplied policy for each detected flow.

The target label is `violation` or `compliant`. Metrics are reported overall and by
partition, action, provider, trust zone, and sensitive-data category.

The generated Phase 2B2 benchmark contains 36 cases: 24 in-scope, 12 challenge, 20
violations, and 16 compliant flows. In the current run, `policy_blind` reached precision
0.556, recall 1.000, F1 0.714, and accuracy 0.556. `piiflow_policy` reached precision,
recall, F1, and accuracy of 1.000. This is a scoped result on a small synthetic policy
benchmark and does not imply perfect real-world policy classification.

## Contributing A Case

Add a focused source file under `benchmarks/cases/in_scope` or
`benchmarks/cases/challenge`, then add one manifest entry. Prefer one principal behavior
per case. Include a clear description, expected categories, finding bounds, family, and
tags. Review the label from source code, not from analyzer output.

## Threats To Validity

- Benchmark cases are synthetic and smaller than production repositories.
- The analyzer authors also constructed the benchmark.
- Baselines are intentionally simple and are not state-of-the-art analyzers.
- Python dynamic behavior is only partially represented.
- Case-level binary metrics do not fully measure source-to-sink path quality.
- Similarity between development tests and benchmark cases may inflate performance.
- The challenge set is not exhaustive.
- Category labels may not capture every privacy-policy nuance.
- High performance does not imply legal or regulatory compliance.
- Results must not be generalized to other programming languages.
- Benchmark performance does not prove superiority over CodeQL, Pysa, Semgrep, or
  commercial systems.

## Known Limitations

The benchmark measures PIIFlow honestly. It does not rewrite labels, add runtime
tracing, infer semantic sensitivity with an LLM, model vector stores, or evaluate
state-of-the-art static-analysis systems.
