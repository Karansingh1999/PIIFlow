# PIIFlow v0.3.0 Technical Report

This document summarizes the design and evaluation of PIIFlow v0.3.0. It is a
project technical report, not a peer-reviewed paper.

## Abstract

PIIFlow is a policy-aware static taint analyzer for Python LLM applications. It
detects flows from configured request and sensitive-data sources into configured
LLM sinks, preserves sanitizer provenance, annotates sinks with provider and
trust-zone metadata, and optionally evaluates each detected flow against a YAML
privacy policy. On the frozen 90-case synthetic flow benchmark, PIIFlow v0.3.0
reports precision 0.9545454545454546, recall 0.84, F1 0.8936170212765958, and
accuracy 0.8888888888888888. On the separate 36-case synthetic policy benchmark,
PIIFlow achieved 1.00 F1. These results describe scoped synthetic benchmarks and
do not imply perfect real-world accuracy.

## Problem Statement

Python applications increasingly send request-derived values to LLM providers.
Developers need source-level visibility into whether emails, phone numbers,
medical terms, financial values, government identifiers, or location data can
reach external model calls. They also need to distinguish sensitive flows that
are allowed by policy from flows that violate provider, trust-zone, category, or
sanitizer requirements.

## Threat Model

PIIFlow targets accidental source-code privacy leaks in Python LLM integrations.
It assumes source code is available locally and can be parsed with Python's
standard `ast` module. It does not execute target programs, intercept runtime
requests, inspect production data, verify legal compliance, or prevent leakage at
runtime.

## Design Goals

- Keep analysis deterministic and local.
- Report readable source-to-sink provenance.
- Preserve benchmark reproducibility and honest failure reporting.
- Separate flow detection from policy evaluation.
- Support configurable sources, sinks, sanitizers, providers, and trust zones.
- Avoid broad claims about soundness, compliance, or production completeness.

## Static-Analysis Architecture

The scanner discovers Python files, parses them with `ast`, indexes project-local
functions and methods, runs structured taint propagation, records findings, and
then optionally applies policy evaluation. CLI and rendering code are adapters
around the analysis core.

Core modules:

- `config.py`: packaged and user YAML rule loading.
- `indexing.py`: function, method-kind, module, and import collection.
- `propagation.py`: taint introduction, propagation, sanitizer evidence, and sink
  recording.
- `scanner.py`: file discovery, parse/read errors, deduplication, and summary
  construction.
- `policy.py`: YAML policy validation and first-match decision logic.

## Structured Abstract Domain

The analyzer represents each value as an `AbstractValue` with direct taint,
known dictionary/list fields, wildcard fields for dynamic or collapsed access,
known attributes, wildcard attributes, optional source-collection references, and
bounded object identity. Known literal fields are strongly updated. Dynamic keys
and over-bound paths collapse to wildcard state to keep the analysis bounded.

## Interprocedural Propagation

PIIFlow analyzes bounded direct calls to project-local functions. Resolution uses
module-qualified identities, same-module preference, simple explicit imports,
import aliases, and method-kind binding for instance, class, and static methods.
Unresolved or ambiguous calls fall back to conservative unknown-call taint-through
instead of executing code.

## Policy Model

Policy files use schema version `1`. Rules are evaluated top to bottom, with
first-match semantics over category, provider, and trust zone. Actions are
`allow`, `deny`, and `require_sanitizer`. A `require_sanitizer` rule is satisfied
only when an approved sanitizer name appears in the actual propagation path.

Policy decisions are additive JSON/text annotations. The original flow
fingerprint remains stable across policy files, and `policy_fingerprint` records
the policy-specific decision.

## Benchmark Methodology

The original benchmark contains 90 synthetic Python cases with frozen labels and
case content. It compares `lexical`, `direct`, `piiflow_legacy`, and `piiflow`.
The policy benchmark is separate and contains 36 synthetic cases labeled
`violation` or `compliant`. It compares `policy_blind` with `piiflow_policy`.

Benchmark labels must not be edited to improve metrics. Generated results include
manifest and content hashes for reproducibility.

## Experimental Results

Original frozen 90-case benchmark:

| System | Precision | Recall | F1 | Accuracy | TP | FP | TN | FN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `lexical` | 0.714 | 1.000 | 0.833 | 0.778 | 50 | 20 | 20 | 0 |
| `direct` | 1.000 | 0.060 | 0.113 | 0.478 | 3 | 0 | 40 | 47 |
| `piiflow_legacy` | 0.909 | 0.800 | 0.851 | 0.844 | 40 | 4 | 36 | 10 |
| `piiflow` | 0.955 | 0.840 | 0.894 | 0.889 | 42 | 2 | 38 | 8 |

Policy benchmark:

| System | Precision | Recall | F1 | Accuracy | TP | FP | TN | FN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `policy_blind` | 0.556 | 1.000 | 0.714 | 0.556 | 20 | 16 | 0 | 0 |
| `piiflow_policy` | 1.000 | 1.000 | 1.000 | 1.000 | 20 | 0 | 16 | 0 |

## Ablation Study

The v0.2.0 structured analyzer improved over the saved v0.1.0 baseline on the
frozen benchmark:

| System | Precision | Recall | F1 | Accuracy | Total runtime |
| --- | ---: | ---: | ---: | ---: | ---: |
| v0.1.0 baseline | 0.909 | 0.800 | 0.851 | 0.844 | 0.382s |
| v0.2.0 structured | 0.955 | 0.840 | 0.894 | 0.889 | 0.252s |

The measured run showed better metrics and lower total runtime on this small
benchmark. Timings are small and machine-dependent.

## Error Analysis

Current false positives:

- `challenge_decorator_sanitizes_safe_008`
- `challenge_runtime_target_safe_014`

Current false negatives:

- `challenge_closure_vulnerable_009`
- `challenge_dynamic_attribute_vulnerable_016`
- `challenge_dynamic_sink_vulnerable_005`
- `challenge_exception_flow_vulnerable_017`
- `challenge_framework_value_vulnerable_015`
- `challenge_generator_vulnerable_010`
- `challenge_implicit_control_vulnerable_004`
- `challenge_nested_function_vulnerable_018`

These are documented challenge behaviors rather than hidden release defects.

## Runtime Analysis

The final policy benchmark run reported median per-case runtime of about
0.002867 seconds for `policy_blind` and 0.003472 seconds for `piiflow_policy`.
Across three policy benchmark replays, median added policy cost was about
0.000557 seconds per case. Because the cases are small, these numbers should be
treated as reproducibility checks, not production performance claims.

## Threats To Validity

- Benchmarks are synthetic and small.
- The project author constructed both analyzer and benchmark.
- Baselines are intentionally simple.
- Python dynamic behavior is only partially represented.
- Case-level binary metrics do not fully measure path quality.
- Test and benchmark similarity may inflate results.
- The policy benchmark's perfect score does not imply perfect real-world policy
  classification.
- Results do not generalize to other languages, larger frameworks, or commercial
  analyzers.

## Limitations

PIIFlow does not model implicit/control-flow taint, broad reflection, arbitrary
decorator semantics, generators, exception successor flow, framework lifecycle
behavior, runtime sink construction, external dependencies, OPA/Rego, runtime
interception, or legal compliance.

## Ethical And Privacy Considerations

PIIFlow is intended to help developers find and review privacy-sensitive code
paths. Public bug reports and benchmark contributions must use synthetic data,
not genuine personal data, credentials, private keys, or proprietary source code.
Policy decisions should be reviewed by qualified privacy, legal, and security
stakeholders before being used operationally.

## Conclusion

PIIFlow v0.3.0 provides a reproducible, policy-aware static taint-analysis
prototype for Python LLM applications. It demonstrates useful source-to-sink and
policy-decision reporting on scoped synthetic benchmarks while explicitly
documenting its static-analysis boundaries.
