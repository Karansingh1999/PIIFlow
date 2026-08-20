# Phase 2B1 Structured State Comparison

## Frozen Benchmark Integrity

- Manifest hash: `2335f30a119652db32aca3163e4b1a4d91a1e2bb8331cec51d247cd444ee51c7`
- Benchmark content hash: `a34c9817f0da31aaf4bd8a9590796614c62cbf33137b6486c3192d794f361f94`
- Benchmark content changed during run: False

## Overall Metrics

| System | Precision | Recall | F1 | Accuracy | TP | FP | TN | FN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline_piiflow_v0.1.0 | 0.909 | 0.800 | 0.851 | 0.844 | 40 | 4 | 36 | 10 |
| piiflow_legacy | 0.909 | 0.800 | 0.851 | 0.844 | 40 | 4 | 36 | 10 |
| piiflow | 0.955 | 0.840 | 0.894 | 0.889 | 42 | 2 | 38 | 8 |

## Overall Metric Changes

| Comparison | Precision | Recall | F1 | Accuracy | Runtime |
|---|---:|---:|---:|---:|---:|
| structured minus v0.1.0 | +0.045 | +0.040 | +0.043 | +0.044 | +0.016s |
| structured minus legacy | +0.045 | +0.040 | +0.043 | +0.044 | -0.003s |

## Relative Metric Changes

| Comparison | Precision | Recall | F1 | Accuracy | Runtime |
|---|---:|---:|---:|---:|---:|
| structured vs v0.1.0 | +5.0% | +5.0% | +5.0% | +5.3% | +4.2% |
| structured vs legacy | +5.0% | +5.0% | +5.0% | +5.3% | -0.8% |

## Challenge Metrics

| System | Precision | Recall | F1 | Accuracy | TP | FP | TN | FN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline_piiflow_v0.1.0 | 0.500 | 0.286 | 0.364 | 0.222 | 4 | 4 | 0 | 10 |
| piiflow_legacy | 0.500 | 0.286 | 0.364 | 0.222 | 4 | 4 | 0 | 10 |
| piiflow | 0.750 | 0.429 | 0.545 | 0.444 | 6 | 2 | 2 | 8 |

## Case-Level Changes

- Fixed baseline failures: challenge_attribute_storage_vulnerable_002, challenge_collection_alias_safe_011, challenge_dict_field_safe_001, challenge_request_alias_vulnerable_003
- New regressions: none
- Changed PIIFlow predictions: challenge_attribute_storage_vulnerable_002, challenge_collection_alias_safe_011, challenge_dict_field_safe_001, challenge_request_alias_vulnerable_003
- False positives removed: challenge_collection_alias_safe_011, challenge_dict_field_safe_001
- False negatives removed: challenge_attribute_storage_vulnerable_002, challenge_request_alias_vulnerable_003
- False positives introduced: none
- False negatives introduced: none

## Runtime Overhead

- Structured total runtime: 0.399 seconds
- v0.1.0 baseline total runtime: 0.382 seconds
- Legacy-mode total runtime: 0.402 seconds
- Structured vs v0.1.0 overhead: +0.016 seconds
- Structured vs legacy overhead: -0.003 seconds

## Memory And State Growth

Peak memory is not separately instrumented in this benchmark runner. Structured state growth is bounded by max access-path depth, max known fields per object, and wildcard collapse when known-field limits are exceeded.

## Interpretation

Structured field and alias modeling improves challenge performance by fixing general dictionary-field, request-alias, attribute-storage, and collection-alias behaviors while preserving in-scope performance.

## Threats To Validity

- Benchmark cases are synthetic and smaller than production repositories.
- The same project owns the analyzer and benchmark, so confirmation bias remains possible.
- Runtime measurements are single-process wall-clock timings on this machine.
- Memory growth is controlled by bounds but not independently profiled here.
- The analysis remains intentionally incomplete for later challenge families.

## Notes

The comparison uses the saved v0.1.0 baseline outputs and the current Phase 2B1 run. Benchmark labels and case files are not rewritten by this report.
