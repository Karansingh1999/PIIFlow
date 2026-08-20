# Changelog

All notable changes to PIIFlow are documented here. Dates are marked
`Unreleased` where no verified public release date exists.

## [0.3.0] - Unreleased

### Added

- Policy-aware privacy-boundary evaluation with `piiflow scan --policy`.
- YAML policy schema version `1` with first-match `allow`, `deny`, and
  `require_sanitizer` rules.
- Provider and trust-zone metadata on sink rules.
- Sanitizer provenance reporting on the actual propagation path.
- Separate 36-case synthetic policy benchmark with `policy_blind` and
  `piiflow_policy` systems.
- Policy examples, policy-model documentation, and reproducibility guidance.

### Changed

- JSON and text reports include additive policy decision fields when a policy is
  supplied.
- Packaging excludes generated benchmark results, caches, local environments,
  temporary files, and coverage data from release artifacts.

## [0.2.0] - Unreleased

### Added

- Structured field- and alias-sensitive abstract state.
- Module-aware function indexing and improved import resolution.
- Instance, class, and static method binding.
- Regression coverage for async handlers, module-name collisions, parse/read
  errors, output failures, and Unicode source handling.

### Changed

- Improved frozen 90-case benchmark performance from the saved v0.1.0 baseline.

## [0.1.0] - Unreleased

### Added

- Initial Python AST-based sensitive-data flow analyzer.
- Configurable source, sink, and sanitizer rules.
- Text and JSON CLI output.
- Initial synthetic benchmark and transparent lexical/direct baselines.
