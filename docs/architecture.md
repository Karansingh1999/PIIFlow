# PIIFlow Architecture

PIIFlow is a bounded static analyzer for Python source code. It parses files with the
standard `ast` module and never imports or executes the target project.

## Components

- `config.py` loads packaged YAML rules and optional user extensions.
- `indexing.py` collects project-local synchronous/asynchronous functions, method
  kind, module identity, parameters, and simple import aliases.
- `sources.py` normalizes configured sensitive names and request-source expressions.
- `propagation.py` performs taint introduction, propagation, bounded local function
  calls, sanitizer handling, and sink finding construction.
- `sinks.py` matches dotted call names against exact or wildcard sink rules.
- `fingerprints.py` creates deterministic finding fingerprints.
- `scanner.py` handles file discovery, parse-error collection, deterministic
  ordering, deduplication, and scan summaries.
- `reporting.py` renders JSON and Rich text output.
- `policy.py` loads YAML privacy policies and evaluates detected flows.
- `cli.py` is the Typer adapter. The analysis core does not depend on Typer.

## Analysis Flow

1. Discover one Python file or all `*.py` files under a directory.
2. Parse each file independently. Syntax errors are reported and do not stop the scan.
3. Collect project-local functions and methods.
4. Analyze top-level statements and each function body.
5. Introduce taint from configured request sources and sensitive names.
6. Propagate taint through simple Python expressions, calls inside `await`, and
   project-local calls.
7. Record findings when taint reaches configured LLM/API sink arguments.
8. Optionally evaluate findings against a YAML privacy policy.
9. Deduplicate findings by stable fingerprint and render output.

Policy-aware scans follow this pipeline:

```text
Python source
-> AST/data-flow analyzer
-> sensitive flow record
-> policy evaluator
-> compliant record or policy violation
-> text/JSON reporter
```

## Provenance Bounds

Each tainted value stores a compact path with the most recent eight steps. This keeps
findings understandable without attempting to enumerate every possible path through a
program.

## Structured Abstract State

The propagation engine uses an `AbstractValue` model rather than encoding fields into
synthetic variable names. Each value can contain:

- Direct scalar taints.
- Known dictionary/list fields keyed by literal strings or integer indexes.
- Wildcard dictionary/list field taints for dynamic keys and collapsed fields.
- Known object attributes.
- Wildcard attribute taints for dynamic or over-bound attributes.
- A source-collection reference such as `request.json`.
- A bounded object identity used to preserve simple aliases.

Known dictionary keys and attributes are strongly updated. For example, assigning
`payload["email"] = "public"` replaces the previous known-field value for `email`.
Dynamic keys use wildcard state, so subsequent known or dynamic reads conservatively see
the possible taint. Whole-object sink use walks direct, field, wildcard-field, attribute,
and wildcard-attribute taints.

Simple collection and object aliases share an abstract object identity, so writes through
`alias["email"]` or `alias.email` can be observed through the original object. Source
collections are tracked separately from ordinary taint, allowing aliases such as
`data = request.json` and `email = data["email"]` without treating every dictionary as a
request source.

The analysis is bounded by `AnalysisOptions`: structured state is enabled by default,
maximum access-path depth is 4, maximum known fields per object is 64, and maximum
aliases per object is reserved at 32 for the explicit alias bound. When known-field or
attribute limits are exceeded, state collapses into wildcard taint and prefers a
conservative false positive over an unsafe false negative.

Control-flow joins merge abstract values and heap objects field by field. A branch that
may assign sensitive data to `payload["value"]` keeps that field tainted after the join;
if every analyzed branch strongly overwrites the field with safe values, the merged field
can remain safe under the existing bounded control-flow model.

## Policy Evaluation

Policy evaluation is deliberately separate from propagation. The analyzer records a flow
with sanitizer evidence, provider, and trust zone. `policy.py` then applies first-match
policy rules over category, provider, and trust zone. `allow` marks a flow compliant,
`deny` marks it a violation, and `require_sanitizer` checks for a listed sanitizer on the
actual propagation path.

OpenAI and Anthropic built-in sinks are external provider-specific sinks. Generic custom
sinks default to `provider=generic` and `trust_zone=external` when metadata is omitted.
Policy fields are additive in JSON output, and the original flow fingerprint is preserved
across policy files.

## Function Resolution

Every function has a module-qualified identity derived from its relative file path and
qualified name. Unqualified calls prefer definitions from the same module. Basic
`import module as alias` and `from module import name as alias` forms are resolved when
they point to analyzed project files. Same-named functions from other modules are not
silently overwritten; if a call cannot be resolved unambiguously, the analyzer falls
back to unknown-call taint-through.

Methods are classified as instance, static, or class methods. Instance and class methods
bind the receiver to `self` or `cls`, then bind explicit positional arguments after that
receiver. Static methods bind explicit arguments starting at the first parameter.
