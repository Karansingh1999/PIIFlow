# Policy Model

PIIFlow separates two questions:

- Did sensitive data flow to an LLM sink?
- Is that flow allowed by the declared privacy policy?

The AST/data-flow analyzer produces sensitive flow records with category, source,
propagation path, sanitizer evidence, sink, provider, and trust zone. The policy
evaluator consumes those records and marks each flow as compliant or a violation. PIIFlow
does not execute scanned programs and does not enforce policy at runtime.

## YAML Schema

```yaml
version: 1
default_action: deny
rules:
  - id: require-redacted-email-openai
    description: Email may be sent to OpenAI only after redact_email.
    categories: [EMAIL]
    providers: [openai]
    trust_zones: [external]
    action: require_sanitizer
    sanitizers: [redact_email]
```

`default_action` is restricted to `allow` or `deny`. Rules are evaluated top to bottom,
and the first matching rule decides the result. `*` is supported in categories,
providers, trust zones, and sanitizer lists. Rule order matters.

## Actions

- `allow`: matching flows are compliant, even if unsanitized.
- `deny`: matching flows are violations, even if sanitized.
- `require_sanitizer`: matching flows are compliant only when one listed sanitizer
  occurred on the actual propagation path.

Reason codes are stable: `POLICY_ALLOW`, `POLICY_DENY`,
`REQUIRED_SANITIZER_PRESENT`, `REQUIRED_SANITIZER_MISSING`, `DEFAULT_ALLOW`, and
`DEFAULT_DENY`.

## Providers And Trust Zones

Built-in sinks carry metadata:

- OpenAI sinks: `provider=openai`, `trust_zone=external`
- Anthropic sinks: `provider=anthropic`, `trust_zone=external`
- Generic invoke sinks: `provider=generic`, `trust_zone=external`

Custom sinks may define `provider` and `trust_zone`. Older custom sink rules that omit
metadata default conservatively to `generic` and `external`.

With `piiflow scan --rule-provider orcarouter`, OpenAI Responses/Chat Completions and
Anthropic Messages sinks are reported with `provider=orcarouter` instead, so OrcaRouter
Cyber Inference flows can be governed separately from direct vendor SDK calls.

Supported identities include `openai`, `anthropic`, `orcarouter`, `generic`, and `local`.
Supported trust zones include `external`, `internal`, and `local`.

## Sanitizer Evidence

Sanitizer evidence is attached to taint only when the flow passes through a configured
sanitizer such as `redact_email`. Hashing and encoding remain ordinary transformations
unless explicitly configured as sanitizers. Multiple observed sanitizers are reported in
deterministic order by name.

## CLI

```bash
piiflow scan PATH --policy path/to/policy.yml
```

Policy-compliant sensitive flows remain visible as informational audit records and exit
0. Policy violations exit 1. Parse/read errors retain precedence and exit 3. Malformed
config, policy, or output-file errors exit 2.

## Examples

```bash
piiflow scan examples/policy_apps/medical_external.py --policy examples/policies/strict_external.yml
piiflow scan examples/policy_apps/redacted_email.py --policy examples/policies/sanitized_email.yml
piiflow scan examples/policy_apps/local_financial.py --config examples/policy_apps/local_rules.yml --policy examples/policies/local_model.yml
```

## Benchmark

The policy benchmark is separate from the frozen 90-case flow benchmark:

```bash
uv run python benchmarks/run_policy.py --system all
```

It compares `policy_blind`, which treats every detected sensitive LLM flow as a
violation, with `piiflow_policy`, which evaluates the declared policy. Labels target
`violation` versus `compliant`.

Threats to validity: cases are synthetic, timings are small and noisy, memory growth is
bounded but not separately profiled, and the benchmark is not a legal compliance
certification.

## Limitations

PIIFlow is a bounded static-analysis research prototype. It is not runtime data-loss
prevention, not legal certification, not a guarantee that all Python flows are found, and
not a replacement for privacy/legal review.
