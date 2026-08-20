# PIIFlow Limitations

PIIFlow 0.3 is a credible developer MVP, not a research-grade or compliance-grade
privacy verifier.

Supported behavior is intentionally bounded:

- Python is parsed statically with `ast`; target code is never executed.
- Taint is explicit data flow only. Implicit/control-flow taint is not modeled.
- Interprocedural analysis covers direct calls to project-local functions and simple
  same-module or explicitly imported functions with bounded recursion depth.
- Heap and alias behavior are modeled only for bounded, simple structured objects.
  Descriptor, decorator, metaclass, generator, framework lifecycle, and broad reflection
  behavior are not modeled precisely.
- Installed dependencies are not analyzed.
- Unknown transformation calls propagate taint conservatively.
- Only configured sanitizers clear taint on their returned values.
- Hashing and encoding are not approved sanitizers by default.
- Provenance and structured state are compact and bounded to avoid path explosion.
- Findings are developer signals, not legal, regulatory, or contractual compliance
  decisions.

Policy-aware scans classify detected flows against declared rules, but they still inherit
the analyzer's static-analysis limits. A policy result is not runtime enforcement, legal
certification, or proof that every relevant Python flow was found.

Async function bodies and calls inside `await` expressions are analyzed with the same
bounded semantics as synchronous functions. This does not make async scheduling or
framework lifecycle behavior fully modeled.

Structured dictionaries and attributes are field-sensitive for known literal fields
within configured bounds. Dynamic keys collapse into wildcard state, so this can still
produce conservative results outside the precise known-field model:

```python
payload = {"public": "hello"}
payload[key] = email
client.responses.create(input=payload["public"])
```

Attribute paths beyond the configured depth collapse into wildcard attribute state. This
is conservative for taint, but it is not a precise heap model and may report a broader
object as possibly tainted or miss dynamic attribute names that are not statically
available.

Request-collection aliases are tracked through direct assignments and simple alias
chains. Reassignment kills the source-collection reference, and arbitrary framework
objects are not inferred as request sources unless configured.

The following families remain intentionally incomplete and are represented by challenge
benchmark failures:

- Decorator-provided sanitization.
- Dynamic runtime sink construction.
- Closures and nested functions beyond direct collected-function summaries.
- Dynamic attributes when the attribute name is not statically available.
- Exception-handler data flow into successor statements.
- Framework-generated request values.
- Generators.
- Implicit/control-flow taint.

Policy rules are intentionally simple. They do not support arbitrary expressions, OPA,
Rego, code execution, data residency calculations, user identity conditions, or runtime
request interception. Rule order is significant and should be reviewed carefully.

Future research-grade versions may add vector stores, agent memory, stronger context
sensitivity, sanitizer-strength classification, benchmark applications, and broader
dynamic Python modeling.
