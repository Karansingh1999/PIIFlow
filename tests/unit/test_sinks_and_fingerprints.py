from piiflow.fingerprints import stable_fingerprint
from piiflow.models import SinkRef, SinkRule, SourceRef
from piiflow.propagation import severity_for
from piiflow.sinks import matching_sink


def test_sink_wildcard_matching() -> None:
    rules = [
        SinkRule(
            id="openai",
            call="*.responses.create",
            arguments=["input"],
            destination="external_llm",
        )
    ]

    assert matching_sink("client.responses.create", rules) == rules[0]
    assert matching_sink("client.responses.retrieve", rules) is None


def test_severity_assignment() -> None:
    assert severity_for("MEDICAL", "external_llm", sanitized=False).value == "critical"
    assert severity_for("EMAIL", "external_llm", sanitized=False).value == "high"
    assert severity_for("EMAIL", "configurable_llm", sanitized=False).value == "medium"
    assert severity_for("EMAIL", "external_llm", sanitized=True).value == "info"


def test_stable_fingerprint_generation() -> None:
    source = SourceRef(file="app.py", line=1, expression='request.json["email"]')
    sink = SinkRef(file="app.py", line=3, call="client.responses.create", argument="input")

    first = stable_fingerprint(
        rule_id="PIIFLOW001",
        category="EMAIL",
        source=source,
        sink=sink,
        sanitized=False,
    )
    second = stable_fingerprint(
        rule_id="PIIFLOW001",
        category="EMAIL",
        source=source,
        sink=sink,
        sanitized=False,
    )

    assert first == second
    assert len(first) == 16
