from pathlib import Path

from piiflow.models import AnalysisOptions
from piiflow.scanner import scan_path


def write_app(tmp_path: Path, source: str) -> Path:
    path = tmp_path / "app.py"
    path.write_text(source, encoding="utf-8")
    return path


def categories(path: Path) -> list[str]:
    return [finding.category for finding in scan_path(path).findings if not finding.sanitized]


def option_categories(
    path: Path,
    *,
    structured_state: bool,
    config_path: Path | None = None,
    max_known_fields_per_object: int = 64,
    max_access_path_depth: int = 4,
) -> list[str]:
    return [
        finding.category
        for finding in scan_path(
            path,
            config_path=config_path,
            options=AnalysisOptions(
                structured_state=structured_state,
                max_known_fields_per_object=max_known_fields_per_object,
                max_access_path_depth=max_access_path_depth,
            ),
        ).findings
        if not finding.sanitized
    ]


def test_subscript_and_get_sources(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def handle(request, client):
    email = request.json["email"]
    phone = request.args.get("phone_number")
    client.responses.create(input=email)
    client.responses.create(input=phone)
""",
    )

    assert categories(path) == ["EMAIL", "PHONE"]


def test_assignment_fstring_concat_and_container_propagation(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def handle(request, client):
    diagnosis = request.form["diagnosis"]
    prompt = "Dx: " + f"{diagnosis}"
    messages = [{"role": "user", "content": prompt}]
    client.messages.create(messages=messages)
""",
    )

    result = scan_path(path)

    assert result.summary.critical == 1
    assert result.findings[0].category == "MEDICAL"
    assert "messages" in result.findings[0].path


def test_unknown_call_taints_through_and_hashing_does_not_sanitize(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
import hashlib

def handle(request, client):
    salary = request.json["salary"]
    digest = hashlib.sha256(salary.encode()).hexdigest()
    client.chat.completions.create(messages=[{"content": digest}])
""",
    )

    result = scan_path(path)

    assert result.summary.critical == 1
    assert result.findings[0].category == "FINANCIAL"


def test_sanitizer_clears_return_only(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def redact_pii(value):
    return "[redacted]"

def handle(request, client):
    email = request.json["email"]
    safe_email = redact_pii(email)
    client.responses.create(input=safe_email)
    client.responses.create(input=email)
""",
    )

    result = scan_path(path)
    unsanitized = [finding for finding in result.findings if not finding.sanitized]
    sanitized = [finding for finding in result.findings if finding.sanitized]

    assert len(unsanitized) == 1
    assert len(sanitized) == 1
    assert unsanitized[0].severity.value == "high"
    assert sanitized[0].severity.value == "info"


def test_tuple_unpacking_and_conditional_expressions(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def handle(request, client, flag):
    email, public = request.json["email"], "hello"
    prompt = email if flag else public
    client.responses.create(input=prompt)
""",
    )

    assert categories(path) == ["EMAIL"]


def test_sensitive_target_from_request_collection(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def handle(request, client):
    email = request.json["unknown_key"]
    client.responses.create(input=email)
""",
    )

    assert categories(path) == ["EMAIL"]


def test_structured_dict_reads_do_not_leak_sibling_fields(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def handle(request, client):
    payload = {
        "email": request.json["email"],
        "prompt": "hello",
    }
    client.responses.create(input=payload["prompt"])
""",
    )

    assert option_categories(path, structured_state=True) == []
    assert option_categories(path, structured_state=False) == ["EMAIL"]


def test_structured_dict_reads_known_tainted_field(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def handle(request, client):
    payload = {
        "private": request.json["email"],
        "public": "hello",
    }
    client.responses.create(input=payload["private"])
""",
    )

    assert option_categories(path, structured_state=True) == ["EMAIL"]


def test_dynamic_dict_key_write_and_read_are_conservative(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def handle(request, client, key):
    payload = {"public": "hello"}
    payload[key] = request.json["email"]
    client.responses.create(input=payload["public"])
    client.responses.create(input=payload[key])
""",
    )

    assert option_categories(path, structured_state=True) == ["EMAIL", "EMAIL"]


def test_nested_dict_fields_remain_separate(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def handle(request, client):
    payload = {
        "private": {"email": request.json["email"]},
        "public": {"message": "hello"},
    }
    client.responses.create(input=payload["public"]["message"])
    client.responses.create(input=payload["private"]["email"])
""",
    )

    assert option_categories(path, structured_state=True) == ["EMAIL"]


def test_field_bound_collapse_is_conservative(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def handle(request, client):
    payload = {
        "private": request.json["email"],
        "public": "hello",
    }
    client.responses.create(input=payload["public"])
""",
    )

    assert option_categories(path, structured_state=True, max_known_fields_per_object=1) == [
        "EMAIL"
    ]


def test_structured_whole_dict_use_reports_sensitive_field(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def handle(request, client):
    payload = {"email": request.json["email"], "prompt": "hello"}
    client.responses.create(input=payload)
""",
    )

    assert option_categories(path, structured_state=True) == ["EMAIL"]


def test_structured_dict_alias_write_updates_shared_object(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def handle(request, client):
    payload = {}
    alias = payload
    alias["email"] = request.json["email"]
    client.responses.create(input=payload["email"])
""",
    )

    assert option_categories(path, structured_state=True) == ["EMAIL"]


def test_structured_dict_alias_overwrite_clears_field_taint(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def handle(request, client):
    payload = {"email": request.json["email"]}
    alias = payload
    alias["email"] = "public"
    client.responses.create(input=payload)
""",
    )

    assert option_categories(path, structured_state=True) == []
    assert option_categories(path, structured_state=False) == ["EMAIL"]


def test_structured_request_collection_alias_detects_sensitive_lookup(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def handle(request, client):
    data = request.json
    email = data["email"]
    client.responses.create(input=email)
""",
    )

    assert option_categories(path, structured_state=True) == ["EMAIL"]
    assert option_categories(path, structured_state=False) == []


def test_structured_request_collection_alias_chain_detects_lookup(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def handle(request, client):
    first = request.json
    second = first
    email = second["email"]
    client.responses.create(input=email)
""",
    )

    assert option_categories(path, structured_state=True) == ["EMAIL"]


def test_request_alias_reassignment_kills_source_reference(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def handle(request, client):
    data = request.json
    data = {"email": "public"}
    email = data["email"]
    client.responses.create(input=email)
""",
    )

    assert option_categories(path, structured_state=True) == []


def test_non_request_dictionary_is_not_a_source_alias(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def handle(client):
    data = {"email": "public"}
    email = data["email"]
    client.responses.create(input=email)
""",
    )

    assert option_categories(path, structured_state=True) == []


def test_custom_source_collection_alias_respects_config(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def handle(request, client):
    data = request.cookies
    email = data["email"]
    client.responses.create(input=email)
""",
    )
    config = tmp_path / "rules.yaml"
    config.write_text(
        """
version: 1
source_patterns:
  - "request.cookies[*]"
""",
        encoding="utf-8",
    )

    assert option_categories(path, structured_state=True, config_path=config) == ["EMAIL"]


def test_structured_attribute_storage_and_getattr_are_tracked(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def handle(request, client, state, key):
    state.email = request.json["email"]
    client.responses.create(input=getattr(state, "email"))
    client.responses.create(input=getattr(state, key))
""",
    )

    assert option_categories(path, structured_state=True) == ["EMAIL", "EMAIL"]
    assert option_categories(path, structured_state=False) == []


def test_structured_attribute_siblings_and_overwrite(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def handle(request, client, state):
    state.email = request.json["email"]
    state.public_value = "hello"
    state.email = "public"
    client.responses.create(input=state.public_value)
    client.responses.create(input=state.email)
""",
    )

    assert option_categories(path, structured_state=True) == []


def test_structured_attribute_alias_and_depth_bound(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def handle(request, client, state):
    alias = state
    alias.profile.email = request.json["email"]
    client.responses.create(input=state.profile.email)
""",
    )

    assert option_categories(path, structured_state=True) == ["EMAIL"]
    assert option_categories(path, structured_state=True, max_access_path_depth=1) == ["EMAIL"]


def test_structured_list_alias_overwrite_clears_index_taint(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def handle(request, client):
    messages = [request.json["medical_history"]]
    alias = messages
    alias[0] = "public"
    client.chat.completions.create(messages=messages)
""",
    )

    assert option_categories(path, structured_state=True) == []
    assert option_categories(path, structured_state=False) == ["MEDICAL"]


def test_structured_value_returned_from_function_preserves_fields(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def build_payload(email):
    return {"private": email, "public": "hello"}

def handle(request, client):
    payload = build_payload(request.json["email"])
    client.responses.create(input=payload["public"])
    client.responses.create(input=payload["private"])
""",
    )

    assert option_categories(path, structured_state=True) == ["EMAIL"]


def test_structured_value_passed_into_helper_preserves_fields(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def private_field(payload):
    return payload["private"]

def public_field(payload):
    return payload["public"]

def handle(request, client):
    payload = {"private": request.json["email"], "public": "hello"}
    client.responses.create(input=public_field(payload))
    client.responses.create(input=private_field(payload))
""",
    )

    assert option_categories(path, structured_state=True) == ["EMAIL"]


def test_structured_value_returned_through_two_function_chain(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def wrap(payload):
    return payload

def build(email):
    return wrap({"private": email, "public": "hello"})

def handle(request, client):
    payload = build(request.json["email"])
    client.responses.create(input=payload["private"])
""",
    )

    assert option_categories(path, structured_state=True) == ["EMAIL"]


def test_structured_recursive_propagation_terminates(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def loop(payload):
    return loop(payload)

def handle(request, client):
    payload = {"private": request.json["email"], "public": "hello"}
    result = loop(payload)
    client.responses.create(input=result["private"])
""",
    )

    assert option_categories(path, structured_state=True) == ["EMAIL"]


def test_sanitizing_one_structured_field_does_not_clear_others(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def redact_pii(value):
    return "[redacted]"

def handle(request, client):
    payload = {
        "email": request.json["email"],
        "medical_history": request.json["medical_history"],
    }
    payload["email"] = redact_pii(payload["email"])
    client.responses.create(input=payload["email"])
    client.responses.create(input=payload["medical_history"])
""",
    )

    result = scan_path(path, options=AnalysisOptions(structured_state=True))
    unsanitized = [finding.category for finding in result.findings if not finding.sanitized]
    sanitized = [finding.category for finding in result.findings if finding.sanitized]

    assert unsanitized == ["MEDICAL"]
    assert sanitized == ["EMAIL"]


def test_hashing_structured_field_remains_tainted(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
import hashlib

def handle(request, client):
    payload = {"email": request.json["email"]}
    payload["email"] = hashlib.sha256(payload["email"].encode()).hexdigest()
    client.responses.create(input=payload["email"])
""",
    )

    assert option_categories(path, structured_state=True) == ["EMAIL"]


def test_control_flow_merges_tainted_and_safe_field_values(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def handle(request, client, flag):
    payload = {}
    if flag:
        payload["value"] = request.json["email"]
    else:
        payload["value"] = "public"
    client.responses.create(input=payload["value"])
""",
    )

    assert option_categories(path, structured_state=True) == ["EMAIL"]


def test_control_flow_both_branches_safe_field_values(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def handle(request, client, flag):
    payload = {"value": request.json["email"]}
    if flag:
        payload["value"] = "public"
    else:
        payload["value"] = "hello"
    client.responses.create(input=payload["value"])
""",
    )

    assert option_categories(path, structured_state=True) == []


def test_loop_field_assignment_remains_conservative(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def handle(request, client, values):
    payload = {"value": "public"}
    for _ in values:
        payload["value"] = request.json["email"]
    client.responses.create(input=payload["value"])
""",
    )

    assert option_categories(path, structured_state=True) == ["EMAIL"]
