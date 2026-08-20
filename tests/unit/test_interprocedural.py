from pathlib import Path

from piiflow.scanner import scan_path


def write_app(tmp_path: Path, source: str) -> Path:
    path = tmp_path / "app.py"
    path.write_text(source, encoding="utf-8")
    return path


def test_tainted_argument_passed_to_helper_and_returned(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def build_prompt(email):
    return f"Account {email}"

def handle(request, client):
    email = request.json["email"]
    prompt = build_prompt(email)
    client.responses.create(input=prompt)
""",
    )

    result = scan_path(path)

    assert result.summary.high == 1
    assert any("build_prompt" in step for step in result.findings[0].path)


def test_keyword_argument_mapping(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def build_prompt(value):
    return f"Account {value}"

def handle(request, client):
    email = request.json["email"]
    prompt = build_prompt(value=email)
    client.responses.create(input=prompt)
""",
    )

    assert scan_path(path).summary.high == 1


def test_untainted_argument_remains_untainted(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def build_prompt(value):
    return f"Account {value}"

def handle(client):
    prompt = build_prompt("public")
    client.responses.create(input=prompt)
""",
    )

    assert scan_path(path).findings == []


def test_helper_returning_constant_does_not_propagate(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def build_prompt(email):
    return "public"

def handle(request, client):
    email = request.json["email"]
    prompt = build_prompt(email)
    client.responses.create(input=prompt)
""",
    )

    assert scan_path(path).findings == []


def test_two_function_chain(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def wrap(value):
    return f"Wrapped {value}"

def build_prompt(email):
    return wrap(email)

def handle(request, client):
    email = request.json["email"]
    prompt = build_prompt(email)
    client.responses.create(input=prompt)
""",
    )

    assert scan_path(path).summary.high == 1


def test_recursive_cycle_terminates(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
def loop(value):
    return loop(value)

def handle(request, client):
    email = request.json["email"]
    prompt = loop(email)
    client.responses.create(input=prompt)
""",
    )

    assert scan_path(path).summary.high == 1


def test_async_function_collection_and_await_sink(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
async def handle(request, client):
    diagnosis = request.json["diagnosis"]
    await client.responses.create(input=diagnosis)
""",
    )

    result = scan_path(path)

    assert result.summary.critical == 1
    assert result.findings[0].category == "MEDICAL"


def test_instance_method_binds_explicit_argument_after_self(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
class PromptBuilder:
    def build(self, value):
        return f"private: {value}"

def handle(request, client, builder):
    email = request.json["email"]
    prompt = builder.build(email)
    client.responses.create(input=prompt)
""",
    )

    assert scan_path(path).summary.high == 1


def test_static_method_does_not_bind_receiver(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
class PromptBuilder:
    @staticmethod
    def build(value):
        return f"private: {value}"

def handle(request, client, builder):
    email = request.json["email"]
    prompt = builder.build(email)
    client.responses.create(input=prompt)
""",
    )

    assert scan_path(path).summary.high == 1


def test_class_method_binds_explicit_argument_after_cls(tmp_path: Path) -> None:
    path = write_app(
        tmp_path,
        """
class PromptBuilder:
    @classmethod
    def build(cls, value):
        return f"private: {value}"

def handle(request, client):
    email = request.json["email"]
    prompt = PromptBuilder.build(email)
    client.responses.create(input=prompt)
""",
    )

    assert scan_path(path).summary.high == 1


def test_same_named_functions_across_modules_prefer_same_module(tmp_path: Path) -> None:
    vulnerable = tmp_path / "a_vulnerable.py"
    safe = tmp_path / "z_safe.py"
    vulnerable.write_text(
        """
def build_prompt(value):
    return f"private: {value}"

def handle(request, client):
    email = request.json["email"]
    prompt = build_prompt(email)
    client.responses.create(input=prompt)
""",
        encoding="utf-8",
    )
    safe.write_text(
        """
def build_prompt(value):
    return "public"
""",
        encoding="utf-8",
    )

    assert scan_path(tmp_path).summary.high == 1


def test_same_named_functions_reversed_filename_order(tmp_path: Path) -> None:
    safe = tmp_path / "a_safe.py"
    vulnerable = tmp_path / "z_vulnerable.py"
    safe.write_text(
        """
def build_prompt(value):
    return "public"
""",
        encoding="utf-8",
    )
    vulnerable.write_text(
        """
def build_prompt(value):
    return f"private: {value}"

def handle(request, client):
    email = request.json["email"]
    prompt = build_prompt(email)
    client.responses.create(input=prompt)
""",
        encoding="utf-8",
    )

    assert scan_path(tmp_path).summary.high == 1


def test_ambiguous_unqualified_call_is_conservative(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        """
def build_prompt(value):
    return "public"
""",
        encoding="utf-8",
    )
    (tmp_path / "b.py").write_text(
        """
def build_prompt(value):
    return "also public"
""",
        encoding="utf-8",
    )
    (tmp_path / "handler.py").write_text(
        """
def handle(request, client):
    email = request.json["email"]
    prompt = build_prompt(email)
    client.responses.create(input=prompt)
""",
        encoding="utf-8",
    )

    assert scan_path(tmp_path).summary.high == 1


def test_explicit_import_alias_resolution(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text(
        """
def build_prompt(value):
    return f"private: {value}"
""",
        encoding="utf-8",
    )
    (tmp_path / "handler.py").write_text(
        """
from helpers import build_prompt as make_prompt

def handle(request, client):
    email = request.json["email"]
    prompt = make_prompt(email)
    client.responses.create(input=prompt)
""",
        encoding="utf-8",
    )

    assert scan_path(tmp_path).summary.high == 1
