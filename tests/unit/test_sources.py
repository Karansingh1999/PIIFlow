from pathlib import Path

from piiflow.config import load_config
from piiflow.sources import normalize_name, sensitive_category


def test_sensitive_name_normalization_and_matching() -> None:
    config = load_config()

    assert normalize_name("EmailAddress") == "email_address"
    assert sensitive_category("email_address", config) == "EMAIL"
    assert sensitive_category("email-enabled", config) is None
    assert sensitive_category("passport_number", config) == "GOVERNMENT_ID"


def test_custom_config_extends_defaults(tmp_path: Path) -> None:
    custom = tmp_path / "rules.yaml"
    custom.write_text(
        """
version: 1
sensitive_names:
  CUSTOMER_SECRET:
    - loyalty_id
sanitizer_patterns:
  - scrub_customer
""",
        encoding="utf-8",
    )

    config = load_config(custom)

    assert sensitive_category("email", config) == "EMAIL"
    assert sensitive_category("loyalty_id", config) == "CUSTOMER_SECRET"
    assert "scrub_customer" in config.sanitizer_patterns
