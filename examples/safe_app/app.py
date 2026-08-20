def redact_pii(value: str) -> str:
    return "[redacted]"


def handle_safe(request, openai_client) -> None:
    email = request.json["email"]
    safe_email = redact_pii(email)
    openai_client.responses.create(input=safe_email)


def handle_public(openai_client) -> None:
    product_name = "PIIFlow"
    email_enabled = True
    prompt = f"Summarize public product {product_name}: {email_enabled}"
    openai_client.responses.create(input=prompt)
