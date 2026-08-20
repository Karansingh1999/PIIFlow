import base64
import hashlib


def build_prompt(email: str) -> str:
    return f"Summarize the customer account for {email}"


def handle_email(request, openai_client) -> None:
    email = request.json["email"]
    prompt = build_prompt(email)
    openai_client.responses.create(input=prompt)


def handle_medical(request, anthropic_client) -> None:
    diagnosis = request.form.get("diagnosis")
    message = f"Explain care options for this diagnosis: {diagnosis}"
    anthropic_client.messages.create(messages=[{"role": "user", "content": message}])


def handle_financial(request, openai_client) -> None:
    card_number = request.json["card_number"]
    encoded = base64.b64encode(card_number.encode()).decode()
    digest = hashlib.sha256(encoded.encode()).hexdigest()
    openai_client.chat.completions.create(messages=[{"role": "user", "content": digest}])
