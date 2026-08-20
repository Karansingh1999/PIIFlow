def redact_pii(value):
    return "[redacted]"


def handle(request, client):
    email = request.json["email"]
    safe_email = redact_pii(email)
    client.responses.create(input=safe_email)
    client.responses.create(input=email)
