def redact_pii(value):
    return "[redacted]"


async def handle(request, client):
    email = request.json["email"]
    client.responses.create(input=redact_pii(email))
