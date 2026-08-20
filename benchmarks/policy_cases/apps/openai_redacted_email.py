def redact_email(value):
    return "[redacted]"


def handle(request, client):
    email = request.json["email"]
    client.responses.create(input=redact_email(email))
