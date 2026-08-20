def redact_pii(value):
    return "[redacted]"


def handle(request, client):
    diagnosis = request.json["diagnosis"]
    client.responses.create(input=redact_pii(diagnosis))
