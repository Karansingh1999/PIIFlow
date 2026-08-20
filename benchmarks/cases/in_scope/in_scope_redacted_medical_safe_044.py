def redact_pii(value):
    return "[redacted]"


def handle(request, client):
    diagnosis = request.json["diagnosis"]
    client.chat.completions.create(messages=[{"content": redact_pii(diagnosis)}])
