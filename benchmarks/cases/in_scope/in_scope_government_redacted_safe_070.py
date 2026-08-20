def redact_pii(value):
    return "[redacted]"


def handle(request, chain):
    ssn = request.json["ssn"]
    chain.invoke(input=redact_pii(ssn))
