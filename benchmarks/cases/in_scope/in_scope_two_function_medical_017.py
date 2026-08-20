def wrap(value):
    return f"wrapped {value}"


def build_prompt(value):
    return wrap(value)


def handle(request, client):
    diagnosis = request.json["diagnosis"]
    prompt = build_prompt(diagnosis)
    client.messages.create(messages=[{"content": prompt}])
