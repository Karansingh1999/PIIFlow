def build_prompt(value):
    return f"public {value}"


def handle(client):
    prompt = build_prompt("release notes")
    client.responses.create(input=prompt)
