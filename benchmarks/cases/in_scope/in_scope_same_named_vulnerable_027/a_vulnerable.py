def build_prompt(value):
    return f"private {value}"


def handle(request, client):
    email = request.json["email"]
    prompt = build_prompt(email)
    client.responses.create(input=prompt)
