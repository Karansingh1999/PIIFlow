def build_prompt(value):
    return f"address {value}"


def handle(request, client):
    home_address = request.json["home_address"]
    prompt = build_prompt(value=home_address)
    client.responses.create(input=prompt)
