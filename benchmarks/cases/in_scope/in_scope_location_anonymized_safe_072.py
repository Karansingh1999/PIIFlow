def anonymize(value):
    return "city-level"


def handle(request, client):
    home_address = request.json["home_address"]
    client.messages.create(messages=[{"content": anonymize(home_address)}])
