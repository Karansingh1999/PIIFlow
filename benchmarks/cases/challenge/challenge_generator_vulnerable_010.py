def values(card_number):
    yield card_number


def handle(request, client):
    card_number = request.json["card_number"]
    prompt = next(values(card_number))
    client.responses.create(input=prompt)
