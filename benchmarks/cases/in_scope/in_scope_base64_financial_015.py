import base64


def handle(request, client):
    card_number = request.json["card_number"]
    encoded = base64.b64encode(card_number.encode()).decode()
    client.responses.create(input=encoded)
