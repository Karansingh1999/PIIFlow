def handle(request, client):
    home_address = request.json["home_address"]
    client.internal_model.generate(input=home_address)
