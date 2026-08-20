def handle(request, client):
    home_address = request.json["home_address"]
    message = {"content": home_address}
    client.messages.create(messages=[message])
