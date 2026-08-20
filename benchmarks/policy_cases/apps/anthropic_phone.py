def handle(request, client):
    phone = request.json["phone_number"]
    client.messages.create(messages=phone)
