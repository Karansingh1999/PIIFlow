def handle(request, client):
    email = request.json["email"]
    client.responses.create(input=email)
