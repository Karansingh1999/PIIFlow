def handle(request, client):
    data = request.json
    email = data["email"]
    client.responses.create(input=email)
