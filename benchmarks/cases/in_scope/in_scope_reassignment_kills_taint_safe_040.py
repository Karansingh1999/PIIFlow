def handle(request, client):
    email = request.json["email"]
    email = "public@example.com"
    client.responses.create(input=email)
