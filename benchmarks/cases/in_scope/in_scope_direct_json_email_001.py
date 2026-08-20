def handle(request, client):
    client.responses.create(input=request.json["email"])
