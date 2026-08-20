def handle(request, client):
    email = request.json["email"]
    prompt = "public summary"
    client.responses.create(input=prompt)
