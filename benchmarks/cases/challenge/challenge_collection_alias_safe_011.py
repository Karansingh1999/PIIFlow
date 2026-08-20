def handle(request, client):
    email = request.json["email"]
    payload = [email]
    alias = payload
    alias[0] = "public"
    client.responses.create(input=payload)
