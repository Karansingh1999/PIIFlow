def handle(request, client):
    email = request.json["email"]
    payload = {"private": email, "public": "hello"}
    client.responses.create(input=payload["public"])
