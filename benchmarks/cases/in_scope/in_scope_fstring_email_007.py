def handle(request, client):
    email = request.json["email"]
    prompt = f"account: {email}"
    client.responses.create(input=prompt)
