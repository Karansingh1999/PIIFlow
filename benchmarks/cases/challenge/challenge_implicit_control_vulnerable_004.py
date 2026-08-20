def handle(request, client):
    email = request.json["email"]
    prompt = "public"
    if email:
        prompt = "private user exists"
    client.responses.create(input=prompt)
