def handle(request, client):
    email = request.json["email"]
    prompt = build_prompt(email)
    client.responses.create(input=prompt)
