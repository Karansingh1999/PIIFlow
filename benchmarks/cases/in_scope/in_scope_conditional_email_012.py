def handle(request, client, flag):
    email = request.json["email"]
    prompt = email if flag else "public"
    client.responses.create(input=prompt)
