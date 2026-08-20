async def handle(request, client):
    email = request.json["email"]
    await client.responses.create(input=email)
