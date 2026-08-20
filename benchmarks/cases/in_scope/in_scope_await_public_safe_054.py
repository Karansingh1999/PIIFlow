async def handle(client):
    prompt = "public"
    await client.responses.create(input=prompt)
