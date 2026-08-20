def handle(client):
    prompt: str = "public"
    client.responses.create(input=prompt)
