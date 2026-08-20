def handle(client):
    prompt = custom_format("public")
    client.responses.create(input=prompt)
