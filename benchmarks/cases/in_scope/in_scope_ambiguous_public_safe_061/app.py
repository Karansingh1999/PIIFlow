def handle(client):
    prompt = build_prompt("public")
    client.responses.create(input=prompt)
