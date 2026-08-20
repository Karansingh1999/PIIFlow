def handle(client):
    messages = ("role", "public")
    client.chat.completions.create(messages=messages)
