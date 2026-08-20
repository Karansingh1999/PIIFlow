def handle(client):
    client.chat.completions.create(messages=[{"content": "public"}])
