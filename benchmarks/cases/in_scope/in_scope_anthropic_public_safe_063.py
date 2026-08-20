def handle(client):
    client.messages.create(messages=[{"content": "public"}])
