def handle(client):
    message = {"content": "public"}
    client.messages.create(messages=[message])
