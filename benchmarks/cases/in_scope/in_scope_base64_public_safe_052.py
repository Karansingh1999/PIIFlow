import base64


def handle(client):
    encoded = base64.b64encode(b"public").decode()
    client.responses.create(input=encoded)
