import hashlib


def handle(client):
    digest = hashlib.sha256(b"public").hexdigest()
    client.responses.create(input=digest)
