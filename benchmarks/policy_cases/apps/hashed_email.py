def hash_value(value):
    return f"hash:{value}"


def handle(request, client):
    email = request.json["email"]
    client.responses.create(input=hash_value(email))
