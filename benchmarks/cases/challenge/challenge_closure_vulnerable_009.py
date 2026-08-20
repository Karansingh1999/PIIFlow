def outer(email):
    def inner():
        return f"private {email}"

    return inner()


def handle(request, client):
    email = request.json["email"]
    prompt = outer(email)
    client.responses.create(input=prompt)
