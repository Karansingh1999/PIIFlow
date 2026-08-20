def handle(request, client):
    email = request.json["email"]

    def inner():
        return f"private {email}"

    prompt = inner()
    client.responses.create(input=prompt)
