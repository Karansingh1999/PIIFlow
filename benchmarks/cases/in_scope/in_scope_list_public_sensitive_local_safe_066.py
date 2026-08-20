def handle(request, client):
    email = request.json["email"]
    messages = ["public"]
    client.chat.completions.create(messages=messages)
