def handle(request, client):
    salary = request.json["salary"]
    messages = ("salary", salary)
    client.chat.completions.create(messages=messages)
