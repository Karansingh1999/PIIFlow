def handle(request, client):
    diagnosis: str = request.form["diagnosis"]
    client.messages.create(messages=[{"content": diagnosis}])
