def handle(request, client):
    email = request.json["email"]
    diagnosis = request.json["diagnosis"]
    client.responses.create(input=email)
    client.responses.create(input=diagnosis)
