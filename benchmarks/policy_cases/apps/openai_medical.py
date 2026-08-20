def handle(request, client):
    medical_history = request.json["medical_history"]
    client.responses.create(input=medical_history)
