def handle(request, client):
    salary = request.json["salary"]
    client.local_model.generate(input=salary)
