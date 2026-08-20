def handle(request, client):
    diagnosis = request.json["diagnosis"]
    sink = client.responses.create
    sink(input=diagnosis)
