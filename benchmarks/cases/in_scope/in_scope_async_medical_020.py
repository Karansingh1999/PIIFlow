async def handle(request, client):
    diagnosis = request.json["diagnosis"]
    client.responses.create(input=diagnosis)
