def handle(request, client):
    ssn = request.json.get("ssn")
    client.responses.create(input=ssn)
