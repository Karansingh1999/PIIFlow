def handle(request, client):
    salary = request.json["salary"]
    public = "company overview"
    client.responses.create(input=public)
