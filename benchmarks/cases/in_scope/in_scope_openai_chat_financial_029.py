def handle(request, client):
    salary = request.json["salary"]
    client.chat.completions.create(messages=[{"content": salary}])
