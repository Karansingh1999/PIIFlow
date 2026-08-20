def handle(request, client):
    topic = request.json.get("topic")
    client.responses.create(input=topic)
