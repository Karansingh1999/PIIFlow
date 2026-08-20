def handle(request, client):
    topic = request.form["topic"]
    client.responses.create(input=topic)
