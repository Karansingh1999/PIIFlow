def handle(request, client, state):
    state.email = request.json["email"]
    client.responses.create(input=state.email)
