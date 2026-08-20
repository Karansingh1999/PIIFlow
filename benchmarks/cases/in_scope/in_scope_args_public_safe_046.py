def handle(request, client):
    page = request.args["page"]
    client.responses.create(input=page)
