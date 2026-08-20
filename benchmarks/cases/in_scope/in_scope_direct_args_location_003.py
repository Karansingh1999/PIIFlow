def handle(request, client):
    client.responses.create(input=request.args["postal_address"])
