def handle(request, client):
    phone_number = request.args["phone_number"]
    client.responses.create(input=phone_number)
