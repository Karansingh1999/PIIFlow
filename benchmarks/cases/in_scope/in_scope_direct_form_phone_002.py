def handle(request, client):
    client.responses.create(input=request.form["phone_number"])
