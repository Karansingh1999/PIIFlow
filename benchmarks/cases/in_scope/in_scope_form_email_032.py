def handle(request, client):
    email_address = request.form["email_address"]
    client.responses.create(input=email_address)
