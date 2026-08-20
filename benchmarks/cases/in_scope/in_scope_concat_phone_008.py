def handle(request, client):
    phone = request.json["phone"]
    prompt = "call " + phone
    client.responses.create(input=prompt)
