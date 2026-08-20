def handle(request, client):
    passport_number = request.json["passport_number"]
    prompt = custom_format(passport_number)
    client.responses.create(input=prompt)
