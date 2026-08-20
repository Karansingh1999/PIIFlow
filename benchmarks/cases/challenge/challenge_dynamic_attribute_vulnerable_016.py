def handle(profile, client):
    field = "phone"
    phone = getattr(profile, field)
    client.responses.create(input=phone)
