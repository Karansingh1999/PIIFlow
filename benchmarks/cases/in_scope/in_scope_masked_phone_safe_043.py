def mask_sensitive(value):
    return "***"


def handle(request, client):
    phone = request.json["phone"]
    message = mask_sensitive(phone)
    client.messages.create(messages=[{"content": message}])
