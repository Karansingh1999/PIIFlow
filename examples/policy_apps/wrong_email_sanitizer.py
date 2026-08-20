def mask_email(value):
    return "***"


def handle(request, client):
    email = request.json["email"]
    client.responses.create(input=mask_email(email))
