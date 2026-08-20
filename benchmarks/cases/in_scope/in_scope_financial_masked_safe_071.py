def mask_sensitive(value):
    return "***"


def handle(request, client):
    account_number = request.json["account_number"]
    client.responses.create(input=mask_sensitive(account_number))
