def handle(request, client):
    account_number = request.json["account_number"]
    client.chat.completions.create(messages=[{"content": account_number}])
