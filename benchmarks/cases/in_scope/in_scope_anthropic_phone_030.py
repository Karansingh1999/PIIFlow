def handle(request, client):
    mobile = request.json["mobile"]
    client.messages.create(messages=[{"content": mobile}])
