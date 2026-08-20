def handle(request, client):
    payload = {"private": request.json["email"], "public": "hello"}
    client.responses.create(input=payload["private"])
