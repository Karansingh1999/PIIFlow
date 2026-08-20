def handle(request, client):
    ssn = request.json["ssn"]
    prompt = "public"
    try:
        raise ValueError("fallback")
    except ValueError:
        prompt = ssn
    client.responses.create(input=prompt)
