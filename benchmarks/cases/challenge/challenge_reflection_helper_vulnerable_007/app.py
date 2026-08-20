import helpers


def handle(request, client):
    phone = request.json["phone"]
    fn = getattr(helpers, "build_prompt")
    prompt = fn(phone)
    client.responses.create(input=prompt)
