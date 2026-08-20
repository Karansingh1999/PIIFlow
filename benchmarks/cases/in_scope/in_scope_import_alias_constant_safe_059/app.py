import helpers as hp


def handle(request, client):
    email = request.json["email"]
    prompt = hp.build_prompt(email)
    client.responses.create(input=prompt)
