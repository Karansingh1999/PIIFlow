import importlib


def handle(request, client):
    email = request.json["email"]
    helper = importlib.import_module("helpers")
    prompt = helper.build_prompt(email)
    client.responses.create(input=prompt)
