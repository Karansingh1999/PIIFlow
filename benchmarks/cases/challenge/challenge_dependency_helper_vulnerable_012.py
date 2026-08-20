from vendor_privacy import build_prompt


def handle(request, client):
    medical_history = request.json["medical_history"]
    prompt = build_prompt(medical_history)
    client.responses.create(input=prompt)
