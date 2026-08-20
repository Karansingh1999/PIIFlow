def handle(request, client):
    medical_history = request.json["medical_history"]
    messages = [medical_history]
    client.chat.completions.create(messages=messages)
