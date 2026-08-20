import hashlib


def handle(request, client):
    salary = request.json["salary"]
    digest = hashlib.sha256(salary.encode()).hexdigest()
    client.chat.completions.create(messages=[{"content": digest}])
