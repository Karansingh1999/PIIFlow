def build_prompt(salary):
    return f"Salary: {salary}"


def handle(request, client):
    salary = request.json["salary"]
    client.responses.create(input=build_prompt(salary))
