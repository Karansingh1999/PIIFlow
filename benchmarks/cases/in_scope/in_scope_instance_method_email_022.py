class PromptBuilder:
    def build(self, value):
        return f"private {value}"


def handle(request, client, builder):
    email = request.json["email"]
    prompt = builder.build(email)
    client.responses.create(input=prompt)
