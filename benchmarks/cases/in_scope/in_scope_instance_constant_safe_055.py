class PromptBuilder:
    def build(self, value):
        return "public"


def handle(request, client, builder):
    email = request.json["email"]
    prompt = builder.build(email)
    client.responses.create(input=prompt)
