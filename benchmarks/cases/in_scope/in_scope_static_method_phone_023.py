class PromptBuilder:
    @staticmethod
    def build(value):
        return f"private {value}"


def handle(request, client, builder):
    phone = request.json["phone"]
    prompt = builder.build(phone)
    client.responses.create(input=prompt)
