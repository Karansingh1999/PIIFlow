class PromptBuilder:
    @staticmethod
    def build(value):
        return f"public {value}"


def handle(client, builder):
    prompt = builder.build("release")
    client.responses.create(input=prompt)
