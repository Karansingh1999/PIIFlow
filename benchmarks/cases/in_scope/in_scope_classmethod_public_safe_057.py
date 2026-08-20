class PromptBuilder:
    @classmethod
    def build(cls, value):
        return f"public {value}"


def handle(client):
    prompt = PromptBuilder.build("release")
    client.responses.create(input=prompt)
