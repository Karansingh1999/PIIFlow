class PromptBuilder:
    @classmethod
    def build(cls, value):
        return f"private {value}"


def handle(request, client):
    aadhaar = request.json["aadhaar"]
    prompt = PromptBuilder.build(aadhaar)
    client.responses.create(input=prompt)
