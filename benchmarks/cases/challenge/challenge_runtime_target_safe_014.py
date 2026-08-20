class Unsafe:
    def build(self, value):
        return f"private {value}"


class Safe:
    def build(self, value):
        return "public"


def handle(request, client):
    email = request.json["email"]
    builder = Safe()
    prompt = builder.build(email)
    client.responses.create(input=prompt)
