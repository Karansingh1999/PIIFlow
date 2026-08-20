class A:
    def build(self, value):
        return f"private {value}"


class B:
    def build(self, value):
        return "public"


def handle(request, client, builder):
    home_address = request.json["home_address"]
    prompt = builder.build(home_address)
    client.responses.create(input=prompt)
