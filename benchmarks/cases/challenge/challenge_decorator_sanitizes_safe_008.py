def sanitize_output(fn):
    def wrapper(value):
        return "[redacted]"

    return wrapper


@sanitize_output
def build_prompt(value):
    return f"private {value}"


def handle(request, client):
    email = request.json["email"]
    client.responses.create(input=build_prompt(email))
