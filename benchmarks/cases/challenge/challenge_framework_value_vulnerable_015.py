def handle(current_user, client):
    email = current_user.email
    client.responses.create(input=email)
