def handle(request, chain):
    phone_number = request.json["phone_number"]
    chain.invoke(phone_number)
