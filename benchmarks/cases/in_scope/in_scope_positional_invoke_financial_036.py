def handle(request, chain):
    card_number = request.json["card_number"]
    chain.invoke(card_number)
