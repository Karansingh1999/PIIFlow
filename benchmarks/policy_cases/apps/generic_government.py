def handle(request, chain):
    ssn = request.json["ssn"]
    chain.invoke(ssn)
