def handle(request, chain):
    patient_record = request.json["patient_record"]
    chain.invoke(input=patient_record)
