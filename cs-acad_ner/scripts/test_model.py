import spacy

# Load the trained model
nlp = spacy.load("models/cs-acad_ner1/output/model-best")

# Text to test
text = "DEVELOPMENT OF A VIRTUAL NURSE SYSTEM WITH BASIC HEALTH DETECTION USING GEOLOCATION BASED TECHNOLOGY\n\nUndergraduate Thesis\nSubmitted to the Faculty of the\nDepartment of Computer Studies\nCavite State University - Imus Campus\nCity of Imus, Cavite\n\nof the requirements in the degree\nBachelor of Science in Computer Science\n\nVIRGILIO JR. C. DIAZ\nRODNIE G. GELLA\nSHARINA ACEL V. MACROHON\nJANUARY 2025"


# Run the model
doc = nlp(text)

# Print the results
for ent in doc.ents:
    print(f"{ent.text} -> {ent.label_}")