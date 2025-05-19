import spacy

# Load your trained span-based model
nlp = spacy.load("models/cs-acad_spancat")  # adjust path if needed

# Test input
text = "INTELLIGENT STUDY COMPANION: A CHATBOT SYSTEM FOR COMPUTER SCIENCE STUDENTS USING NATURAL LANGUAGE PROCESSING\n\nUndergraduate Thesis\nSubmitted to the Faculty of the\nDepartment of Computer Studies\nCavite State University - Imus Campus\n\nCity of Imus, Cavite\n\nIn partial fulfilment\nof the requirements for the degree\n\nBachelor of Science in Computer Science\n\nJULIAN D. MENDOZA\nKATRINA L. DELA CRUZ\nMIGUEL A. SANTOS\nMarch 2025"

doc = nlp(text)

# Print predicted spans
print(f"\nText: {text}")
print("Predicted spans:")
for span in doc.spans.get("sc", []):  # "sc" is your span key
    print(f" - Text: '{span.text}', Label: {span.label_}")

# Optional: show no predictions warning
if not doc.spans.get("sc", []):
    print("⚠️  No spans predicted by the model.")
