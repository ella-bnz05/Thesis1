import spacy

# Load your trained span-based model
nlp = spacy.load("models/cs-acad_spancat")  # adjust path if needed

# Test input
text = "RIC JOHN"
doc = nlp(text)

# Print predicted spans
print(f"\nText: {text}")
print("Predicted spans:")
for span in doc.spans.get("sc", []):  # "sc" is your span key
    print(f" - Text: '{span.text}', Label: {span.label_}")

# Optional: show no predictions warning
if not doc.spans.get("sc", []):
    print("⚠️  No spans predicted by the model.")
