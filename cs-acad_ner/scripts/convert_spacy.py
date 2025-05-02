import json
import spacy
from spacy.training import Example
from spacy.tokens import DocBin
from pathlib import Path

# Paths
input_json = Path("data/test_data.json")
output_spacy = Path("data/dev.spacy")

# Load the data
with input_json.open("r", encoding="utf-8") as f:
    data = json.load(f)

# Create a blank nlp object
nlp = spacy.blank("en")  # or "xx" if using multilingual, or "tl" for Filipino if supported

# Create a DocBin for saving spaCy training data
doc_bin = DocBin()

for item in data:
    text = item["text"]
    ents = item["entities"]

    # Build annotations
    spans = [(start, end, label) for start, end, label in ents]

    doc = nlp.make_doc(text)
    example = Example.from_dict(doc, {"entities": spans})
    doc_bin.add(example.reference)

# Save to .spacy file
doc_bin.to_disk(output_spacy)
print(f"✅ Saved to {output_spacy}")
