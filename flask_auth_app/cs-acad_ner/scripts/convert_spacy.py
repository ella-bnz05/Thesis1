import json
import spacy
from spacy.tokens import DocBin
from pathlib import Path

def convert_to_spacy(input_json_path, output_spacy_path):
    # Load the data
    with open(input_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    # Create a blank nlp object
    nlp = spacy.blank("en")
    
    # Create a DocBin for saving spaCy training data
    doc_bin = DocBin()
    
    for item in data:
        text = item["text"]
        spans = item["spans"]["sc"]
        
        # Create the Doc object
        doc = nlp.make_doc(text)
        
        # Initialize entities list
        entities = []
        
        # Process each span
        for span in spans:
            start = span["start"]
            end = span["end"]
            label = span["label"]
            
            # Ensure the span is within document bounds
            if start <= len(text) and end <= len(text):
                entities.append((start, end, label))
        
        # Add entities to the doc
        doc.ents = [
            doc.char_span(start, end, label=label, alignment_mode="contract")
            for start, end, label in entities
            if doc.char_span(start, end, label=label) is not None
        ]
        
        # Add the doc to the DocBin
        doc_bin.add(doc)
    
    # Save to .spacy file
    doc_bin.to_disk(output_spacy_path)
    print(f"✅ Saved to {output_spacy_path}")

# Paths
input_json = Path("data/converted_span_data1.json")
output_spacy = Path("data/test1.spacy")

# Convert the data
convert_to_spacy(input_json, output_spacy)