import spacy
from spacy.training import offsets_to_biluo_tags
import json

# Initialize a blank English model
nlp = spacy.blank("en")

def check_alignment(text, entities):
    """Verify entity alignment with tokenization"""
    doc = nlp.make_doc(text)
    tags = offsets_to_biluo_tags(doc, entities)
    
    print("\nText:", text)
    print("Tokens and their tags:")
    for token, tag in zip(doc, tags):
        print(f"{token.text:>15} -> {tag}")
    
    # Count misaligned entities
    misaligned = tags.count("-")
    print(f"\nFound {misaligned} misaligned entities")
    return misaligned == 0

def verify_dataset(filepath):
    """Check all examples in a dataset"""
    with open(filepath) as f:
        data = json.load(f)
    
    all_valid = True
    for i, example in enumerate(data[:20]):  # Check first 20 examples
        print(f"\n=== Example {i} ===")
        is_valid = check_alignment(example["text"], example["entities"])
        all_valid = all_valid and is_valid
    
    if all_valid:
        print("\nAll checked examples are properly aligned!")
    else:
        print("\nWarning: Some entities are misaligned")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        verify_dataset(sys.argv[1])
    else:
        print("Usage: python check_alignment.py path/to/data.json")