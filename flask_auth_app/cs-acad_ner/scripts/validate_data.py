import spacy
from spacy.training import offsets_to_biluo_tags

nlp = spacy.blank("en")  # Don't load full model just for validation

def check_alignment(text, entities):
    doc = nlp.make_doc(text)
    tags = offsets_to_biluo_tags(doc, entities)
    return list(zip([t.text for t in doc], tags))

if __name__ == "__main__":
    # Example test case
    text = "SMITH ET AL : MACHINE LEARNING IN CLIMATE RESEARCH"
    entities = [(0, 10, "AUTHOR"), (13, 29, "METHOD"), (33, 50, "RESEARCH_PROBLEM")]
    

    result = check_alignment(text, entities)
    print("Token alignment results:")
    for token, tag in result:
        print(f"{token:>15} → {tag}")
    
    # Count misaligned entities
    misaligned = sum(1 for _, tag in result if tag == "-")
    print(f"\nMisaligned entities: {misaligned}")
