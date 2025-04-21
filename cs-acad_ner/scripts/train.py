import spacy
from spacy.tokens import Span
from spacy.training import Example, offsets_to_biluo_tags
import json
import random

nlp = spacy.blank("en")
# --------------------------
# 1. DATA PREPROCESSING FUNCTIONS
# --------------------------
def preprocess_text(text):
    """Normalize text before tokenization"""
    # Add spaces around colons in author names
    if ":" in text and "ET AL" in text:
        text = text.replace(":", " : ")
    # Add other preprocessing rules as needed
    return text

def resolve_overlapping_entities(entities):
    """Resolve overlapping entities by keeping the longest span"""
    if not entities:
        return []
    
    # Sort by start position, then by length (longest first)
    sorted_entities = sorted(entities, key=lambda x: (x[0], -(x[1] - x[0])))
    
    filtered_entities = []
    prev_start, prev_end, prev_label = sorted_entities[0]
    
    for curr_start, curr_end, curr_label in sorted_entities[1:]:
        if curr_start >= prev_end:
            # No overlap, add the previous entity
            filtered_entities.append((prev_start, prev_end, prev_label))
            prev_start, prev_end, prev_label = curr_start, curr_end, curr_label
        else:
            # Overlap detected, keep the longer span
            curr_length = curr_end - curr_start
            prev_length = prev_end - prev_start
            
            if curr_length > prev_length:
                prev_start, prev_end, prev_label = curr_start, curr_end, curr_label
    
    # Add the last entity
    filtered_entities.append((prev_start, prev_end, prev_label))
    
    return filtered_entities

def fix_misaligned_entities(text, entities):
    """Adjust entity spans to match token boundaries"""
    doc = nlp.make_doc(text)
    fixed_entities = []
    
    for start, end, label in entities:
        span = doc.char_span(start, end, label=label)
        
        if span is None:
            # Try expanding/shrinking the span
            for delta in [-1, 1, -2, 2]:  # Try different adjustments
                adjusted_start = max(0, start + delta)
                adjusted_end = min(len(text), end + delta)
                span = doc.char_span(adjusted_start, adjusted_end, label=label)
                if span is not None:
                    break
            
            if span is None:
                print(f"Couldn't fix: {text[start:end]} (label: {label})")
                continue
                
        fixed_entities.append((span.start_char, span.end_char, label))
    
    return fixed_entities

def load_data(filepath):
    """Load and preprocess training data"""
    with open(filepath) as f:
        raw_data = json.load(f)
    
    processed_data = []
    for item in raw_data:
        text = preprocess_text(item["text"])
        fixed_ents = fix_misaligned_entities(text, item["entities"])
        non_overlapping = resolve_overlapping_entities(fixed_ents)
        processed_data.append((text, {"entities": non_overlapping}))
    
    return processed_data

# --------------------------
# 2. MODEL CONFIGURATION
# --------------------------

def create_blank_model():
    nlp = spacy.blank("en")
    
    # Add entity recognizer
    if "ner" not in nlp.pipe_names:
        ner = nlp.add_pipe("ner")
    
    # Define your entity labels
    labels = [
        "RESEARCH_PROBLEM", "SOLUTION", "METHOD", "TOOL",
        "RESOURCE", "METRIC", "AUTHOR", "CAMPUS",
        "DEPARTMENT", "DATE", "PAPER_TYPE"
    ]
    
    for label in labels:
        ner.add_label(label)
    
    return nlp

def add_uppercase_patterns(nlp):
    ruler = nlp.add_pipe("entity_ruler", before="ner")
    
    patterns = [
        # Paper types
        {"label": "PAPER_TYPE", "pattern": [{"TEXT": {"REGEX": "UNDERGRADUATE[_\s]THESIS|DISSERTATION|RESEARCH[_\s]PROPOSAL|THESIS[_\s]PROPOSAL"}}]},
        # Methods
        {"label": "METHOD", "pattern": [{"TEXT": {"REGEX": "DEEP[_\s]LEARNING|MACHINE[_\s]LEARNING"}}]},
        # Authors
        {"label": "AUTHOR", "pattern": [{"TEXT": {"REGEX": "^[A-Z]+$"}, "OP": "+"}, {"TEXT": "ET"}, {"TEXT": "AL"}]},
        # Date 
        {"label": "DATE", "pattern": [
            {"TEXT": {"REGEX": "(?i)(January|February|March|April|May|June|July|August|September|October|November|December)"}},
            {"SHAPE": "dddd"}
                 ]},
        {"label": "DATE", "pattern": [
         {"SHAPE": "dddd"}
         ]},
        # Deparment
        {"label": "DEPARTMENT", "pattern": [{"TEXT": {"REGEX": "DEPARTMENT OF [A-Z]+"}}]},
         # Campus
        {"label": "CAMPUS", "pattern": [{"TEXT": {"REGEX": "CAMPUS|COLLEGE|SCHOOL OF [A-Z]+"}}]}
    ]
      
   
    ruler.add_patterns(patterns)
    return nlp

def debug_alignment_examples(data):
    nlp = spacy.blank("en")
    for i, (text, annot) in enumerate(data[:3]):  # Check first 3 examples
        print(f"\n--- Example {i} ---")
        doc = nlp.make_doc(text)
        tags = offsets_to_biluo_tags(doc, annot["entities"])
        for token, tag in zip(doc, tags):
            print(f"{token.text:>15} → {tag}")

def debug_alignment_examples(data):
    nlp = spacy.blank("en")
    for i, (text, annot) in enumerate(data[:3]):  # Check first 3 examples
        print(f"\n--- Example {i} ---")
        print(f"Text: {text}")
        doc = nlp.make_doc(text)
        
        # Print all entities first
        print("Entities:")
        for start, end, label in annot["entities"]:
            print(f"  {label}: {text[start:end]}")
        
        # Then try to convert to BILUO tags
        try:
            tags = offsets_to_biluo_tags(doc, annot["entities"])
            for token, tag in zip(doc, tags):
                print(f"{token.text:>15} → {tag}")
        except ValueError as e:
            print(f"ERROR: {e}")
            print("Overlapping entities found. You'll need to resolve these conflicts.")


# --------------------------
# 3. TRAINING LOGIC
# --------------------------


def train_model(nlp, train_data, output_dir):
    """Train the NER model with proper data format handling"""
    examples = []
    
    # Convert all training examples to spaCy Example format
    for item in train_data:
        try:
            # Handle both tuple and dict formats
            if isinstance(item, tuple):
                text, annotations = item
            else:
                text = item["text"]
                annotations = {"entities": item["entities"]}
            
            # Create training example
            doc = nlp.make_doc(text)
            example = Example.from_dict(doc, annotations)
            examples.append(example)
            
        except (KeyError, TypeError) as e:
            print(f"Skipping malformed training example: {item}")
            print(f"Error: {str(e)}")
            continue
    
    # Verify we have valid examples
    if not examples:
        raise ValueError("No valid training examples found. Check your data format.")
    
    # Train only the NER pipe
    other_pipes = [pipe for pipe in nlp.pipe_names if pipe != "ner"]
    with nlp.disable_pipes(*other_pipes):
        optimizer = nlp.begin_training()
        
        # Training loop
        for epoch in range(20):
            random.shuffle(examples)
            losses = {}
            
            # Batch processing
            for batch in spacy.util.minibatch(examples, size=8):
                nlp.update(batch, drop=0.3, losses=losses, sgd=optimizer)
            
            print(f"Epoch {epoch}, Losses: {losses}")
    
    # Save the trained model
    nlp.to_disk(output_dir)
    print(f"Model saved to {output_dir}")

# --------------------------
# MAIN EXECUTION
# --------------------------


if __name__ == "__main__":
    train_data = load_data("data/converted_data.json")
    # DEBUG entity alignment for one sample
    sample = train_data[0]
    text = sample[0]
    entities = sample[1]["entities"]

    doc = nlp.make_doc(text)
    tags = offsets_to_biluo_tags(doc, entities)

    print("Entity alignment check:")
    for token, tag in zip(doc, tags):
        print(f"{token.text:>15} → {tag}")

    # Then continue to training
    nlp = create_blank_model()
    nlp = add_uppercase_patterns(nlp)
    train_model(nlp, train_data, "models/cs-acad_ner")
