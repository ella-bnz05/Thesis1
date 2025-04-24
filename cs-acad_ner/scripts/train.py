import spacy
from spacy.training import Example, offsets_to_biluo_tags
import json
import random


# --------------------------
# 1. DATA PREPROCESSING FUNCTIONS
# --------------------------
def preprocess_text(text):
    """Normalize text before tokenization"""
    # Example preprocessing rule for text normalization
    return text.strip()


def resolve_overlapping_entities(entities):
    """Resolve overlapping entities by keeping the longest span"""
    if not entities:
        return []
    
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
    """Ensure entity spans align with token boundaries"""
    nlp = spacy.blank("en")
    doc = nlp.make_doc(text)
    fixed_entities = []
    
    for start, end, label in entities:
        span = doc.char_span(start, end, label=label)
        if span is None:
            print(f"Misaligned entity: {text[start:end]} (label: {label})")
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

def create_blank_model(entity_labels):
    """Create a blank spacy model with NER pipeline"""
    nlp = spacy.blank("en")
    if "ner" not in nlp.pipe_names:
        ner = nlp.add_pipe("ner", last=True)
    
    # Add entity labels
    for label in entity_labels:
        ner.add_label(label)
    
    return nlp


# --------------------------
# 3. TRAINING LOGIC
# --------------------------

def train_span_based_model(nlp, train_data, output_dir):
    """Train the span-based NER model"""
    examples = []
    
    # Convert training data into spacy Example objects
    for item in train_data:
        text, annotations = item
        doc = nlp.make_doc(text)
        example = Example.from_dict(doc, annotations)
        examples.append(example)
    
    # Verify training examples
    if not examples:
        raise ValueError("No valid training examples found. Check your data format.")
    
    # Train the NER component only
    with nlp.disable_pipes(*[pipe for pipe in nlp.pipe_names if pipe != "ner"]):
        optimizer = nlp.begin_training()
        for epoch in range(20):  # Training for 20 epochs
            random.shuffle(examples)
            losses = {}
            
            for batch in spacy.util.minibatch(examples, size=8):
                nlp.update(batch, drop=0.3, losses=losses, sgd=optimizer)
            
            print(f"Epoch {epoch}: Losses: {losses}")
    
    # Save the trained model
    nlp.to_disk(output_dir)
    print(f"Model saved to {output_dir}")


# --------------------------
# MAIN EXECUTION
# --------------------------

if __name__ == "__main__":
    # Define entity labels
    ENTITY_LABELS = ["TITLE", "AUTHOR", "CAMPUS", "DEPARTMENT", "DATE"]

    # Load and preprocess data
    train_data = load_data("data/converted_data.json")
    
    # Create a blank model with necessary entity labels
    nlp = create_blank_model(ENTITY_LABELS)
    
    # Train the model with span-based annotations
    train_span_based_model(nlp, train_data, "models/cs-acad_ner")
