import spacy
from spacy.training import Example
import json
import random

# --------------------------
# 1. DATA PREPROCESSING FUNCTIONS
# --------------------------
def preprocess_text(text):
    """Normalize text before tokenization"""
    return text.strip()

def resolve_overlapping_spans(spans):
    """Resolve overlapping spans by keeping the longest span"""
    if not spans:
        return []
    
    # Convert all spans to consistent format (start, end, label)
    processed_spans = []
    for span in spans:
        if isinstance(span, dict):
            processed_spans.append((span["start"], span["end"], span["label"]))
        else:  # assume list/tuple format
            processed_spans.append((span[0], span[1], span[2]))
    
    # Sort by start position then length (longest first)
    sorted_spans = sorted(processed_spans, key=lambda x: (x[0], -(x[1] - x[0])))
    
    filtered_spans = []
    if not sorted_spans:
        return filtered_spans
        
    prev_start, prev_end, prev_label = sorted_spans[0]
    
    for curr_start, curr_end, curr_label in sorted_spans[1:]:
        if curr_start >= prev_end:
            filtered_spans.append((prev_start, prev_end, prev_label))
            prev_start, prev_end, prev_label = curr_start, curr_end, curr_label
        else:
            curr_len = curr_end - curr_start
            prev_len = prev_end - prev_start
            if curr_len > prev_len:
                prev_start, prev_end, prev_label = curr_start, curr_end, curr_label
    
    filtered_spans.append((prev_start, prev_end, prev_label))
    return filtered_spans

def fix_misaligned_spans(text, spans):
    """Ensure spans align with token boundaries"""
    nlp = spacy.blank("en")
    doc = nlp.make_doc(text)
    fixed_spans = []
    
    for span in spans:
        if isinstance(span, dict):
            start, end, label = span["start"], span["end"], span["label"]
        else:
            start, end, label = span[0], span[1], span[2]
        
        spacy_span = doc.char_span(start, end, label=label, alignment_mode="contract")
        if spacy_span is None:
            # Try expanding the span if contracting fails
            spacy_span = doc.char_span(start, end, label=label, alignment_mode="expand")
            if spacy_span is None:
                print(f"Could not align span: {text[start:end]} (label: {label})")
                continue
        fixed_spans.append((spacy_span.start_char, spacy_span.end_char, label))
    
    return fixed_spans

def load_data(filepath):
    """Load and preprocess training data in span format"""
    with open(filepath) as f:
        raw_data = json.load(f)
    
    processed_data = []
    for item in raw_data:
        text = preprocess_text(item["text"])
        
        # Get spans from either "spans" or "entities" key
        spans = item.get("spans", {}).get("sc", item.get("entities", []))
        
        fixed_spans = fix_misaligned_spans(text, spans)
        non_overlapping = resolve_overlapping_spans(fixed_spans)
        
        # Only include examples that have at least one valid span
        if non_overlapping:
            processed_data.append((text, {"spans": {"sc": non_overlapping}}))
    
    return processed_data

# --------------------------
# 2. MODEL CONFIGURATION (UPDATED)
# --------------------------

def create_blank_model():
    """Create a blank spacy model with SpanCategorizer pipeline"""
    nlp = spacy.blank("en")

    config = {
        "threshold": 0.5,
        "suggester": {"@misc": "spacy.ngram_suggester.v1", "sizes": [1, 2, 3, 4, 5, 6, 7]}
    }

    if "spancat" not in nlp.pipe_names:
        spancat = nlp.add_pipe("spancat", config=config)

    return nlp, spancat

    

# --------------------------
# 3. TRAINING LOGIC (UPDATED)
# --------------------------

def train_span_based_model(nlp, train_data, output_dir):
    """Train the span-based NER model"""
    examples = []
    
    # Convert training data into spacy Example objects
    for text, annotations in train_data:
        doc = nlp.make_doc(text)
        example = Example.from_dict(doc, annotations)
        examples.append(example)
    
    # Verify training examples
    if not examples:
        raise ValueError("No valid training examples found. Check your data format.")
    
    # Initialize the model with examples
    # Create a small subset for initialization to avoid memory issues
    init_examples = examples[:min(10, len(examples))]
    nlp.initialize(lambda: init_examples)
    
    # Verify labels were properly initialized
    spancat = nlp.get_pipe("spancat")
    print(f"Initialized spancat with labels: {spancat.labels}")
    
    # Train the SpanCategorizer component only
    with nlp.disable_pipes(*[pipe for pipe in nlp.pipe_names if pipe != "spancat"]):
        optimizer = nlp.begin_training()
        
        # Training loop
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
    train_data = load_data("data/converted_span_data.json")
    print(f"Loaded {len(train_data)} training examples")

    # Extract unique labels from training data
    labels = set()
    for _, annots in train_data:
        for start, end, label in annots["spans"]["sc"]:
            labels.add(label)
    ENTITY_LABELS = sorted(list(labels))
    print(f"Extracted labels: {ENTITY_LABELS}")    
    
    # Verify some samples
    for text, annots in train_data[:3]:
        print(f"Text: {text[:50]}...")
        print(f"Spans: {annots['spans']['sc']}")    
        print("---")
    
    # Create a blank model and get spancat
    nlp, spancat = create_blank_model()

    # Add labels based on the data
    for label in ENTITY_LABELS:
        spancat.add_label(label)
    
        # Verify all labels in data exist in the model
    spancat = nlp.get_pipe("spancat")
    all_data_labels = set()

    for _, annots in train_data:
        for span in annots['spans']['sc']:
            all_data_labels.add(span[2])  # Get label

    print("\nLABELS IN DATA:", all_data_labels)
    print("LABELS IN MODEL:", spancat.labels)

    # Check for mismatches
    missing_labels = all_data_labels - set(spancat.labels)
    if missing_labels:
        print("🚨 MISSING LABELS:", missing_labels)

    # Train the span-based model
    train_span_based_model(nlp, train_data, "models/cs-acad_spancat")
