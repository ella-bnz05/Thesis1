import spacy
from spacy.training import Example
import random
import json

def resolve_overlaps(entities):
    """Handle both tuple and dict formats"""
    if not entities:
        return []
    
    # Convert to uniform tuple format
    processed = []
    for ent in entities:
        if isinstance(ent, dict):
            processed.append((ent["start"], ent["end"], ent["label"]))
        else:
            processed.append(ent)
    
    # Sort by start position then length (longest first)
    sorted_ents = sorted(processed, key=lambda x: (x[0], -(x[1] - x[0])))
    
    filtered = []
    if not sorted_ents:
        return filtered
        
    prev_start, prev_end, prev_label = sorted_ents[0]
    
    for curr_start, curr_end, curr_label in sorted_ents[1:]:
        if curr_start >= prev_end:
            filtered.append((prev_start, prev_end, prev_label))
            prev_start, prev_end, prev_label = curr_start, curr_end, curr_label
        else:
            curr_len = curr_end - curr_start
            prev_len = prev_end - prev_start
            if curr_len > prev_len:
                prev_start, prev_end, prev_label = curr_start, curr_end, curr_label
    
    filtered.append((prev_start, prev_end, prev_label))
    return filtered

def evaluate_model(model_path, data_path):
    # 1. Load model
    try:
        nlp = spacy.load(model_path)
    except OSError:
        raise ValueError(f"Model not found at {model_path}. Train first!")
    
    # 2. Load data
    with open(data_path) as f:
        raw_data = json.load(f)
    
    # 3. Process examples
    examples = []
    for item in raw_data:
        text = item["text"]
        doc = nlp.make_doc(text)
        
        # Convert all entity formats to tuples
        entities = []
        for ent in item.get("entities", []):
            if isinstance(ent, dict):
                entities.append((ent["start"], ent["end"], ent["label"]))
            else:
                entities.append(ent)
        
        # Resolve overlaps
        non_overlapping = resolve_overlaps(entities)
        
        try:
            example = Example.from_dict(doc, {"entities": non_overlapping})
            examples.append(example)
        except ValueError as e:
            print(f"Skipping problematic text: {text[:50]}... - Error: {e}")
    
    # 4. Evaluate
    if not examples:
        raise ValueError("No valid examples to evaluate! Check your data.")
    
    scores = nlp.evaluate(examples)
    print("\nEvaluation Results:")
    print(f"- F1: {scores['ents_f']:.3f}")
    print(f"- Precision: {scores['ents_p']:.3f}")
    print(f"- Recall: {scores['ents_r']:.3f}\n")
    
    print("Per-Entity Performance:")
    for label, metrics in scores["ents_per_type"].items():
        print(f"{label}:")
        print(f"  Precision: {metrics['p']:.3f}")
        print(f"  Recall: {metrics['r']:.3f}")
        print(f"  F1: {metrics['f']:.3f}\n")

if __name__ == "__main__":
    evaluate_model(
        model_path="models/cs-acad_ner",
        data_path="data/test_data.json"  # Use your test data path
    )