import spacy
from spacy.training import Example
import random
import json

def resolve_overlaps(entities):
    if not entities:
        return []
    
    # Sort by start position, then by length (longest first)
    sorted_ents = sorted(entities, key=lambda x: (x[0], -(x[1] - x[0])))
    
    filtered = []
    prev_start, prev_end, prev_label = sorted_ents[0]
    
    for curr_start, curr_end, curr_label in sorted_ents[1:]:
        if curr_start >= prev_end:
            filtered.append((prev_start, prev_end, prev_label))
            prev_start, prev_end, prev_label = curr_start, curr_end, curr_label
        else:
            # Keep the longer span
            curr_len = curr_end - curr_start
            prev_len = prev_end - prev_start
            if curr_len > prev_len:
                prev_start, prev_end, prev_label = curr_start, curr_end, curr_label
    
    filtered.append((prev_start, prev_end, prev_label))
    return filtered

def evaluate_model(model_path, data_path):
    # 1. Load trained model
    nlp = spacy.load(model_path)
    
    # 2. Load and preprocess data
    with open(data_path) as f:
        train_data = [(item["text"], {"entities": item["entities"]}) for item in json.load(f)]
    
    # 3. Split into train/validation sets
    random.shuffle(train_data)
    split = int(0.8 * len(train_data))
    
    # 4. Create validation examples with overlap resolution
    val_examples = []
    for text, annot in train_data[split:]:
        doc = nlp.make_doc(text)
        non_overlapping = resolve_overlaps(annot["entities"])
        example = Example.from_dict(doc, {"entities": non_overlapping})
        val_examples.append(example)
    
    # 5. Evaluate
    scores = nlp.evaluate(val_examples)
    print(f"F1: {scores['ents_f']:.3f}, Precision: {scores['ents_p']:.3f}, Recall: {scores['ents_r']:.3f}")
    
    # 6. (Optional) Per-label metrics
    for label, metrics in scores["ents_per_type"].items():
        print(f"{label}: P={metrics['p']:.3f} R={metrics['r']:.3f} F1={metrics['f']:.3f}")

if __name__ == "__main__":
    evaluate_model(
        model_path="models/cs-acad_ner",  # Path to your trained model
        data_path="data/test_data.json"  # Path to your dataset
    )   