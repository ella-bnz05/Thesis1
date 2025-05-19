import spacy
from spacy.training import Example
from spacy.scorer import Scorer
import json
import argparse

def preprocess_text(text):
    text = text.replace(" - ", "-")
    text = text.replace(" : ", ": ")
    return text.strip()

def resolve_overlaps(spans):
    if not spans:
        return []

    processed = []
    for span in spans:
        if isinstance(span, dict):
            try:
                processed.append((int(span["start"]), int(span["end"]), span["label"]))
            except (ValueError, KeyError):
                continue
        else:
            try:
                processed.append((int(span[0]), int(span[1]), span[2]))
            except (ValueError, IndexError):
                continue

    sorted_spans = sorted(processed, key=lambda x: (x[0], -(x[1] - x[0])))

    filtered = []
    if not sorted_spans:
        return filtered

    prev_start, prev_end, prev_label = sorted_spans[0]

    for curr_start, curr_end, curr_label in sorted_spans[1:]:
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

def evaluate_with_spacy_scorer(nlp, examples):
    example_objs = []

    for text, annotations in examples:
        doc = nlp.make_doc(text)
        example = Example.from_dict(doc, annotations)
        pred_doc = nlp(example.text)
        example_objs.append(Example(pred_doc, example.reference))

    scorer = Scorer()
    results = scorer.score(example_objs)

    # Debugging: Check the structure of the results dictionary
    print(f"\nScorer Results: {results}")

    # Check if the expected key exists
    if 'spans_sc_f' in results:
        print(f"- SpanCategorizer F1: {results['spans_sc_f']:.3f}")
    else:
        print("Error: 'spans_sc_f' not found in the results")

    print(f"- Precision: {results.get('spans_sc_p', 'N/A')}")
    print(f"- Recall: {results.get('spans_sc_r', 'N/A')}")

    # Per-type results (if available)
    if "spans_sc_per_type" in results:
        print("Per-label Scores:")
        for label, metrics in results["spans_sc_per_type"].items():
            print(f"{label}: P={metrics['p']:.3f}, R={metrics['r']:.3f}, F1={metrics['f']:.3f}")
    else:
        print("No per-type scores found.")

def load_examples(nlp, data_path, spans_key="sc"):
    with open(data_path) as f:
        raw_data = json.load(f)

    examples = []
    for item in raw_data:
        text = preprocess_text(item["text"])
        spans = item.get("spans", {}).get(spans_key, item.get("entities", []))
        spans = resolve_overlaps(spans)

        doc = nlp.make_doc(text)
        aligned_spans = []
        for start, end, label in spans:
            span = doc.char_span(start, end, label=label)
            if span:
                aligned_spans.append((span.start_char, span.end_char, span.label_))

        annotations = {"spans": {spans_key: aligned_spans}}
        examples.append((text, annotations))

    return examples

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate SpanCategorizer model using Scorer.")
    parser.add_argument("--model", required=True, help="Path to the trained spaCy model")
    parser.add_argument("--data", required=True, help="Path to evaluation data (JSON)")
    parser.add_argument("--spans_key", default="sc", help="Span key used in data (default: 'sc')")
    args = parser.parse_args()

    try:
        nlp = spacy.load(args.model)
    except OSError:
        raise ValueError(f"Model not found at '{args.model}'. Did you train it?")

    if "spancat" not in nlp.pipe_names:
        raise ValueError("The loaded model must have a SpanCategorizer component.")

    examples = load_examples(nlp, args.data, spans_key=args.spans_key)

    evaluate_with_spacy_scorer(nlp, examples)
    
print(nlp.pipe_names)
