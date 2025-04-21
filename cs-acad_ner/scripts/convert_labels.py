import json
from transformers import BertTokenizerFast

# Initialize tokenizer
tokenizer = BertTokenizerFast.from_pretrained("bert-base-uncased")

# Load your exported Label Studio data
with open("label_studio_export.json") as f:
    ls_data = json.load(f)

# Output holders
dataset_bio = []
dataset_spans = []

# Process each item in the Label Studio data
for item in ls_data:
    text = item["data"]["text"]
    annotations = item["annotations"][0]["result"]
    
    # Tokenize with offsets
    encoding = tokenizer(text, return_offsets_mapping=True, truncation=True)
    tokens = tokenizer.convert_ids_to_tokens(encoding["input_ids"])
    offsets = encoding["offset_mapping"]

    # Create BIO tags
    bio_labels = ["O"] * len(tokens)

    # Create span list
    span_list = []

    for ent in annotations:
        label = ent["value"]["labels"][0]
        start = ent["value"]["start"]
        end = ent["value"]["end"]

        # For span-based models
        span_list.append({
            "start": start,
            "end": end,
            "label": label,
            "text": text[start:end]
        })

        # For BIO tagging
        for i, (token_start, token_end) in enumerate(offsets):
            if token_start >= end:
                break
            if token_end <= start:
                continue
            if token_start >= start and token_end <= end:
                prefix = "B" if token_start == start else "I"
                bio_labels[i] = f"{prefix}-{label}"

    # Append to datasets
    dataset_bio.append({"tokens": tokens, "labels": bio_labels})
    dataset_spans.append({"text": text, "spans": span_list})

# Save the converted data to a new JSON file
converted_data = {
    "bio": dataset_bio,
    "spans": dataset_spans
}

# Write the converted data to a new file
with open("converted_label_studio_data.json", "w") as outfile:
    json.dump(converted_data, outfile, indent=4)

print("Conversion complete! Output saved to 'converted_label_studio_data.json'.")