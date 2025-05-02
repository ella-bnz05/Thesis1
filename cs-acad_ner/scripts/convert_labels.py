import json
from pathlib import Path

# Paths
input_path = Path("Dataset_half.json")
output_path = Path("data/converted_data3.json")

# Load Label Studio JSON
with input_path.open("r", encoding="utf-8") as f:
    raw_data = json.load(f)

# Converted examples holder
converted_dataset = []

# Iterate through Label Studio items
for entry in raw_data:
    try:
        text = entry["data"]["text"]
        annotation_results = entry["annotations"][0]["result"]

        entities = []
        for result in annotation_results:
            label = result["value"]["labels"][0]
            start = result["value"]["start"]
            end = result["value"]["end"]
            entities.append([start, end, label])

        converted_dataset.append({
            "text": text,
            "entities": entities
        })

    except (KeyError, IndexError, TypeError) as e:
        print(f"Skipping entry due to format error: {e}")
        continue

# Save the final JSON
output_path.parent.mkdir(parents=True, exist_ok=True)
with output_path.open("w", encoding="utf-8") as f:
    json.dump(converted_dataset, f, indent=4, ensure_ascii=False)

print(f"✅ Conversion complete! Saved to '{output_path}'. Total samples: {len(converted_dataset)}")
