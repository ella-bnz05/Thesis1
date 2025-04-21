import json

def convert_label_studio_format(input_file, output_file):
    """
    Converts Label Studio JSON export to a format like:
    {
        "text": "Some text here...",
        "entities": [[start, end, label], ...]
    }
    """
    with open(input_file, 'r', encoding='utf-8') as f:
        label_studio_data = json.load(f)

    converted_data = []

    for item in label_studio_data:
        text = item["data"]["text"]
        entities = []

        for annotation in item.get("annotations", []):
            for result in annotation.get("result", []):
                start = result["value"]["start"]
                end = result["value"]["end"]
                label = result["value"]["labels"][0]  # Assuming one label per result

                entities.append([start, end, label])

        converted_data.append({
            "text": text,
            "entities": entities
        })

    # Write the converted data to a new JSON file
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(converted_data, f, indent=4)

    print(f"Converted data saved to {output_file}")


# Example usage
if __name__ == "__main__":
    convert_label_studio_format("label_studio_export.json", "converted_data.json")