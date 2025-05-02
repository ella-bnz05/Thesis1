import json

def convert_data_format(input_file, output_file):
    """Convert dataset from dictionary-style entities to array-style entities."""
    with open(input_file, 'r') as f:
        data = json.load(f)

    converted_data = []
    for item in data:
        # Extract text and entities
        text = item["text"]
        entities = item["entities"]

        # Convert each entity from dictionary to array format
        entity_list = [[entity["start"], entity["end"], entity["label"]] for entity in entities]

        # Create the converted format
        converted_item = {
            "text": text,
            "entities": entity_list
        }
        converted_data.append(converted_item)
    
    # Save the converted dataset
    with open(output_file, 'w') as f:
        json.dump(converted_data, f, indent=4)

    print(f"Data successfully converted and saved to {output_file}")

# Example usage
if __name__ == "__main__":
    input_filepath = "data/converted_label_studio_data1.json"  # Replace with your input file path
    output_filepath = "data/converted_data1.json"  # Replace with your output file path
    convert_data_format(input_filepath, output_filepath)