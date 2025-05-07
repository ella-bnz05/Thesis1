import json

def convert_to_span_format(input_file, output_file):
    """
    Convert from entities format to spans format for span-based NER
    
    Args:
        input_file: Path to input JSON file with entities format
        output_file: Path to save output JSON file with spans format
    """
    with open(input_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    converted_data = []
    
    for item in data:
        converted_item = {
            "text": item["text"],
            "spans": {
                "sc": []
            }
        }
        
        # Convert entities to spans format
        for entity in item.get("entities", []):
            if isinstance(entity, (list, tuple)) and len(entity) >= 3:
                # Handle [start, end, label] format
                converted_item["spans"]["sc"].append({
                    "start": entity[0],
                    "end": entity[1],
                    "label": entity[2]
                })
            elif isinstance(entity, dict):
                # Handle {"start": x, "end": y, "label": z} format
                converted_item["spans"]["sc"].append({
                    "start": entity.get("start"),
                    "end": entity.get("end"),
                    "label": entity.get("label")
                })
        
        converted_data.append(converted_item)
    
    # Save the converted data
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(converted_data, f, ensure_ascii=False, indent=2)
    
    print(f"Successfully converted {len(converted_data)} items. Saved to {output_file}")

# Example usage
convert_to_span_format(
    input_file="data/train_data.json",
    output_file="data/converted_span_data1.json"
)