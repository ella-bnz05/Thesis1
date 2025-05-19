import pytesseract
import cv2
from PIL import Image
import PyPDF2
import re
import spacy
import os
from pathlib import Path
from PIL import Image
import tempfile

# Load both models
nlp_base = spacy.load("en_core_web_lg")

# custom SpanCat model
custom_model_path = Path(__file__).parent / "cs-acad_ner" / "models" / "cs-acad_spancat"
nlp_custom = spacy.load(custom_model_path)

def preprocess_image_for_ocr(image_path):
    image = cv2.imread(image_path)

    # Convert to grayscale
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

    # Resize to improve OCR accuracy
    scale_percent = 70  # or 200
    width = int(gray.shape[1] * scale_percent / 100)
    height = int(gray.shape[0] * scale_percent / 100)
    dim = (width, height)
    resized = cv2.resize(gray, dim, interpolation=cv2.INTER_LINEAR)

#    Apply slight Gaussian blur to reduce noise (avoids CLAHE + adaptive overkill)
    blurred = cv2.GaussianBlur(gray, (3, 3), 0)

    # Global thresholding instead of adaptive
    _, binary = cv2.threshold(blurred, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)

    # Binarization
    thresh = cv2.threshold(resized, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]

    # Denoise
    denoised = cv2.fastNlMeansDenoising(thresh, h=30)

     # Save the result
    temp_path = os.path.join(tempfile.gettempdir(), "preprocessed_ocr.jpg")
    cv2.imwrite(temp_path, binary)


    return temp_path

def extract_text_from_image_by_type(image_path):
    try:
        ext = os.path.splitext(image_path)[1].lower()

        if ext == ".png":
            # Preprocess or handle PNG differently
            return extract_text_from_png(image_path)
        elif ext in [".jpg", ".jpeg"]:
            # Preprocess or handle JPEG differently
            return extract_text_from_jpeg(image_path)
        else:
            print(f"Unsupported image format: {ext}")
            return ""
    except Exception as e:
        print(f"Error in extract_text_from_image_by_type: {str(e)}")
        return ""
    
def extract_text_from_pdf(filepath):
    text = ""
    with open(filepath, 'rb') as f:
        reader = PyPDF2.PdfReader(f)
        for page in reader.pages:
            # Improved extraction with layout preservation
            text += page.extract_text() + "\n\n"
    
    # Clean the extracted text
    text = re.sub(r'\n{3,}', '\n\n', text)  # Remove excessive newlines
    text = re.sub(r'-\n', '', text)         # Fix hyphenated words
    return text.strip()

def extract_text_from_png(image_path):
    """
    Extract text from an image file using Tesseract OCR
    """
    try:
        img = Image.open(image_path)
        text = pytesseract.image_to_string(img)
        return text.strip()
    except Exception as e:
        print(f"Error in extract_text_from_image_by_type: {str(e)}")
        return ""
    
def extract_text_from_jpeg(image_path):
    try:
        processed_path = preprocess_image_for_ocr(image_path)
        img = Image.open(processed_path)
        img.load()
        img = img.convert('L')
        img.info['dpi'] = (300, 300)

      
        config = "--oem 3 --psm 3"  # LSTM neural nets + assume single uniform block
        text = pytesseract.image_to_string(img, config=config)

        return text.strip()
    except Exception as e:
        print(f"Error in extract_text_from_image_by_type: {str(e)}")
        return ""
    
def clean_ocr_text(text):
    replacements = {
        "‘": "'", "’": "'", "“": '"', "”": '"',
        "—": "-", "–": "-", "•": "",
        "ﬂ": "fl", "ﬁ": "fi", "—": "-",
        " Universitv": " University",  # common OCR mistake
        "fullment": "fulfillment",
        "mus": "Imus",
        "Mus": "Imus",
        "Cavite State Universitv": "Cavite State University",
        "Depaltment": "Department",
        "Scicnce": "Science",
        "thc": "the",
        "Thcsis": "Thesis",
        "Systcm": "System",
    }

    # Replace all manually
    for wrong, right in replacements.items():
        text = text.replace(wrong, right)

    # Remove multiple spaces
    text = re.sub(r'\s{2,}', ' ', text)

    return text

def extract_title(lines):
    """Maintain existing title extraction logic"""
    title_candidates = []
    for line in lines[:15]:
        if line.isupper() and len(re.findall(r'\b[A-Z]{2,}\b', line)) > 3:
            title_candidates.append(line)
        elif title_candidates:
            break
    return " ".join(title_candidates).strip('.,') if title_candidates else "Not Found"

def extract_info(text):
    text = clean_ocr_text(text)
    lines = [line.strip() for line in text.split("\n") if line.strip()]
    
    # Get title using existing method
    title = extract_title(lines)
    
    # Process with custom model for other fields
    doc = nlp_custom(text)
    
    # Initialize default values
    info = {
        "Title": title,
        "Author": "Not Found",
        "School": "Not Found",
        "Year Made": "Not Found",
        "Keywords": "Not Found"
    }
        
    # Extract entities from custom model
    authors = []
    for ent in doc.spans.get("sc", []):
        if ent.label_ == "AUTHOR":
            cleaned_author = ent.text.strip().rstrip('.,').upper()
            authors.append(cleaned_author)
        elif ent.label_ == "YEAR" and info["Year Made"] == "Not Found":
            info["Year Made"] = ent.text.strip().upper()
        elif ent.label_ == "SCHOOL" and info["School"] == "Not Found":
            info["School"] = ent.text.strip()

    # Remove duplicate authors while preserving order
    unique_authors = list(dict.fromkeys(authors))

    if unique_authors:
        info["Author"] = ", ".join(unique_authors)

    
    # Fallback to basic keyword extraction if custom model didn't find school
    if info["School"] == "Not Found":
        school_keywords = ["Cavite State University", "Department of Computer Studies", "Imus Campus"]
        detected_schools = [s for s in school_keywords if s in text]
        if detected_schools:
            info["School"] = ", ".join(detected_schools)
    
    # Fallback to regex if custom model didn't find year
    if info["Year Made"] == "Not Found":
        year_match = re.search(r"\b(19|20)\d{2}\b", text)
        if year_match:
            info["Year Made"] = year_match.group(0)
    
    # Extract keywords from title using base model
    if info["Title"] != "Not Found":
        doc_title = nlp_base(info["Title"])
        keywords = set()
        for chunk in doc_title.noun_chunks:
            if 2 <= len(chunk.text.split()) <= 5:
                keywords.add(chunk.text)
        for token in doc_title:
            if token.pos_ in {"NOUN", "PROPN"} and not token.is_stop:
                keywords.add(token.text)
        
        common_words = {"method", "study", "studies", "information", "extraction", "science", "thesis", "project"}
        info["Keywords"] = ", ".join(sorted(kw for kw in keywords if kw.lower() not in common_words)) or "Not Found"
    
    return info

