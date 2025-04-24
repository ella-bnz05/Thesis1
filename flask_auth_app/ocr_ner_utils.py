
import pytesseract
from PIL import Image
import PyPDF2
import re
import spacy
import os

nlp = spacy.load("en_core_web_lg")

def extract_text_from_pdf(filepath):
    text = ""
    with open(filepath, 'rb') as f:
        reader = PyPDF2.PdfReader(f)
        for page in reader.pages:
            text += page.extract_text()
    return text

def extract_text_from_image(filepath):
    image = Image.open(filepath)
    return pytesseract.image_to_string(image)

def clean_ocr_text(text):
    replacements = {
        "‘": "'", "’": "'", "“": '"', "”": '"',
        "—": "-", "–": "-",
        "ﬂ": "fl", "ﬁ": "fi",
        " mus ": " Imus ",
        "fullment": "fulfillment",
        "Cavite State Universitv": "Cavite State University",
    }
    for wrong, right in replacements.items():
        text = text.replace(wrong, right)
    return text

def extract_title(lines):
    title_candidates = []
    for line in lines[:15]:
        if line.isupper() and len(re.findall(r'\b[A-Z]{2,}\b', line)) > 3:
            title_candidates.append(line)
        elif title_candidates:
            break
    return " ".join(title_candidates).strip('.,') if title_candidates else "Not Found"

def extract_authors(lines):
    author_lines = []
    capture_authors = False

    for line in lines:
        if "Bachelor of Science" in line:
            capture_authors = True
            continue
        if capture_authors:
            if re.search(r"\b(?:JANUARY|FEBRUARY|MARCH|...)\b", line):
                break
            if line.isupper() and len(line.split()) > 1 and len(line) < 50:
                if not re.search(r'\b(GAME|PROJECT|...)\b', line):
                    author_lines.append(line)
    return ", ".join(author_lines) if author_lines else "Not Found"

def extract_keywords(title):
    doc = nlp(title)
    keywords = set()
    for chunk in doc.noun_chunks:
        if 2 <= len(chunk.text.split()) <= 5:
            keywords.add(chunk.text)
    for token in doc:
        if token.pos_ in {"NOUN", "PROPN"} and not token.is_stop:
            keywords.add(token.text)

    common_words = {"method", "study", "studies", "information", "extraction", "science", "thesis", "project"}
    return ", ".join(sorted(kw for kw in keywords if kw.lower() not in common_words)) or "Not Found"

def extract_info(text):
    text = clean_ocr_text(text)
    lines = [line.strip() for line in text.split("\n") if line.strip()]
    
    info = {
        "Title": extract_title(lines),
        "Author": extract_authors(lines),
        "School": "Not Found",
        "Year Made": "Not Found",
        "Keywords": "Not Found"
    }

    if info["Title"] != "Not Found":
        info["Keywords"] = extract_keywords(info["Title"])

    school_keywords = ["Cavite State University", "Department of Computer Studies", "Imus Campus"]
    detected_schools = [s for s in school_keywords if s in text]
    info["School"] = ", ".join(detected_schools) if detected_schools else "Not Found"

    year_match = re.search(r"\b(19|20)\d{2}\b", text)
    if year_match:
        info["Year Made"] = year_match.group(0)

    return info
