import spacy
import pytest

@pytest.fixture
def nlp():
    return spacy.load("models/cs-acad_ner")

def test_method_recognition(nlp):
    doc = nlp("DEEP LEARNING APPROACH TO IMAGE RECOGNITION")
    assert any(ent.label_ == "METHOD" and ent.text == "DEEP LEARNING" for ent in doc.ents)

def test_author_recognition(nlp):
    doc = nlp("JOHNSON ET AL.: NOVEL METHOD FOR DATA ANALYSIS")
    assert any(ent.label_ == "AUTHOR" and ent.text == "JOHNSON ET AL." for ent in doc.ents)

def test_research_problem(nlp):
    doc = nlp("QUANTUM COMPUTING APPLICATIONS IN CHEMISTRY")
    assert any(ent.label_ == "RESEARCH_PROBLEM" for ent in doc.ents)