# Wrapper for BLIP (image captioning) + Tesseract OCR.
# Accepts a screenshot path or PIL Image and returns a standardised triage JSON object.

import logging 
import re
from pathlib import Path
from typing import Union
from PIL import Image, ImageOps, ImageStat
from models.utilities import SCREEN_KEYWORDS, infer_severity, extract_entities, classify_tactic
logger = logging.getLogger(__name__)

# Lazy imports — only load heavy libraries when the wrapper is first called
blip_processor = None
blip_model = None
tesseract_available = None

# Constants
BLIP_MODEL_ID = "Salesforce/blip-image-captioning-base"

# Functions to load BLIP model
def load_blip():
    # Load BLIP model and processor (once, on first call)
    global blip_processor, blip_model

    if blip_processor is None:
        from transformers import BlipProcessor, BlipForConditionalGeneration
        import torch
        logger.info("Loading BLIP model: %s", BLIP_MODEL_ID)
        blip_processor = BlipProcessor.from_pretrained(BLIP_MODEL_ID)
        blip_model = BlipForConditionalGeneration.from_pretrained(BLIP_MODEL_ID)
        blip_model.eval()
        logger.info("BLIP model loaded")

# Function to check Tesseract availability
def check_tesseract():
    # Verify Tesseract is available
    global tesseract_available

    if tesseract_available is None:
        try:
            import pytesseract
            pytesseract.get_tesseract_version()
            tesseract_available = True
        except Exception as e:
            logger.warning("Tesseract not available: %s", e)
            tesseract_available = False
    return tesseract_available

# Function to generate caption for image using BLIP
def blip_caption(image) -> tuple[str, float]:
    
    load_blip()
    import torch

    inputs = blip_processor(image, return_tensors="pt")
    
    # Generate caption with BLIP and approximate confidence based on caption length and content.
    with torch.no_grad():
        output = blip_model.generate(**inputs,
                                     max_new_tokens=80,
                                     num_beams=4,
                                     early_stopping=True)
    
    # Decode the generated caption
    caption = blip_processor.decode(output[0], skip_special_tokens=True)

    # Proxy confidence: longer, more specific captions score higher
    word_count = len(caption.split())
    confidence = min(0.85, 0.40 + (word_count * 0.025))
    return caption, round(confidence, 2)

# Function to normalise a screenshot for Tesseract OCR, regardless if the
# dashboard's light/dark theme. Tesseract is trained predominantly on
# dark-text-on-light-background documents so dark-themed dashboard
# screenshots need to be inverted before OCR
def preprocess_for_ocr(image):
    
    # Convert to grayscale for brightness analysis and thresholding
    gray = image.convert("L")

    # Mean pixel brightness: 0 = black, 255 = white
    mean_brightness = ImageStat.Stat(gray).mean[0]

    # Dark-themed panel (dark background, light text) -> invert so text
    # becomes dark-on-light, matching Tesseract's expected input
    if mean_brightness < 128:
        gray = ImageOps.invert(gray)

    # Upscale small text for better character recognition
    width, height = gray.size
    if width < 1500:
        scale = 1500 / width
        gray = gray.resize((int(width * scale), int(height * scale)), Image.LANCZOS)

    # Fixed-threshold binarisation after normalisation, to sharpen edges
    # for Tesseract's character segmentation
    gray = gray.point(lambda x: 0 if x < 140 else 255, mode="L")

    return gray

# Function to extract text from image using Tesseract OCR
def tesseract_extract(image) -> str:
    
    # Check if Tesseract is available before attempting OCR
    if not check_tesseract():
        return ""
    
    # Extract all visible text from the image using Tesseract.
    import pytesseract
    processed = preprocess_for_ocr(image)
    text = pytesseract.image_to_string(processed, config="--psm 6")
    # Collapse excessive whitespace
    return re.sub(r"\s+", " ", text).strip()


# Function to analyse Kibana/SIEM screenshot image using BLIP and Tesseract
def analyse_image(image_input: Union[str, Path, object]) -> dict:

    # Load image (from path or PIL Image)
    try:
        from PIL import Image
        if isinstance(image_input, (str, Path)):
            image = Image.open(image_input).convert("RGB")
        else:
            image = image_input.convert("RGB")
    except Exception as e:
        logger.error("Failed to load image: %s", e)
        return error_result(f"Image load error: {e}")

    # BLIP captioning
    try:
        caption, blip_confidence = blip_caption(image)
    except Exception as e:
        logger.error("BLIP captioning failed: %s", e)
        caption, blip_confidence = "", 0.0

    # Tesseract OCR (extract text from image)
    try:
        ocr_text = tesseract_extract(image)
    except Exception as e:
        logger.warning("OCR failed: %s", e)
        ocr_text = ""

    # Combine and classify 
    combined_text = f"{caption} {ocr_text}".strip()
    attack_cls = classify_tactic(combined_text, SCREEN_KEYWORDS)
    entities = extract_entities(ocr_text)

    confidence = blip_confidence
    
    # Confidence: BLIP score boosted slightly 
    # if OCR also found entities
    if entities:
        confidence = min(0.90, confidence + 0.05)
    if ocr_text:
        confidence = min(0.90, confidence + 0.05)
        
    if attack_cls == "Unknown":
        confidence = 0.0
        
    # Severity heuristic from OCR text
    severity = infer_severity(combined_text)

    # Build summary from caption and OCR findings
    summary = build_summary(caption, ocr_text, attack_cls)

    # Return standardised wrapper output
    return {"model": "vision",
            "confidence": round(confidence, 2),
            "entities": entities,
            "attack_classification": attack_cls,
            "severity": severity,
            "summary": summary,
            "raw": combined_text}

# Function to build a concise summary from BLIP caption and OCR findings.
def build_summary(caption: str, ocr_text: str, attack_cls: str) -> str:
    # Build a concise summary from BLIP caption and OCR findings
    parts = []
    if caption:
        parts.append(f"Visual: {caption}.")
    if attack_cls != "Unknown":
        parts.append(f"Possible tactic: {attack_cls}.")
    elif ocr_text:
        parts.append("No clear tactic identified from screen content.")
        
    return " ".join(parts) if parts else "No visual analysis available."

# Function to return a standardised error result
def error_result(message: str) -> dict:
    # Return a standardised error result with the message included in the summary.
    return {
        "model": "vision",
        "confidence": 0.0,
        "entities": [],
        "summary": f"[ERROR] {message}",
        "attack_classification": "Unknown",
        "severity": 1,
        "raw": "",
    }
