# Wrapper for OpenAI Whisper (base model) running fully offline.
# Accepts a .wav audio file path and returns a standardised triage JSON object 
# containing the transcription and derived metadata.

"""
Whisper exposes per-segment log-probabilities which are
used to compute a meaningful confidence score (average probability
across all decoded segments).
"""

import logging
import re
from pathlib import Path
from typing import Union
from models.utilities import SPEECH_KEYWORDS, infer_severity, extract_entities, classify_tactic

# Set up logging
logger = logging.getLogger(__name__)

# Lazy load the Whisper model on first use to save resources
_whisper_model = None
WHISPER_MODEL_SIZE = "base"

# Function to load the Whisper model (called on first use)
def load_whisper():
    global _whisper_model
    if _whisper_model is None:
        import whisper
        logger.info("Loading Whisper model: %s", WHISPER_MODEL_SIZE)
        _whisper_model = whisper.load_model(WHISPER_MODEL_SIZE)
        logger.info("Whisper model loaded")

# Function to compute confidence from Whisper segments
def compute_confidence(segments: list) -> float:
    """
    Compute confidence as the mean of exponentiated average log-probabilities
    across all Whisper segments.

    Whisper returns avg_logprob per segment (typically -0.2 to -1.5).
    exp(avg_logprob) maps this to a [0, 1] probability proxy.
    Segments with no_speech_prob > 0.6 are excluded as silence.
    """
    if not segments:
        return 0.0

    probs = []
    for seg in segments:
        if seg.get("no_speech_prob", 0) > 0.6:
            continue
        avg_logprob = seg.get("avg_logprob", -1.0)
        probs.append(min(1.0, max(0.0, (avg_logprob + 1.0))))  # shift: -1→0, 0→1

    if not probs:
        return 0.0
    return round(sum(probs) / len(probs), 2)

# Function to transcribe and analyse an audio file, returning a standardised result dict.
def analyse_audio(audio_input: Union[str, Path]) -> dict:
    """
    Parameters
    ------------------------------------------------
    audio_input : str or Path to a .wav audio file.
    ------------------------------------------------
    """
    audio_path = Path(audio_input)
    
    # Check if file exists before attempting transcription
    if not audio_path.exists():
        logger.error("Audio file not found: %s", audio_path)
        return error_result(f"Audio file not found: {audio_path}")

    # Transcribe audio using Whisper
    try:
        load_whisper()
        result = _whisper_model.transcribe(str(audio_path),
                                           language="en",
                                           verbose=False,
                                           fp16=False,  # CPU-safe; GPU users can override
                                           )
    except Exception as e:
        logger.error("Whisper transcription failed: %s", e)
        return error_result(f"Transcription error: {e}")

    # Extract transcript and segments for confidence calculation
    transcript = result.get("text", "").strip()
    segments = result.get("segments", [])

    # Handle case where transcription is empty (maybe audio issues)
    if not transcript:
        logger.warning("Whisper returned empty transcript for %s", audio_path)
        return error_result("Empty transcription — check audio quality")

    # Compute confidence, classify attack tactic, infer severity, and extract entities from transcript.
    confidence = compute_confidence(segments)
    attack_cls = classify_tactic(transcript, SPEECH_KEYWORDS)
    
    if attack_cls == "Unknown":
        confidence = 0.0
    
    severity = infer_severity(transcript)
    entities = extract_entities(transcript)

    # Summary: first sentence of transcript, capped at 30 words
    first_sentence = re.split(r"[.!?]", transcript)[0].strip()
    words = first_sentence.split()
    summary = " ".join(words[:30]) + ("..." if len(words) > 30 else "")

    # Return standardised wrapper output
    return {"model": "speech",
            "confidence": confidence,
            "entities": entities,
            "attack_classification": attack_cls,
            "severity": severity,
            "summary": summary,
            "raw": transcript}

# Function to return a standardised error result for speech model
def error_result(message: str) -> dict:
    return {
        "model": "speech",
        "confidence": 0.0,
        "entities": [],
        "summary": f"[ERROR] {message}",
        "attack_classification": "Unknown",
        "severity": 1,
        "raw": "",
    }
