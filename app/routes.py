"""
routes.py
Flask route definitions for Flashpoint.

POST /analyse  — accepts multipart form with optional log (JSON text),
                 screenshot (image file), and voice (audio file).
                 Runs whichever model wrappers have input, fuses results,
                 and returns a triage JSON response.
GET  /         — serves the single-page dashboard
GET  /health   — service health check
"""

import json
import logging
import tempfile
import os
from pathlib import Path

from flask import Blueprint, jsonify, render_template, request

from models import analyse_text, analyse_image, analyse_audio
from orchestrator import late_fusion_orchestrator

logger = logging.getLogger(__name__)

main = Blueprint('main', __name__)

# Define allowed file extensions for uploads
ALLOWED_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".tiff"}
ALLOWED_AUDIO_EXTENSIONS = {".wav", ".mp3", ".m4a", ".flac"}

# Route to serve the main dashboard page
@main.route('/')
def index():
    return render_template('index.html')

# Main analysis endpoint to handle text, image, and audio inputs and return a triage result
@main.route('/analyse', methods=['POST'])
def analyse():
   
    text_result = None
    vision_result = None
    speech_result = None

    errors = []

    # ------------------------------------------------------------------
    # 1. Text / log input
    # ------------------------------------------------------------------
   log_file = request.files.get("log_file")
    if log_file and log_file.filename:
        extension = Path(log_file.filename).suffix.lower()
        
        # Check if extension is inside allowed text file extension list
        if extension not in ALLOWED_LOG_EXTENSIONS:
            errors.append(f"Log file extension '{extension}' not supported. "
                          f"Use one of: {', '.join(ALLOWED_LOG_EXTENSIONS)}")
        else:
            try:
                content = log_file.read().decode("utf-8")
                try:
                    log_input = json.loads(content)
                except json.JSONDecodeError:
                    log_input = content
                logger.info("Running text model from uploaded file")
                text_result = analyse_text(log_input)
            except Exception as e:
                logger.error("Log file read error: %s", e)
                errors.append(f"Log file error: {e}")

    # ------------------------------------------------------------------
    # 2. Screenshot input
    # ------------------------------------------------------------------
    screenshot_file = request.files.get("screenshot")
    if screenshot_file and screenshot_file.filename:
        extension = Path(screenshot_file.filename).suffix.lower()
        
        # Check if extension is inside allowed image file extension list
        if extension not in ALLOWED_IMAGE_EXTENSIONS:
            errors.append(f"Screenshot extension '{extension}' not supported. "
                          f"Use one of: {', '.join(ALLOWED_IMAGE_EXTENSIONS)}")
        else:
            tmp_img = None
            try:
                with tempfile.NamedTemporaryFile(
                    suffix = extension, delete = False
                ) as tmp_img:
                    screenshot_file.save(tmp_img.name)
                    tmp_path = tmp_img.name

                logger.info("Running vision model on %s", tmp_path)
                vision_result = analyse_image(tmp_path)
            except Exception as e:
                logger.error("Vision model error: %s", e)
                errors.append(f"Vision model error: {e}")
            finally:
                if tmp_img and os.path.exists(tmp_img.name):
                    os.unlink(tmp_img.name)

    # ------------------------------------------------------------------
    # 3. Voice note input
    # ------------------------------------------------------------------
    voice_file = request.files.get("voice")
    if voice_file and voice_file.filename:
        extension = Path(voice_file.filename).suffix.lower()
        
        # Check if extension is inside allowed audio file extension list
        if extension not in ALLOWED_AUDIO_EXTENSIONS:
            errors.append(f"Audio extension '{extension}' not supported. "
                          f"Use one of: {', '.join(ALLOWED_AUDIO_EXTENSIONS)}")
        else:
            tmp_audio = None
            try:
                with tempfile.NamedTemporaryFile(
                    suffix = extension, delete=False
                ) as tmp_audio:
                    voice_file.save(tmp_audio.name)
                    tmp_path = tmp_audio.name

                logger.info("Running speech model on %s", tmp_path)
                speech_result = analyse_audio(tmp_path)
            except Exception as e:
                logger.error("Speech model error: %s", e)
                errors.append(f"Speech model error: {e}")
            finally:
                if tmp_audio and os.path.exists(tmp_audio.name):
                    os.unlink(tmp_audio.name)

    # ------------------------------------------------------------------
    # 4. Validate at least one input was processed
    # ------------------------------------------------------------------
    if text_result is None and vision_result is None and speech_result is None:
        return jsonify({
            "status": "error",
            "message": "No valid inputs provided. Supply at least one of: "
                       "log_text, screenshot, or voice.",
            "errors": errors,
        }), 400

    # ------------------------------------------------------------------
    # 5. Late fusion
    # ------------------------------------------------------------------
    try:
        triage = late_fusion_orchestrator(
            text_result=text_result,
            vision_result=vision_result,
            speech_result=speech_result,
        )
    except Exception as e:
        logger.error("Fusion error: %s", e)
        return jsonify({"status": "error",
                        "message": f"Fusion error: {e}",
                        }), 500

    # ------------------------------------------------------------------
    # 6. Return triage result
    # ------------------------------------------------------------------
    response = {"status": "ok","triage": triage}
    if errors:
        response["warnings"] = errors

    return jsonify(response), 200


