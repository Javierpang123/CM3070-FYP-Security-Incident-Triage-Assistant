"""
POST /analyse = Analyse route that accepts multipart form with 
                optional log (JSON text),
                screenshot (image file), and voice (audio file).
                Runs whichever model wrappers have input, fuses results,
                and returns a triage JSON response.
                  
GET / = Main route that serves the single page dashboard

POST /download-report = Accepts triage result JSON and returns a downloadable PDF report
"""

import io
import logging
import tempfile
import os
from pathlib import Path

from flask import Blueprint, jsonify, render_template, request, send_file

from models import analyse_text, analyse_image, analyse_audio
from models.text_model import parse_log_input
from orchestrator import late_fusion_orchestrator
from .pdf_report import build_pdf_report

logger = logging.getLogger(__name__)

main = Blueprint('main', __name__)

# Define allowed file extensions for uploads
ALLOWED_LOG_EXTENSIONS = {".json", ".txt", ".log"}
ALLOWED_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".tiff"}
ALLOWED_AUDIO_EXTENSIONS = {".wav", ".mp3", ".m4a", ".flac"}

# Route to serve the main dashboard page
@main.route('/')
def index():
    return render_template('index.html')

# Main analysis route to handle text, image, and audio inputs and return a triage result
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
    
    # If a log file is provided, check its extension and process it
    if log_file and log_file.filename:
        extension = Path(log_file.filename).suffix.lower()
        
        # IF extension is not inside allowed text file extension list then return error
        if extension not in ALLOWED_LOG_EXTENSIONS:
            errors.append(f"Log file extension '{extension}' not supported. "
                          f"Use one of: {', '.join(ALLOWED_LOG_EXTENSIONS)}")
        
        # Else the log file has a valid extension, read and process it
        else:
            try:
                content = log_file.read().decode("utf-8")
                log_input = parse_log_input(content)
                logger.info("Running text model from uploaded file")
                text_result = analyse_text(log_input)
            except Exception as e:
                logger.error("Log file read error: %s", e)
                errors.append(f"Log file error: {e}")

    # ------------------------------------------------------------------
    # 2. Screenshot input
    # ------------------------------------------------------------------
    screenshot_file = request.files.get("screenshot")
    
    # If a screenshot file is provided, check its extension and process it
    if screenshot_file and screenshot_file.filename:
        extension = Path(screenshot_file.filename).suffix.lower()
        
        # If extension is not inside allowed image file extension list then return error
        if extension not in ALLOWED_IMAGE_EXTENSIONS:
            errors.append(f"Screenshot extension '{extension}' not supported. "
                          f"Use one of: {', '.join(ALLOWED_IMAGE_EXTENSIONS)}")
        
        # Else the screenshot has a valid extension, read and process it
        else:
            tmp_img = None
            # Try to save the uploaded screenshot to a temporary file and run the vision model on it
            try:
                with tempfile.NamedTemporaryFile(
                    suffix = extension, delete = False
                ) as tmp_img:
                    screenshot_file.save(tmp_img.name)
                    tmp_path = tmp_img.name

                logger.info("Running vision model on %s", tmp_path)
                vision_result = analyse_image(tmp_path)
            
            # Handle any exceptions that occur during the vision model processing
            except Exception as e:
                logger.error("Vision model error: %s", e)
                errors.append(f"Vision model error: {e}")
            
            # Clean up the temporary file after processing, regardless of success or failure
            finally:
                if tmp_img and os.path.exists(tmp_img.name):
                    os.unlink(tmp_img.name)

    # ------------------------------------------------------------------
    # 3. Voice note input
    # ------------------------------------------------------------------
    voice_file = request.files.get("voice")
    
    # If a voice file is provided, check its extension and process it
    if voice_file and voice_file.filename:
        extension = Path(voice_file.filename).suffix.lower()
        
        # If extension is not inside allowed audio file extension list then return error
        if extension not in ALLOWED_AUDIO_EXTENSIONS:
            errors.append(f"Audio extension '{extension}' not supported. "
                          f"Use one of: {', '.join(ALLOWED_AUDIO_EXTENSIONS)}")
        
        # Else the voice file has a valid extension, read and process it
        else:
            tmp_audio = None
            
            # Try to save the uploaded voice file to a temporary file and run the speech model on it
            try:
                with tempfile.NamedTemporaryFile(suffix = extension, delete=False) as tmp_audio:
                    voice_file.save(tmp_audio.name)
                    tmp_path = tmp_audio.name

                logger.info("Running speech model on %s", tmp_path)
                speech_result = analyse_audio(tmp_path)
            
            # Handle any exceptions that occur during the speech model processing
            except Exception as e:
                logger.error("Speech model error: %s", e)
                errors.append(f"Speech model error: {e}")
           
            # Clean up temporary file after processing, regardless of success or failure
            finally:
                if tmp_audio and os.path.exists(tmp_audio.name):
                    os.unlink(tmp_audio.name)

    # ------------------------------------------------------------------
    # 4. Validate at least one input was processed
    # ------------------------------------------------------------------
    if text_result is None and vision_result is None and speech_result is None:
        return jsonify({"status": "error",
                        "message": "No valid inputs provided. Supply at least one of: "
                        "log_text, screenshot, or voice.",
                        "errors": errors,
                        }), 400

    # ------------------------------------------------------------------
    # 5. Late fusion
    # ------------------------------------------------------------------
    
    # Try to run the late fusion orchestrator with the results from the individual models
    try:
        triage = late_fusion_orchestrator(text_result=text_result,
                                          vision_result=vision_result,
                                          speech_result=speech_result)
    # Handle exceptions that occur during the late fusion orchestrating
    except Exception as e:
        logger.error("Fusion error: %s", e)
        return jsonify({"status": "error",
                        "message": f"Fusion error: {e}",
                        }), 500

    # ------------------------------------------------------------------
    # 6. Return triage result
    # ------------------------------------------------------------------
    
    # Prepare the response JSON with the triage result and any warnings collected during processing
    response = {"status": "ok","triage": triage}
    if errors:
        response["warnings"] = errors

    return jsonify(response), 200

# Route to generate a downloadable PDF triage report 
# from triage result posted by the frontend 
@main.route('/download-report', methods=['POST'])

# Function to handle the download of the PDF report based on the triage data
def download_report():
    triage = request.get_json(silent=True)

    # Validate that triage data is provided
    if not triage:
        return jsonify({"status": "error",
                        "message": "No triage data provided for report generation."
                        }), 400

    # Try to build the PDF report and handle any exceptions that may occur during the process
    try:
        pdf_bytes = build_pdf_report(triage)
    except Exception as e:
        logger.error("PDF report generation error: %s", e)
        return jsonify({"status": "error",
                        "message": f"PDF generation error: {e}"
                        }), 500

    # Return the generated PDF as a downloadable file
    return send_file(io.BytesIO(pdf_bytes), 
                     mimetype="application/pdf",
                     as_attachment=True,
                     download_name="flashpoint_triage_report.pdf",)

