"""
Runs all incidents in the dataset through the text, vision, and speech model wrappers independently
and records each modality's predicted attack_classification against label.json ground truth. 
"""

import argparse
import csv
import logging
import sys
from pathlib import Path
from typing import Optional

# Ensure the project root (parent of /eval) is importable so `models`
# resolves the same way it does for the Flask app.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from models import analyse_text, analyse_image, analyse_audio
from eval.eval_utils import (iterate_incidents, 
                             load_ground_truth_tactic,
                             load_text_model_input,
                             IncidentPaths)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# List of modalities to evaluate
MODALITIES = ("text", "vision", "speech")

# Directory to write per-modality predictions CSV and later scoring results.
RESULTS_DIR = Path(__file__).resolve().parent / "results"

## CSV file to write per-modality predictions to, for later scoring.
PREDICTIONS_CSV = RESULTS_DIR / "modality_predictions.csv"

# Function to run a single modality's wrapper for one incident, 
# returning the result or None if no input file exists for that modality.
def run_modality(modality: str, incident: IncidentPaths) -> Optional[dict]:
    """
    Run a single modality's wrapper for one incident. Returns None if the
    incident has no input file for this modality, so it can be excluded
    from that modality's scoring rather than counted as a wrong prediction.
    """
    # If "text" modality, check if log_path exists, load it, and run analyse_text.
    if modality == "text":
        if incident.log_path is None:
            return None
        log_input = load_text_model_input(incident.log_path)
        return analyse_text(log_input)

    # If "vision" modality, check if screenshot_path exists and run analyse_image.
    if modality == "vision":
        if incident.screenshot_path is None:
            return None
        return analyse_image(incident.screenshot_path)

    # If "speech" modality, check if voice_path exists and run analyse_audio.
    if modality == "speech":
        if incident.voice_path is None:
            return None
        return analyse_audio(incident.voice_path)

    raise ValueError(f"Unknown modality: {modality}")

# Function to load existing results from the predictions CSV.
def load_existing_results() -> set:
    
    existingResults = set()
    
    ## If the predictions CSV already exists, 
    # read it and store the (incident_id, modality)
    if PREDICTIONS_CSV.exists():
        
        # Opens the existing CSV file and reads the incident_id and modality pairs
        with open(PREDICTIONS_CSV, "r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                existingResults.add((row["incident_id"], row["modality"]))
    
    # Return the set of (incident_id, modality) pairs already scored
    return existingResults

# Main function that run evaluation for all incidents and modalities
def main():
    # Parse command-line arguments for dataset root and modalities to evaluate
    parser = argparse.ArgumentParser(description="Per-modality F1 evaluation for Flashpoint")
    parser.add_argument("--dataset-root",
                        required=True,
                        help="Path to the FYP-Dataset folder.")
    parser.add_argument("--modalities",
                        nargs="+",
                        default=list(MODALITIES),
                        choices=MODALITIES,
                        help="Which modalities to evaluate (default: all three)")
    args = parser.parse_args()

    # Create results directory if it doesn't exist, 
    # and load existing results to avoid re-scoring
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    already_done = load_existing_results()
    file_is_new = not PREDICTIONS_CSV.exists()

    # Open the predictions CSV for appending
    with open(PREDICTIONS_CSV, "a", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f,
                                fieldnames=["incident_id", "tactic_actual", "modality", "tactic_predicted",
                                            "confidence", "correct"])
        
        # Write header if it's a new file
        if file_is_new:
            writer.writeheader()

        # Iterate through all incidents in the dataset root
        for incident in iterate_incidents(args.dataset_root):
            
            
            tactic_true = load_ground_truth_tactic(incident.label_path)

            # Loop through each modality
            for modality in args.modalities:
                
                # Skip incidents that have already been scored for all modalities
                if (incident.incident_id, modality) in already_done:
                    
                    # Store the incident_id and modality 
                    # in the already_done set to avoid re-scoring
                    logger.info("Skipping %s / %s - already scored",
                                incident.incident_id, modality)
                    continue
                
                logger.info("Running %s / %s", incident.incident_id, modality)

                # Try to run the modality wrapper and handle any exceptions
                try:
                    result = run_modality(modality, incident)
                except Exception as e:
                    logger.error("%s / %s failed: %s", incident.incident_id, modality, e)
                    continue
                
                # If the result is None, 
                # it meanING there was no input file for this modality, so skip it
                if result is None:
                    logger.info("Skipping %s / %s",
                                incident.incident_id, 
                                modality)
                    continue

                # Extract the predicted tactic from the result, defaulting to "Unknown"    
                tactic_predicted = result.get("attack_classification", "Unknown")
                
                # Write the incident_id, actual tactic, modality, 
                # predicted tactic, confidence, and correctness to the CSV
                writer.writerow({"incident_id": incident.incident_id,
                                 "tactic_actual": tactic_true,
                                 "modality": modality,
                                 "tactic_predicted": tactic_predicted,
                                 "confidence": result.get("confidence", 0.0),
                                 "correct": int(tactic_predicted == tactic_true)})
                
                # Flush the CSV file to ensure data is written to disk
                f.flush()

    # Log that per-modality predictions written to CSV file
    logger.info("Per-modality predictions written to %s", PREDICTIONS_CSV)

if __name__ == "__main__":
    main()
