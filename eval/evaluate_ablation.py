"""
Tests whether late fusion actually improves on the best single modality
by computing predictions for four input combinations, per incident:
    - text modality alone
    - vision modality alone
    - speech modality alone
    - all three modality fused 
"""

import csv
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from orchestrator.fusion import redistribute_weights, fuse_attack_classification  # noqa: E402

# Variable to hold the path to the CSV file where ablation predictions will be written.
RESULTS_DIR = Path(__file__).resolve().parent / "results"
PREDICTIONS_CSV = RESULTS_DIR / "modality_predictions.csv"
ABLATION_CSV = RESULTS_DIR / "ablation_predictions.csv"

# Function to load modality_predictions.csv and group rows by incident_id, returning a dict.
def load_predictions_by_incident() -> dict:
    """
    Group modality_predictions.csv rows by incident_id
    with only the modalities actually present for that incident (an
    incident missing a modality's input file entirely - e.g. no
    screenshot captured - simply won't have that key, matching how
    fusion.py expects an absent modality to be represented as None).
    """
    by_incident = defaultdict(dict)
    
    # Open the modality_predictions.csv file and read it into a dictionary grouped by incident_id.
    with open(PREDICTIONS_CSV, "r", encoding="utf-8", newline="") as f:
        # Read each row and populate the by_incident dictionary 
        # with the actual tactic and modality predictions.
        for row in csv.DictReader(f):
            incident_id = row["incident_id"]
            by_incident[incident_id]["tactic_actual"] = row["tactic_actual"]

            confidence = float(row["confidence"])
            
            # If the modality is vision or speech 
            # and the predicted tactic is "Unknown", set confidence to 0.0.
            if row["modality"] in ("vision", "speech") and row["tactic_predicted"] == "Unknown":
                confidence = 0.0

            # Store the predicted tactic and confidence for this modality under the incident_id in the by_incident dictionary.
            by_incident[incident_id][row["modality"]] = {"attack_classification": row["tactic_predicted"],
                                                         "confidence": confidence}
    return by_incident

# Main FUNCTIOn to run the ablation study, 
# writing predictions for each of the four combinations to ablation_predictions.csv.
def main():
    
    # Check if the modality_predictions.csv file exists, 
    # if not raise a FileNotFoundError.
    if not PREDICTIONS_CSV.exists():
        raise FileNotFoundError(f"{PREDICTIONS_CSV} not found - run evaluate_modalities.py first.")

    by_incident = load_predictions_by_incident()

    # Open the ablation_predictions.csv file for writing   
    with open(ABLATION_CSV, "w", encoding="utf-8", newline="") as f:
        
        # Write the header and predictions for each incident. 
        writer = csv.DictWriter(f, fieldnames=["incident_id", 
                                               "tactic_actual",
                                               "log_only_pred", 
                                               "screenshot_only_pred", 
                                               "voice_only_pred",
                                               "all_three_fused_pred"])
        writer.writeheader()

        # For each incident, compute the predictions 
        # for each of the four combinations and write them to the CSV.
        for incident_id, data in sorted(by_incident.items()):
            tactic_actual = data["tactic_actual"]

            log_only = data.get("text", {}).get("attack_classification", "Unknown")
            screenshot_only = data.get("vision", {}).get("attack_classification", "Unknown")
            voice_only = data.get("speech", {}).get("attack_classification", "Unknown")

            # Reconstruct the three modalities' results exactly as
            # fusion.py expects them (dict or None per modality), and
            # run them through the real production fusion functions so
            # this result is faithful to what the live Flask app would
            # actually return for this incident with all three inputs.
            results = {"text": data.get("text"),
                       "vision": data.get("vision"),
                       "speech": data.get("speech")}
            
            weights = redistribute_weights(results)
            all_three_fused = (fuse_attack_classification(results, weights) 
                               if weights else "Unknown")

            writer.writerow({"incident_id": incident_id,
                             "tactic_actual": tactic_actual,
                             "log_only_pred": log_only,
                             "screenshot_only_pred": screenshot_only,
                             "voice_only_pred": voice_only,
                             "all_three_fused_pred": all_three_fused})

    print(f"Ablation predictions written to {ABLATION_CSV}")
    print("Run eval/score_ablation.py next to compute F1 per combination.")


if __name__ == "__main__":
    main()
