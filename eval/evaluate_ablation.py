# Ablation study for Flashpoint (eval item 3).

"""
Tests whether late fusion actually improves on the best single modality
by computing predictions for four input combinations, per incident:
    - log-only        (text modality alone)
    - screenshot-only  (vision modality alone)
    - voice-only       (speech modality alone)
    - all-three-fused  (late_fusion_orchestrator's weighted vote across
      all three)

The three single-modality combinations are algebraically identical to
running late_fusion_orchestrator() with only that one modality present -
redistribute_weights() gives a lone active modality 100% of the fusion
weight, so its fused attack_classification always equals its own raw
attack_classification (verified directly against fusion.py before
writing this script). This means the single-modality ablation columns
are read straight from eval/results/modality_predictions.csv (already
computed by evaluate_modalities.py) without re-invoking Ollama, BLIP, or
Whisper.

Only the all-three-fused combination is new computation: it's produced
here by feeding each incident's three already-recorded
(attack_classification, confidence) pairs into the real
redistribute_weights() and fuse_attack_classification() functions
imported directly from orchestrator/fusion.py, so the ablation result is
faithful to the production fusion logic rather than a re-implementation
of it.

Usage (no --dataset-root needed - reads entirely from the existing
modality_predictions.csv):

    python eval/evaluate_ablation.py
"""

import csv
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from orchestrator.fusion import redistribute_weights, fuse_attack_classification  # noqa: E402

RESULTS_DIR = Path(__file__).resolve().parent / "results"
PREDICTIONS_CSV = RESULTS_DIR / "modality_predictions.csv"
ABLATION_CSV = RESULTS_DIR / "ablation_predictions.csv"


def load_predictions_by_incident() -> dict:
    """
    Group modality_predictions.csv rows by incident_id
    with only the modalities actually present for that incident (an
    incident missing a modality's input file entirely - e.g. no
    screenshot captured - simply won't have that key, matching how
    fusion.py expects an absent modality to be represented as None).

    For vision and speech, applies the same confidence-zeroing rule as
    the corrected wrappers: an "Unknown" classification means the
    keyword classifier found no tactic signal, so its confidence is
    treated as 0.0 regardless of what was recorded in the CSV (which
    predates the wrapper fix). This lets the ablation study reflect the
    corrected fusion behaviour without re-invoking BLIP/Whisper, since
    the correction is a deterministic function of tactic_pred alone.
    Text is left untouched - its Unknown-confidence handling in
    build_confidence() is a considered discount, not a bug being fixed.
    """
    by_incident = defaultdict(dict)
    with open(PREDICTIONS_CSV, "r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            incident_id = row["incident_id"]
            by_incident[incident_id]["tactic_actual"] = row["tactic_actual"]

            confidence = float(row["confidence"])
            if row["modality"] in ("vision", "speech") and row["tactic_predicted"] == "Unknown":
                confidence = 0.0

            by_incident[incident_id][row["modality"]] = {"attack_classification": row["tactic_predicted"],
                                                         "confidence": confidence}
    return by_incident


def main():
    if not PREDICTIONS_CSV.exists():
        raise FileNotFoundError(f"{PREDICTIONS_CSV} not found - run evaluate_modalities.py first.")

    by_incident = load_predictions_by_incident()

    with open(ABLATION_CSV, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["incident_id", 
                                               "tactic_actual",
                                               "log_only_pred", 
                                               "screenshot_only_pred", 
                                               "voice_only_pred",
                                               "all_three_fused_pred"])
        writer.writeheader()

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
