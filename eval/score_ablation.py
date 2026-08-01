# Scores ablation predictions produced by evaluate_ablation.py.

"""
Computes macro F1 for each of the four ablation combinations, to test
Flashpoint's core research question directly: does late fusion actually
improve on the best single modality, or does it just average toward the
weaker modalities?

Usage:
    python eval/score_ablation.py
"""

import csv
from pathlib import Path

from sklearn.metrics import f1_score, classification_report

RESULTS_DIR = Path(__file__).resolve().parent / "results"
ABLATION_CSV = RESULTS_DIR / "ablation_predictions.csv"
REPORT_PATH = RESULTS_DIR / "ablation_f1_report.txt"

COMBINATIONS = [
    ("log_only_pred", "Log-only (text modality alone)"),
    ("screenshot_only_pred", "Screenshot-only (vision modality alone)"),
    ("voice_only_pred", "Voice-only (speech modality alone)"),
    ("all_three_fused_pred", "All-three-fused (late_fusion_orchestrator)"),
]


def main():
    if not ABLATION_CSV.exists():
        raise FileNotFoundError(f"{ABLATION_CSV} not found - run evaluate_ablation.py first.")

    with open(ABLATION_CSV, "r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))

    y_true = [row["tactic_actual"] for row in rows]

    summary_lines = []
    detail_lines = []
    for col, label in COMBINATIONS:
        y_pred = [row[col] for row in rows]
        labels = sorted(set(y_true) | set(y_pred))
        macro_f1 = f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)

        summary_lines.append(f"{label}: macro F1 = {macro_f1:.4f}")

        detail_lines.append(f"=== {label} ===")
        detail_lines.append(f"Macro F1: {macro_f1:.4f}")
        detail_lines.append("")
        detail_lines.append(classification_report(y_true, y_pred, labels=labels, zero_division=0))
        detail_lines.append("")

    summary = "\n".join(["ABLATION SUMMARY (does fusion beat the best single modality?)", ""] 
                        + summary_lines)
    full_report = summary + "\n\n" + "\n".join(detail_lines)

    print(full_report)
    REPORT_PATH.write_text(full_report, encoding="utf-8")
    print(f"\nFull report written to {REPORT_PATH}")


if __name__ == "__main__":
    main()
